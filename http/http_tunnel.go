package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/maddsua/vx-proxy/utils"

	"github.com/maddsua/vx-proxy/auth"
)

type TunnelProxy struct {
	Auth auth.Controller
	Dns  *net.Resolver
}

func (this *TunnelProxy) HandleConnection(ctx context.Context, conn net.Conn) {

	clientIP, _, _ := utils.GetAddrPort(conn.RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(conn.LocalAddr())

	var errorRespond = func(statusCode int, headers http.Header) error {

		if headers = headers.Clone(); headers == nil {
			headers = http.Header{}
		}

		headers.Set("Connection", "Close")
		return respondHttp1Tunnel(bufio.NewWriter(conn), statusCode, "", headers)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Debug("HTTP tunnel: Failed to set connection deadline",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("err", err.Error()))
		return
	}

	header, err := readHttp1TunnelHeader(ctx, bufio.NewReaderSize(conn, 16*1024))
	if err != nil {

		if err, ok := err.(HttpError); ok {
			_ = errorRespond(err.Code, nil)
		}

		if err != io.EOF {
			slog.Debug("HTTP tunnel: Client error",
				slog.String("nas_addr", nasIP.String()),
				slog.Int("nas_port", nasPort),
				slog.String("client_ip", clientIP.String()),
				slog.String("err", err.Error()))
		}

		return
	}

	switch {
	case header.Method != http.MethodConnect:
		headers := http.Header{}
		headers.Set("Allow", "CONNECT")
		_ = errorRespond(http.StatusMethodNotAllowed, headers)
		return

	case header.Host == "":
		_ = errorRespond(http.StatusMisdirectedRequest, nil)
		return

	case header.Auth == nil:
		headers := http.Header{}
		headers.Set("Proxy-Authenticate", "Basic")
		_ = errorRespond(http.StatusProxyAuthRequired, headers)
		return
	}

	sess, err := this.Auth.WithPassword(ctx, auth.PasswordProxyAuth{
		BasicCredentials: *header.Auth,
		ClientIP:         clientIP,
		NasAddr:          nasIP,
		NasPort:          nasPort,
	})

	if err == auth.ErrUnauthorized {
		slog.Debug("HTTP tunnel: Unauthorized",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()))
		_ = errorRespond(http.StatusForbidden, nil)
		return
	} else if err != nil {
		slog.Error("HTTP tunnel: Auth error",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("authd_type", this.Auth.Type()),
			slog.String("err", err.Error()))
		_ = errorRespond(http.StatusInternalServerError, nil)
		return
	}

	if err := utils.DestHostAllowed(header.Host); err != nil {
		slog.Warn("HTTP tunnel: Dialed host not allowed",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("host", header.Host))
		_ = errorRespond(http.StatusBadGateway, nil)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("HTTP tunnel: Failed to reset tunnel timeouts",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("err", err.Error()))
		return
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetReverseDialAddrTcp(conn),
		Resolver:  this.Dns,
	}

	dstConn, err := dialer.DialContext(sess.Context, "tcp", header.Host)
	if err != nil {
		slog.Debug("HTTP tunnel: Unable to dial destination",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("host", header.Host),
			slog.String("err", err.Error()))
		_ = errorRespond(http.StatusBadGateway, nil)
		return
	}

	defer dstConn.Close()

	slog.Debug("HTTP tunnel: Connected",
		slog.String("nas_addr", nasIP.String()),
		slog.Int("nas_port", nasPort),
		slog.String("client_ip", clientIP.String()),
		slog.String("client_id", sess.ClientID),
		slog.String("sid", sess.ID.String()),
		slog.String("username", *sess.UserName),
		slog.String("host", header.Host))

	var beginTunnel = func() error {
		headers := http.Header{}
		headers.Set("Proxy-Connection", "Keep-Alive")
		return respondHttp1Tunnel(bufio.NewWriter(conn), 200, "Connection established", headers)
	}

	//	write proxy header
	if err := beginTunnel(); err != nil {
		slog.Debug("HTTP tunnel: Client disconnected after initial handshake",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("host", header.Host),
			slog.String("err", err.Error()))
		return
	}

	//	add to a wait group to make sure session-stops account the full amount of traffix
	sess.ContextWg.Add(1)
	defer sess.ContextWg.Done()

	if len(header.Trailer) > 0 {

		if _, err := conn.Write(header.Trailer); err != nil {
			slog.Debug("HTTP tunnel: Failed to write trailer",
				slog.String("nas_addr", nasIP.String()),
				slog.Int("nas_port", nasPort),
				slog.String("client_ip", clientIP.String()),
				slog.String("client_id", sess.ClientID),
				slog.String("sid", sess.ID.String()),
				slog.String("username", *sess.UserName),
				slog.String("host", header.Host),
				slog.String("err", err.Error()))
			return
		}

		sess.AcctTxBytes.Add(int64(len(header.Trailer)))
		header.Trailer = nil
	}

	//	let the data flow!
	piper := utils.ConnectionPiper{
		RemoteConn: dstConn,
		ClientConn: conn,

		TotalCounterRx: &sess.AcctRxBytes,
		TotalCounterTx: &sess.AcctTxBytes,

		SpeedCapRx: sess.MaxDataRateRx,
		SpeedCapTx: sess.MaxDataRateTx,
	}

	if err := piper.Pipe(sess.Context); err != nil {
		slog.Debug("HTTP tunnel: Broken pipe",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("err", err.Error()))
	}
}

type TunnelHeader struct {
	Method  string
	Auth    *auth.BasicCredentials
	Host    string
	Trailer []byte
}

type HttpError struct {
	Msg  string
	Code int
}

func (this HttpError) Error() string {
	return this.Msg
}

func readHttp1TunnelHeader(ctx context.Context, reader *bufio.Reader) (*TunnelHeader, error) {

	const maxMethodLength = 8

	var header TunnelHeader

	var parseHeader = func(key string, val string) {

		switch key {

		case "host":

			if _, _, err := net.SplitHostPort(val); err == nil {
				header.Host = val
			} else {
				header.Host = fmt.Sprintf("%s:80", val)
			}

		case "proxy-authorization":

			schema, token, _ := strings.Cut(val, " ")
			if strings.ToLower(strings.TrimSpace(schema)) == "basic" {
				if userauth, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token)); err == nil {
					if username, password, has := strings.Cut(string(userauth), ":"); has {
						header.Auth = &auth.BasicCredentials{Username: username, Password: password}
					}
				}
			}
		}
	}

	var parseMethod = func(line string) error {

		method, suffix, has := strings.Cut(line, " ")
		if !has {
			return HttpError{
				Msg:  "invalid http header: no method token",
				Code: http.StatusBadRequest,
			}
		} else if len(method) > maxMethodLength {
			return HttpError{
				Msg:  "invalid http header: method token too long",
				Code: http.StatusBadRequest,
			}
		}

		_, version, has := strings.Cut(strings.TrimSpace(suffix), " ")
		if !has {
			return HttpError{
				Msg:  "invalid http header: no vesrion token",
				Code: http.StatusBadRequest,
			}
		}

		switch strings.TrimSpace(strings.ToUpper(version)) {
		case "HTTP/1.1", "HTTP/1.0", "HTTP/0.9":
			break
		default:
			return HttpError{
				Msg:  "unsupported http version",
				Code: http.StatusBadRequest,
			}
		}

		header.Method = strings.ToUpper(method)
		return nil
	}

	for ctx.Err() == nil {

		next, isPrefix, err := reader.ReadLine()
		if err != nil {
			return nil, err
		} else if isPrefix {
			return nil, HttpError{
				Msg:  fmt.Sprintf("headers too large: %v", err),
				Code: http.StatusRequestHeaderFieldsTooLarge,
			}
		} else if len(next) == 0 {
			break
		}

		if header.Method == "" {
			if err := parseMethod(string(next)); err != nil {
				return nil, err
			}
			continue
		}

		if key, val, has := strings.Cut(string(next), ":"); has {
			parseHeader(strings.ToLower(key), strings.TrimSpace(val))
		}
	}

	if buffered := reader.Buffered(); buffered > 0 {
		trailer, err := utils.ReadBuffN(reader, buffered)
		if err != nil {
			return nil, fmt.Errorf("failed to extract reader buffered data")
		}

		header.Trailer = trailer
	}

	return &header, nil
}

func respondHttp1Tunnel(writer *bufio.Writer, statusCode int, statusText string, headers http.Header) error {

	if statusText == "" {
		statusText = http.StatusText(statusCode)
	}

	if _, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\n", statusCode, statusText); err != nil {
		return err
	}

	if headers = headers.Clone(); headers == nil {
		headers = http.Header{}
	}

	headers.Set("Date", time.Now().Format(time.RFC1123))
	headers.Set("Server", "vx/tunnel")

	if err := headers.Write(writer); err != nil {
		return err
	}

	if _, err := writer.WriteString("\r\n"); err != nil {
		return err
	}

	return writer.Flush()
}
