package http

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maddsua/vx-proxy/utils"

	"github.com/maddsua/vx-proxy/auth"
)

type HttpProxy struct {
	Auth auth.Controller
	Dns  *net.Resolver
}

func (this *HttpProxy) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	clientIP, _, _ := utils.GetAddrPort(getContextConn(ctx).RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(getContextConn(ctx).LocalAddr())

	wrt.Header().Set("Server", "vx")

	creds, err := getRequestCredentials(req.Header)
	if err != nil {

		slog.Debug("HTTP proxy: Invalid authorization data",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("err", err.Error()))

		wrt.WriteHeader(http.StatusBadRequest)
		return

	} else if creds == nil {

		slog.Debug("HTTP proxy: Unauthorized",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()))

		wrt.Header().Set("Proxy-Authenticate", "Basic")
		wrt.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	sess, err := this.Auth.WithPassword(ctx, auth.PasswordProxyAuth{
		BasicCredentials: *creds,
		ClientIP:         clientIP,
		NasAddr:          nasIP,
		NasPort:          nasPort,
	})

	if err == auth.ErrUnauthorized {
		slog.Debug("HTTP proxy: Unauthorized",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()))
		wrt.WriteHeader(http.StatusForbidden)
		return
	} else if err != nil {
		slog.Error("HTTP proxy: Auth error",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("authd_type", this.Auth.Type()),
			slog.String("err", err.Error()))
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	dstHost := getRequestTargetHost(req)
	if dstHost == "" {
		slog.Debug("HTTP proxy: Unable to determine target host",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()))
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := utils.DestHostAllowed(dstHost); err != nil {
		slog.Warn("HTTP proxy: Dialed host not allowed",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ID.String()),
			slog.String("sid", sess.ID.String()),
			slog.String("host", dstHost))
		wrt.WriteHeader(http.StatusBadGateway)
		return
	}

	switch req.Method {

	case http.MethodConnect:

		conn, rw, err := wrt.(http.Hijacker).Hijack()
		if err != nil {
			slog.Error("HTTP tunnel: Connection not switchable",
				slog.String("nas_addr", nasIP.String()),
				slog.Int("nas_port", nasPort),
				slog.String("client_ip", clientIP.String()),
				slog.String("client_id", sess.ID.String()),
				slog.String("sid", sess.ID.String()))
			wrt.WriteHeader(http.StatusNotImplemented)
			return
		}

		defer conn.Close()

		this.ServeTunnel(conn, rw, sess, dstHost)

	default:
		//	todo: handle relay
		wrt.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (this *HttpProxy) ServeTunnel(conn net.Conn, rw *bufio.ReadWriter, sess *auth.Session, hostAddr string) {

	clientIP, _, _ := utils.GetAddrPort(conn.RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(conn.LocalAddr())

	slog.Debug("HTTP tunnel: HTTP connection switched",
		slog.String("nas_addr", nasIP.String()),
		slog.Int("nas_port", nasPort),
		slog.String("client_ip", clientIP.String()),
		slog.String("client_id", sess.ID.String()),
		slog.String("sid", sess.ID.String()))

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		slog.Error("HTTP tunnel: Failed to set timeouts",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ID.String()),
			slog.String("sid", sess.ID.String()))
		return
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetReverseDialAddrTcp(conn),
		Resolver:  this.Dns,
	}

	var flushResponse = func(statusCode int, statusText string, headers http.Header) error {

		if statusText == "" {
			statusText = http.StatusText(statusCode)
		}

		if _, err := fmt.Fprintf(rw.Writer, "HTTP/1.1 %d %s\r\n", statusCode, statusText); err != nil {
			return err
		}

		if headers == nil {
			headers = http.Header{}
		}

		if headers.Get("Proxy-Connection") == "" {
			headers.Set("Proxy-Connection", "Keep-Alive")
		}

		headers.Set("Date", time.Now().In(time.UTC).Format(time.RFC1123))
		headers.Set("Server", "vx/tunnel")
		headers.Set("X-Destination", hostAddr)

		if err := headers.Write(rw.Writer); err != nil {
			return err
		}

		if _, err := rw.Writer.WriteString("\r\n"); err != nil {
			return err
		}

		return rw.Writer.Flush()
	}

	dstConn, err := dialer.DialContext(sess.Context, "tcp", hostAddr)
	if err != nil {

		slog.Debug("HTTP tunnel: Unable to dial destination",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("remote", hostAddr),
			slog.String("err", err.Error()))

		headers := http.Header{}
		headers.Set("Proxy-Connection", "Close")

		_ = flushResponse(http.StatusBadGateway, "", headers)
		return
	}

	defer dstConn.Close()

	slog.Debug("HTTP tunnel: Connected",
		slog.String("nas_addr", nasIP.String()),
		slog.Int("nas_port", nasPort),
		slog.String("client_ip", clientIP.String()),
		slog.String("client_id", sess.ID.String()),
		slog.String("sid", sess.ID.String()),
		slog.String("host", hostAddr))

	if err := flushResponse(200, "Connection established", nil); err != nil {
		slog.Debug("HTTP tunnel: Failed to establish proxy connection",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ID.String()),
			slog.String("sid", sess.ID.String()),
			slog.String("err", err.Error()))
	}

	//	add to a wait group to make sure session-stops account the full amount of traffix
	sess.ContextWg.Add(1)
	defer sess.ContextWg.Done()

	if buffered := rw.Reader.Buffered(); buffered > 0 {

		buff, err := rw.Reader.Peek(buffered)
		if err != nil {
			slog.Debug("HTTP tunnel: Failed to peek tx bufferred data",
				slog.String("nas_addr", nasIP.String()),
				slog.Int("nas_port", nasPort),
				slog.String("client_ip", clientIP.String()),
				slog.String("client_id", sess.ID.String()),
				slog.String("sid", sess.ID.String()),
				slog.String("host", hostAddr),
				slog.String("err", err.Error()))
		}

		if _, err := dstConn.Write(buff); err != nil {
			slog.Debug("HTTP tunnel: Failed flush tx buffer",
				slog.String("nas_addr", nasIP.String()),
				slog.Int("nas_port", nasPort),
				slog.String("client_ip", clientIP.String()),
				slog.String("client_id", sess.ID.String()),
				slog.String("sid", sess.ID.String()),
				slog.String("host", hostAddr),
				slog.String("err", err.Error()))
			return
		}

		sess.AcctTxBytes.Add(int64(buffered))
	}

	//	explicitly reset rw as we won't be using it anymore
	rw.Reader.Reset(nil)
	rw.Writer.Reset(nil)
	rw = nil

	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Error("HTTP tunnel: Failed to reset timeouts",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ID.String()),
			slog.String("sid", sess.ID.String()),
			slog.String("err", err.Error()))
		return
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
			slog.String("host", hostAddr),
			slog.String("err", err.Error()))
	}
}

func getRequestCredentials(headers http.Header) (*auth.BasicCredentials, error) {

	proxyAuth := headers.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return nil, nil
	}

	schema, token, _ := strings.Cut(proxyAuth, " ")
	if strings.ToLower(strings.TrimSpace(schema)) != "basic" {
		return nil, fmt.Errorf("invalid auth schema '%s'", schema)
	}

	userauth, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	username, password, _ := strings.Cut(string(userauth), ":")
	if username == "" {
		return nil, errors.New("username is empty")
	}

	return &auth.BasicCredentials{
		Username: username,
		Password: password,
	}, nil
}

func getRequestTargetHost(req *http.Request) string {

	if req.Method == http.MethodConnect {

		if host := req.Header.Get("Host"); host != "" {
			return host
		}

		if !strings.Contains(req.RequestURI, "/") {
			return req.RequestURI
		}

		return ""
	}

	if url, err := url.Parse(req.RequestURI); err == nil && url.Host != "" {

		host := url.Host

		if _, _, err := net.SplitHostPort(host); err != nil {
			switch url.Scheme {
			case "https":
				host = fmt.Sprintf("%s:443", host)
			case "http":
				host = fmt.Sprintf("%s:80", host)
			}
		}

		return host
	}

	if host := req.Header.Get("Host"); host != "" {

		if _, _, err := net.SplitHostPort(host); err != nil {
			return fmt.Sprintf("%s:80", host)
		}

		return host
	}

	return ""
}
