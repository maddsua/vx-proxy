package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
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

type Proxy struct {
	Auth auth.Controller
	Dns  *net.Resolver
}

func (this *Proxy) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {

	//	get client credentials
	creds, err := parseHttpProxyCreds(req.Header)
	if err != nil {
		slog.Debug("HTTP PROXY: User credentials invalid",
			slog.String("err", err.Error()),
			slog.String("client_ip", req.RemoteAddr))
		wrt.WriteHeader(http.StatusBadRequest)
	} else if creds == nil {
		wrt.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	nasIpAddr, nasPort := GetContextLocalAddr(req.Context())
	remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		slog.Error("HTTP PROXY: Failed to determine client ip address",
			slog.String("err", err.Error()),
			slog.String("client_ip", req.RemoteAddr),
			slog.String("host", req.Host))
	}

	authProps := auth.PasswordProxyAuth{
		ProxyUser: *creds,
		ClientIP:  net.ParseIP(remoteAddr),
		NasAddr:   nasIpAddr,
		NasPort:   nasPort,
	}

	sess, err := this.Auth.WithPassword(req.Context(), authProps)
	if err == auth.ErrUnauthorized {
		slog.Debug("HTTP: Unauthorized",
			slog.String("user", authProps.Username),
			slog.String("remote", authProps.ClientIP.String()),
			slog.String("nas_addr", authProps.NasAddr.String()),
			slog.Int("nas_port", authProps.NasPort))
		wrt.WriteHeader(http.StatusProxyAuthRequired)
		return
	} else if err != nil {
		slog.Error("HTTP: Auth error",
			slog.String("err", err.Error()),
			slog.String("client_ip", req.RemoteAddr),
			slog.String("username", creds.Username),
			slog.String("authd_id", this.Auth.ID()))
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.Method {
	case http.MethodConnect:
		this.ServeTunnel(wrt, req, sess)
	default:
		wrt.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (this *Proxy) ServeTunnel(wrt http.ResponseWriter, req *http.Request, sess *auth.Session) {

	//	switch to the raw connection here
	//	not checking for the hijacker interface as we should always use http/1.1
	//	which must support hijacking
	clientConn, clientRW, err := wrt.(http.Hijacker).Hijack()
	if err != nil {
		slog.Error("HTTP PROXY: TUNNEL: Failed to hijack http connection",
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("sid", sess.ID.String()),
			slog.String("user", sess.UserID.String()))
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		slog.Error("HTTP PROXY: TUNNEL: Failed to set handshake timeout",
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("sid", sess.ID.String()),
			slog.String("user", sess.UserID.String()))
		return
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetLocalDialAddrTCP(clientConn.LocalAddr()),
		Resolver:  this.Dns,
	}

	remoteConn, err := dialer.DialContext(sess.Context, "tcp", req.Host)
	if err != nil {
		slog.Debug("HTTP PROXY: TUNNEL: Failed to connect to the remote server",
			slog.String("err", err.Error()),
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("sid", sess.ID.String()),
			slog.String("user", sess.UserID.String()))
		wrt.WriteHeader(http.StatusBadGateway)
		return
	}

	defer remoteConn.Close()

	slog.Debug("HTTP PROXY: TUNNEL: Connected",
		slog.String("client_ip", req.RemoteAddr),
		slog.String("remote", req.Host),
		slog.String("sid", sess.ID.String()),
		slog.String("user", sess.UserID.String()))

	proxyHeaders := http.Header{}
	proxyHeaders.Set("Proxy-Connection", "Keep-Alive")

	//	write proxy header
	if err := beginTunnel(clientRW.Writer, proxyHeaders); err != nil {
		slog.Error("HTTP PROXY: TUNNEL: Failed to start proxy connection",
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("user", sess.UserID.String()))
		return
	}

	//	add to a wait group to make sure session-stops account the full amount of traffix
	sess.ContextWg.Add(1)
	defer sess.ContextWg.Done()

	//	grap remaining reader data and send that to the remote
	if buffered, err := pipeUnreadBuffer(remoteConn, clientRW.Reader); err != nil {
		slog.Error("HTTP PROXY: TUNNEL: Failed to flush remaining http buffer",
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("user", sess.UserID.String()))
		return
	} else if buffered > 0 {
		sess.AcctTxBytes.Add(int64(buffered))
	}

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		slog.Error("HTTP PROXY: TUNNEL: Failed to set pipeline timeout",
			slog.String("client_ip", req.RemoteAddr),
			slog.String("remote", req.Host),
			slog.String("user", sess.UserID.String()))
		return
	}

	txCtx, cancelTx := context.WithCancel(sess.Context)
	rxCtx, cancelRx := context.WithCancel(sess.Context)

	//	start piping connections directly
	go utils.PipeConnection(txCtx, cancelRx, remoteConn, clientConn, sess.MaxDataRateTx, &sess.AcctTxBytes)
	go utils.PipeConnection(rxCtx, cancelTx, clientConn, remoteConn, sess.MaxDataRateRx, &sess.AcctRxBytes)

	//	keep this scope active until pipe routines exit
	<-txCtx.Done()
	<-rxCtx.Done()
}

func parseHttpProxyCreds(headers http.Header) (*auth.ProxyUser, error) {

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

	return &auth.ProxyUser{
		Username: username,
		Password: password,
	}, nil
}

func pipeUnreadBuffer(dst net.Conn, reader *bufio.Reader) (int, error) {

	buffered := reader.Buffered()
	if buffered == 0 {
		return buffered, nil
	}

	buffer := make([]byte, buffered)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return buffered, err
	}

	_, err := dst.Write(buffer)
	return buffered, err
}

func beginTunnel(writer *bufio.Writer, headers http.Header) error {

	if _, err := writer.WriteString("HTTP/1.1 200 Connection established\r\n"); err != nil {
		return err
	}

	if headers != nil {
		if err := headers.Write(writer); err != nil {
			return err
		}
	}

	if _, err := writer.WriteString("\r\n"); err != nil {
		return err
	}

	return writer.Flush()
}
