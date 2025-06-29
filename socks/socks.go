package socks

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type Proxy struct {
	Auth auth.Controller
	Dns  *net.Resolver
}

func (this *Proxy) HandleConnection(ctx context.Context, conn net.Conn) {

	defer func() {
		if rerr := recover(); rerr != nil {
			slog.Error("SOCKS: Panic recovered",
				slog.Any("err", rerr),
				slog.String("client_ip", conn.RemoteAddr().String()))
		}
	}()

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		slog.Debug("SOCKS: Failed to set connection deadline",
			slog.Any("err", err),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	vn, err := utils.ReadByte(conn)
	if err != nil {
		slog.Debug("SOCKS: Error reading version byte",
			slog.Any("err", err),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	switch vn {

	case v5Ver:
		this.handleV5(ctx, conn)

	default:
		slog.Debug("SOCKS: Unsupported version number",
			slog.Int("vn", int(vn)),
			slog.String("client_ip", conn.RemoteAddr().String()))
	}
}

// As per: https://datatracker.ietf.org/doc/html/rfc1928
func (this *Proxy) handleV5(ctx context.Context, conn net.Conn) {

	var writeError = func(rep byte) error {
		_, err := conn.Write([]byte{v5Ver, rep, v5ByteReserved})
		return err
	}

	var writeAuthMethod = func(method byte) error {
		_, err := conn.Write([]byte{v5Ver, method})
		return err
	}

	var writeAuthStatus = func(ok bool) error {

		code := v5PasswordAuthRepOk
		if !ok {
			code = v5PasswordAuthRepFail
		}

		_, err := conn.Write([]byte{v5PasswordAuthVer, code})
		return err
	}

	nmethods, err := utils.ReadByte(conn)
	if err != nil {
		slog.Debug("SOCKS V5: Handshake error: Failed to read 'nmethods'",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	methods, err := utils.ReadBuffN(conn, int(nmethods))
	if err != nil {
		slog.Debug("SOCKS V5: Handshake error: Failed to read 'methods'",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	//	look: realistically we won't ever use anything but password auth here
	//	it doesn't make sense to keep a plug-in logic here.
	//	just check that the user offers a password and let's move on
	var hasPasswordMethod bool
	for _, method := range methods {
		if method == v5AuthPassword {

			if err := writeAuthMethod(method); err != nil {
				slog.Error("SOCKS V5: Handshake error: Unable to select auth method",
					slog.String("err", err.Error()),
					slog.String("client_ip", conn.RemoteAddr().String()))
				return
			}

			hasPasswordMethod = true
			break
		}
	}

	if !hasPasswordMethod {

		slog.Debug("SOCKS V5: Handshake error: Client doesn't support password auth",
			slog.String("client_ip", conn.RemoteAddr().String()))

		writeAuthMethod(v5AuthUnacceptable)
		return
	}

	//	proceed with plain password auth now
	creds, err := v5ReadCredentials(conn)
	if err != nil {
		slog.Error("SOCKS V5: Handshake error: Unable to read user credentials",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	authProps := auth.PasswordProxyAuth{
		ProxyUser: *creds,
		ClientIP:  conn.RemoteAddr().(*net.TCPAddr).IP,
		NasAddr:   conn.LocalAddr().(*net.TCPAddr).IP,
		NasPort:   conn.LocalAddr().(*net.TCPAddr).Port,
	}

	sess, err := this.Auth.WithPassword(ctx, authProps)
	if err == auth.ErrUnauthorized {

		slog.Debug("SOCKS V5: Unauthorized",
			slog.String("username", authProps.Username),
			slog.String("nas_addr", authProps.NasAddr.String()),
			slog.String("client_ip", authProps.ClientIP.String()))

		writeAuthStatus(false)
		return

	} else if err != nil {
		slog.Error("SOCKS V5: Auth error",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		writeError(v5RepErrGeneric)
		return
	}

	if err := writeAuthStatus(true); err != nil {
		slog.Debug("SOCKS V5: Handshake terminated",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		return
	}

	var cmd uint8
	if cmdBuff, err := utils.ReadBuffN(conn, 3); err != nil {
		slog.Debug("SOCKS V5: Handshake error: Failed to read command",
			slog.String("err", err.Error()),
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		return
	} else if cmdBuff[0] != v5Ver {
		slog.Debug("SOCKS V5: Handshake error: Invalid command version",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		writeError(v5RepErrGeneric)
		return
	} else if cmdBuff[2] != v5ByteReserved {
		slog.Debug("SOCKS V5: Handshake error: Command protocol violation",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		writeError(v5RepErrGeneric)
		return
	} else {
		cmd = cmdBuff[1]
	}

	switch cmd {

	case v5CmdConnect:

		addr, err := v5ReadAddr(conn)
		if err != nil {
			slog.Debug("SOCKS V5: Handshake error: Failed to read 'connect' cmd remote addr",
				slog.String("err", err.Error()),
				slog.String("client_ip", conn.RemoteAddr().String()),
				slog.String("authd_id", this.Auth.ID()))
			return
		}

		this.handleV5Connect(conn, sess, addr)

	default:

		slog.Debug("SOCKS V5: Unsupported command",
			slog.Int("cmd", int(cmd)),
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("user", sess.UserID))

		writeError(v5RepErrCmdNotSupported)
	}
}

func (this *Proxy) handleV5Connect(clientConn net.Conn, sess *auth.Session, remoteAddr string) {

	var respond = func(rep byte, addr string) error {
		_, err := clientConn.Write(append([]byte{v5Ver, rep, v5ByteReserved}, v5PackAddr(addr)...))
		return err
	}

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("SOCKS V5: Failed to reset tunnel timeouts",
			slog.String("err", err.Error()),
			slog.String("client_ip", clientConn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		return
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetLocalDialAddrTCP(clientConn.LocalAddr()),
		Resolver:  this.Dns,
	}

	remoteConn, err := dialer.DialContext(sess.Context, "tcp", remoteAddr)
	if err != nil {

		slog.Debug("SOCKS V5: Unable to dial destination",
			slog.String("err", err.Error()),
			slog.String("client_ip", clientConn.RemoteAddr().String()),
			slog.String("sid", sess.ID.String()),
			slog.String("user", sess.UserID),
			slog.String("remote", remoteAddr))

		respond(v5RepErrHostUnreachable, remoteAddr)
		return
	}

	defer remoteConn.Close()

	if err := respond(v5RepOk, remoteConn.LocalAddr().String()); err != nil {
		slog.Debug("SOCKS V5: Connect terminated",
			slog.String("err", err.Error()),
			slog.String("client_ip", clientConn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()))
		return
	}

	slog.Debug("SOCKS V5: Connected",
		slog.String("client_ip", clientConn.RemoteAddr().String()),
		slog.String("user", sess.UserID),
		slog.String("sid", sess.ID.String()),
		slog.String("remote", remoteAddr))

	// add to a wait group to make sure session-stops account the full amount of traffix
	sess.ContextWg.Add(1)
	defer sess.ContextWg.Done()

	txCtx, cancelTx := context.WithCancel(sess.Context)
	rxCtx, cancelRx := context.WithCancel(sess.Context)

	//	start piping connections directly
	go utils.PipeConnection(txCtx, cancelRx, remoteConn, clientConn, sess.MaxDataRateTx, &sess.AcctTxBytes)
	go utils.PipeConnection(rxCtx, cancelTx, clientConn, remoteConn, sess.MaxDataRateTx, &sess.AcctRxBytes)

	//	keep this scope active until pipe routines exit
	<-txCtx.Done()
	<-rxCtx.Done()
}
