package socks

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type SocksProxy struct {
	Auth auth.Controller
	Dns  *net.Resolver
}

func (this *SocksProxy) HandleConnection(ctx context.Context, conn net.Conn) {

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
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
func (this *SocksProxy) handleV5(ctx context.Context, conn net.Conn) {

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
			slog.String("nas_addr", authProps.NasAddr.String()),
			slog.String("client_ip", authProps.ClientIP.String()),
			slog.String("username", authProps.Username))

		writeAuthStatus(false)
		return

	} else if err != nil {
		slog.Error("SOCKS V5: Auth error",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()),
			slog.String("err", err.Error()))
		writeError(v5RepErrGeneric)
		return
	}

	if err := writeAuthStatus(true); err != nil {
		slog.Debug("SOCKS V5: Handshake terminated",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()),
			slog.String("err", err.Error()))
		return
	}

	var cmd uint8
	if cmdBuff, err := utils.ReadBuffN(conn, 3); err != nil {
		slog.Debug("SOCKS V5: Handshake error: Failed to read command",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("authd_id", this.Auth.ID()),
			slog.String("err", err.Error()))
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

	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("SOCKS V5: Failed to reset tunnel timeouts",
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("err", err.Error()))
		return
	}

	switch cmd {

	case v5CmdConnect:

		addr, err := v5ReadAddr(conn)
		if err != nil {
			slog.Debug("SOCKS V5: Handshake error: Failed to read 'connect' cmd remote addr",
				slog.String("nas_addr", authProps.NasAddr.String()),
				slog.String("client_ip", conn.RemoteAddr().String()),
				slog.String("client_id", sess.ClientID),
				slog.String("username", *sess.UserName),
				slog.String("err", err.Error()))
			return
		}

		this.handleV5Connect(conn, sess, addr)

	default:

		slog.Debug("SOCKS V5: Unsupported command",
			slog.String("nas_addr", authProps.NasAddr.String()),
			slog.String("client_ip", conn.RemoteAddr().String()),
			slog.String("client_id", sess.ClientID),
			slog.String("username", *sess.UserName),
			slog.Int("cmd", int(cmd)))

		writeError(v5RepErrCmdNotSupported)
	}
}

func (this *SocksProxy) handleV5Connect(clientConn net.Conn, sess *auth.Session, remoteAddr string) {

	var respond = func(rep byte, addr string) error {
		_, err := clientConn.Write(append([]byte{v5Ver, rep, v5ByteReserved}, v5PackAddr(addr)...))
		return err
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetLocalDialAddrTCP(clientConn.LocalAddr()),
		Resolver:  this.Dns,
	}

	remoteConn, err := dialer.DialContext(sess.Context, "tcp", remoteAddr)
	if err != nil {

		slog.Debug("SOCKS V5: Unable to dial destination",
			slog.String("client_ip", clientConn.RemoteAddr().String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("remote", remoteAddr),
			slog.String("err", err.Error()))

		respond(v5RepErrHostUnreachable, remoteAddr)
		return
	}

	defer remoteConn.Close()

	if err := respond(v5RepOk, remoteConn.LocalAddr().String()); err != nil {
		slog.Debug("SOCKS V5: Connect terminated",
			slog.String("client_ip", clientConn.RemoteAddr().String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("err", err.Error()))
		return
	}

	slog.Debug("SOCKS V5: Connected",
		slog.String("client_ip", clientConn.RemoteAddr().String()),
		slog.String("client_id", sess.ClientID),
		slog.String("sid", sess.ID.String()),
		slog.String("username", *sess.UserName),
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
