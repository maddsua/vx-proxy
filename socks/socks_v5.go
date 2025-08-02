package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type socksV5Authenticator interface {
	Authorize(ctx context.Context, conn net.Conn) (*auth.Session, error)
}

type socksV5Reply byte

const (
	socksV5ReplOk                  = socksV5Reply(0x00)
	socksV5ErrGeneric              = socksV5Reply(0x01)
	socksV5ErrConnNotAllowed       = socksV5Reply(0x02)
	socksV5ErrNetUnreachable       = socksV5Reply(0x03)
	socksV5ErrHostUnreachable      = socksV5Reply(0x04)
	socksV5ErrConnRefused          = socksV5Reply(0x05)
	socksV5ErrTtlExpired           = socksV5Reply(0x06)
	socksV5ErrCmdNotSupported      = socksV5Reply(0x07)
	socksV5ErrAddrTypeNotSupported = socksV5Reply(0x08)
)

// socksv5 proxy is dispatched from the root handler;
// it doesn't do version checks as it's assumed that they've already been done
type socksV5Proxy struct {
	Auth map[socksV5AuthMethod]socksV5Authenticator
	Dns  *net.Resolver
}

func (this *socksV5Proxy) HandleConnection(ctx context.Context, conn net.Conn) {

	clientIP, _, _ := utils.GetAddrPort(conn.RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(conn.LocalAddr())

	var sess *auth.Session

	var writeReply = func(reply socksV5Reply) error {
		//	note: not writing the address fields here as they're simply missing;
		//	possibly needs to be fixed in the future but idk atm
		_, err := conn.Write([]byte{socksProtoVersion5, byte(reply), socksProtoReserved})
		return err
	}

	methods, err := readsocksV5AuthMethods(conn)
	if err != nil {
		slog.Debug("SOCKSv5: Handshake error",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("err", err.Error()))
		writeReply(socksV5ErrGeneric)
		return
	}

	var writeAuthMethod = func(method socksV5AuthMethod) error {
		_, err := conn.Write([]byte{socksProtoVersion5, byte(method)})
		return err
	}

	for _, method := range methods {

		if methodImpl, has := this.Auth[method]; has {

			if err := writeAuthMethod(method); err != nil {
				slog.Debug("SOCKSv5: Protocol error",
					slog.String("nas_addr", nasIP.String()),
					slog.Int("nas_port", nasPort),
					slog.String("client_ip", clientIP.String()),
					slog.String("err", err.Error()))
				return
			}

			if sess, err = methodImpl.Authorize(ctx, conn); err != nil {

				if credErr, ok := err.(CredentialsError); ok {
					slog.Debug("SOCKSv5: Password auth: Unauthorized",
						slog.String("nas_addr", nasIP.String()),
						slog.Int("nas_port", nasPort),
						slog.String("client_ip", clientIP.String()),
						slog.String("username", credErr.Username))
				} else {
					slog.Error("SOCKSv5: Password auth failed",
						slog.String("nas_addr", nasIP.String()),
						slog.Int("nas_port", nasPort),
						slog.String("client_ip", clientIP.String()),
						slog.String("err", err.Error()))
				}

				return
			}

			break
		}
	}

	if sess == nil {
		slog.Debug("SOCKSv5: No acceptable auth methods",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()))
		_ = writeAuthMethod(socksV5AuthMethodUnacceptable)
		return
	}

	cmd, err := readSocksV5Cmd(conn)
	if err != nil {
		slog.Debug("SOCKSv5: Command error",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("err", err.Error()))
		_ = writeReply(socksV5ErrGeneric)
		return
	}

	switch cmd {

	case socksV5CmdConnect:

		this.connect(conn, sess)

	default:
		_ = writeReply(socksV5ErrCmdNotSupported)
	}
}

func (this *socksV5Proxy) connect(conn net.Conn, sess *auth.Session) {

	clientIP, _, _ := utils.GetAddrPort(conn.RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(conn.LocalAddr())

	var writeReply = func(reply socksV5Reply, addr socksV5Addr) error {
		addrBuff, _ := addr.MarshallBinary()
		_, err := conn.Write(append([]byte{socksProtoVersion5, byte(reply), socksProtoReserved}, addrBuff...))
		return err
	}

	dstAddr, err := readSocksV5Addr(conn)
	if err != nil {
		slog.Debug("SOCKSv5: Connect: Failed to read remote addr",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("err", err.Error()))
		_ = writeReply(socksV5ErrAddrTypeNotSupported, dstAddr)
		return
	}

	if err := utils.DestHostAllowed(string(dstAddr)); err != nil {
		slog.Warn("SOCKSv5: Connect: Dialed host not allowed",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("host", string(dstAddr)))
		_ = writeReply(socksV5ErrNetUnreachable, dstAddr)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("SOCKSv5: Connect: Failed to reset connection deadline",
			slog.Any("err", err),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	dialer := net.Dialer{
		LocalAddr: utils.GetReverseDialAddrTcp(conn),
		Resolver:  this.Dns,
	}

	dstConn, err := dialer.DialContext(sess.Context, "tcp", string(dstAddr))
	if err != nil {

		slog.Debug("SOCKSv5: Connect: Unable to dial destination",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("remote", string(dstAddr)),
			slog.String("err", err.Error()))

		_ = writeReply(socksV5ErrHostUnreachable, dstAddr)
		return
	}

	defer dstConn.Close()

	if err := writeReply(socksV5ReplOk, socksV5Addr(dstConn.LocalAddr().String())); err != nil {
		slog.Debug("SOCKSv5: Connect: Terminated",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("username", *sess.UserName),
			slog.String("err", err.Error()))
		return
	}

	slog.Debug("SOCKSv5: Connected",
		slog.String("nas_addr", nasIP.String()),
		slog.Int("nas_port", nasPort),
		slog.String("client_ip", clientIP.String()),
		slog.String("client_id", sess.ClientID),
		slog.String("sid", sess.ID.String()),
		slog.String("username", *sess.UserName),
		slog.String("remote", string(dstAddr)))

	// add to a wait group to make sure session-stops account the full amount of traffix
	sess.ContextWg.Add(1)
	defer sess.ContextWg.Done()

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
		slog.Debug("SOCKSv5: Connect: Broken pipe",
			slog.String("nas_addr", nasIP.String()),
			slog.Int("nas_port", nasPort),
			slog.String("client_ip", clientIP.String()),
			slog.String("client_id", sess.ClientID),
			slog.String("sid", sess.ID.String()),
			slog.String("err", err.Error()))
	}
}

const (
	socksV5AddrIPV4   = byte(0x01)
	socksV5AddrDomain = byte(0x03)
	socksV5AddrIPv6   = byte(0x04)
)

type socksV5Addr string

func (this socksV5Addr) MarshallBinary() ([]byte, error) {

	if this == "" {
		return nil, nil
	}

	var buff []byte

	hostStr, portStr, err := net.SplitHostPort(string(this))
	if err != nil {
		return nil, fmt.Errorf("invalid 'addr:port': %v", err)
	}

	hostAddr := net.ParseIP(hostStr)

	switch {
	case len(hostAddr) == net.IPv4len:
		buff = append(buff, socksV5AddrIPV4)
		buff = append(buff, hostAddr...)
	case len(hostAddr) == net.IPv6len:
		buff = append(buff, socksV5AddrIPv6)
		buff = append(buff, hostAddr...)
	default:
		buff = append(buff, socksV5AddrDomain, byte(len(hostStr)&0xff))
		buff = append(buff, hostStr...)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	buff = append(buff, byte(port>>8), byte(port&0xff))
	if len(buff) >= 0xff {
		return nil, fmt.Errorf("address too large")
	}

	return buff, nil
}

func readSocksV5Addr(reader io.Reader) (socksV5Addr, error) {

	addrType, err := utils.ReadByte(reader)
	if err != nil {
		return "", err
	}

	var addrLen uint8
	var addrIsIP bool

	switch addrType {

	case socksV5AddrIPV4:
		addrLen = net.IPv4len
		addrIsIP = true

	case socksV5AddrIPv6:
		addrLen = net.IPv6len
		addrIsIP = true

	case socksV5AddrDomain:
		addrLen, err = utils.ReadByte(reader)
		if err != nil {
			return "", err
		}

	default:
		return "", errors.New("invalid socks v5 dst addr type")
	}

	addrBuff, err := utils.ReadBuffN(reader, int(addrLen))
	if err != nil {
		return "", err
	}

	portBuff, err := utils.ReadBuffN(reader, 2)
	if err != nil {
		return "", err
	}

	var hostname string
	if addrIsIP {
		hostname = net.IP(addrBuff).String()
	} else {
		hostname = string(addrBuff)
	}

	port := strconv.Itoa((int(portBuff[0]) << 8) | int(portBuff[1]))

	return socksV5Addr(net.JoinHostPort(hostname, port)), nil
}

type socksV5AuthMethod byte

func (this socksV5AuthMethod) Valid() bool {
	switch this {
	case socksV5AuthMethodNone,
		socksV5AuthMethodGSSAPI,
		socksV5AuthMethodPassword,
		socksV5AuthMethodChallengeHandshake,
		socksV5AuthMethodChallengeResponse,
		socksV5AuthMethodSSL,
		socksV5AuthMethodNDSAuth,
		socksV5AuthMethodMultiAuthFramework,
		socksV5AuthMethodJSON,
		socksV5AuthMethodUnacceptable:
		return true
	default:
		return false
	}
}

// Reference: https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
const (
	socksV5AuthMethodNone               = socksV5AuthMethod(0x00)
	socksV5AuthMethodGSSAPI             = socksV5AuthMethod(0x01)
	socksV5AuthMethodPassword           = socksV5AuthMethod(0x02)
	socksV5AuthMethodChallengeHandshake = socksV5AuthMethod(0x03)
	socksV5AuthMethodChallengeResponse  = socksV5AuthMethod(0x05)
	socksV5AuthMethodSSL                = socksV5AuthMethod(0x06)
	socksV5AuthMethodNDSAuth            = socksV5AuthMethod(0x07)
	socksV5AuthMethodMultiAuthFramework = socksV5AuthMethod(0x08)
	socksV5AuthMethodJSON               = socksV5AuthMethod(0x09)
	socksV5AuthMethodUnacceptable       = socksV5AuthMethod(0xff)
)

func readsocksV5AuthMethods(reader io.Reader) ([]socksV5AuthMethod, error) {

	nmethods, err := utils.ReadByte(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read 'nmethods': %v", err)
	}

	methodBuff, err := utils.ReadBuffN(reader, int(nmethods))
	if err != nil {
		return nil, fmt.Errorf("failed to read 'methods': %v", err)
	}

	methods := make([]socksV5AuthMethod, nmethods)
	for idx, val := range methodBuff {

		method := socksV5AuthMethod(val)
		if !method.Valid() {
			return nil, fmt.Errorf("invalid method value: '%v'", val)
		}

		methods[idx] = method
	}

	return methods, nil
}

type socksV5PasswordAuthStatus byte

const (
	socksV5PasswordAuthVersion = byte(0x01)
	socksV5PasswordAuthOk      = socksV5PasswordAuthStatus(0x00)
	socksV5PasswordAuthFail    = socksV5PasswordAuthStatus(0x01)
)

type socksV5PasswordAuthenticator struct {
	Controller auth.Controller
}

func (this *socksV5PasswordAuthenticator) Authorize(ctx context.Context, conn net.Conn) (*auth.Session, error) {

	var readCredentials = func(reader io.Reader) (*auth.BasicCredentials, error) {

		buff, err := utils.ReadBuffN(reader, 2)
		if err != nil {
			return nil, err
		}

		ver := buff[0]
		ulen := buff[1]

		if ver != socksV5PasswordAuthVersion {
			return nil, fmt.Errorf("invalid auth version")
		} else if ulen == 0 {
			return nil, fmt.Errorf("username length is zero")
		}

		unamePlus, err := utils.ReadBuffN(reader, int(ulen)+1)
		if err != nil {
			return nil, err
		}

		var password string
		if plen := unamePlus[int(ulen)]; plen > 0 {
			if val, err := utils.ReadBuffN(reader, int(plen)); err != nil {
				return nil, err
			} else {
				password = string(val)
			}
		}

		return &auth.BasicCredentials{
			Username: string(unamePlus[:int(ulen)]),
			Password: password,
		}, nil
	}

	var writeStatus = func(status socksV5PasswordAuthStatus) error {
		_, err := conn.Write([]byte{socksV5PasswordAuthVersion, byte(status)})
		return err
	}

	creds, err := readCredentials(conn)
	if err != nil {
		_ = writeStatus(socksV5PasswordAuthFail)
		return nil, fmt.Errorf("unable to parse credentials")
	}

	clientIP, _, _ := utils.GetAddrPort(conn.RemoteAddr())
	nasIP, nasPort, _ := utils.GetAddrPort(conn.LocalAddr())

	sess, err := this.Controller.WithPassword(ctx, auth.PasswordProxyAuth{
		BasicCredentials: *creds,
		ClientIP:         clientIP,
		NasAddr:          nasIP,
		NasPort:          nasPort,
	})

	switch err {
	case nil:
		err = writeStatus(socksV5PasswordAuthOk)
		return sess, err
	case auth.ErrUnauthorized:
		err = CredentialsError{Username: creds.Username}
	}

	if err := writeStatus(socksV5PasswordAuthFail); err != nil {
		return nil, err
	}

	return sess, err
}

type socksV5Cmd byte

func (this socksV5Cmd) Valid() bool {
	switch this {
	case socksV5CmdAssociate,
		socksV5CmdBind,
		socksV5CmdConnect:
		return true
	}
	return false
}

const (
	socksV5CmdConnect   = socksV5Cmd(0x01)
	socksV5CmdBind      = socksV5Cmd(0x02)
	socksV5CmdAssociate = socksV5Cmd(0x03)
)

func readSocksV5Cmd(reader io.Reader) (socksV5Cmd, error) {

	buff, err := utils.ReadBuffN(reader, 3)
	if err != nil {
		return 0x00, fmt.Errorf("unable to read command: %v", err)
	}

	if buff[0] != socksProtoVersion5 {
		return 0x00, fmt.Errorf("invalid protocol version: %v", buff[0])
	} else if buff[2] != socksProtoReserved {
		return 0x00, fmt.Errorf("protocol error")
	}

	cmd := socksV5Cmd(buff[1])
	if !cmd.Valid() {
		return 0x00, fmt.Errorf("invalid command: %v", cmd)
	}

	return cmd, nil
}
