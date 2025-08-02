package socks

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

const (
	socksProtoVersion5 = byte(0x05)
	socksProtoReserved = byte(0x00)
)

type ConnectionHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

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

	versionByte, err := utils.ReadByte(conn)
	if err != nil {
		slog.Debug("SOCKS: Error reading version byte",
			slog.Any("err", err),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	var next ConnectionHandler

	switch versionByte {

	case socksProtoVersion5:
		next = &socksV5Proxy{
			Dns: this.Dns,
			Auth: map[socksV5AuthMethod]socksV5Authenticator{
				socksV5AuthMethodPassword: &socksV5PasswordAuthenticator{
					Controller: this.Auth,
				},
			},
		}
	}

	if next == nil {
		slog.Debug("SOCKS: Unsupported version number",
			slog.Int("vn", int(versionByte)),
			slog.String("client_ip", conn.RemoteAddr().String()))
		return
	}

	next.HandleConnection(ctx, conn)
}

// This error can be returned from various auth hanlers to indicate invalid credentials;
// it exists so that you don't have to pass the actuall credentials all around
type CredentialsError struct {
	Username string
}

func (this CredentialsError) Error() string {
	return auth.ErrUnauthorized.Error()
}
