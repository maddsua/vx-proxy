package http

import (
	"context"
	"net"
)

type localAddrCtxKey struct{}

func SetContextLocalAddr(parent context.Context, value net.Addr) context.Context {
	return context.WithValue(parent, localAddrCtxKey{}, value)
}

func GetContextLocalAddr(ctx context.Context) (net.IP, int) {

	val := ctx.Value(localAddrCtxKey{})
	if val == nil {
		return nil, 0
	}

	if addr, ok := val.(*net.TCPAddr); ok {
		return addr.IP, addr.Port
	}

	if addr, ok := val.(*net.UDPAddr); ok {
		return addr.IP, addr.Port
	}

	return nil, 0
}
