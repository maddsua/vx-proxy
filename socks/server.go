package socks

import (
	"context"
	"errors"
	"log/slog"
	"net"
)

type SocksHandler interface {
	HandleConnection(ctx context.Context, conn net.Conn)
}

type SocksServer struct {
	Handler SocksHandler

	ctx       context.Context
	cancelCtx context.CancelFunc
}

func (this *SocksServer) Serve(listener net.Listener) error {

	if listener == nil {
		return errors.New("listener is nil")
	} else if this.Handler == nil {
		return errors.New("handler is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	this.ctx = ctx
	this.cancelCtx = cancel

	for this.ctx.Err() == nil {

		next, err := listener.Accept()
		if err != nil {

			if this.ctx.Err() != nil {
				return nil
			}

			slog.Debug("socks server: failed to accept",
				slog.String("err", err.Error()))

			continue
		}

		go func(next net.Conn) {

			defer func() {
				if err := recover(); err != nil {
					slog.Error("socks server: handler panic recovered",
						slog.Any("err", err))
				}
			}()

			this.Handler.HandleConnection(this.ctx, next)

		}(next)
	}

	return nil
}

func (this *SocksServer) Close() error {
	this.cancelCtx()
	return nil
}
