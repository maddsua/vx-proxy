package http

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type Config struct {
	PortRange string `yaml:"port_range"`
}

type HttpServer struct {
	Config

	Auth auth.Controller
	Dns  *net.Resolver

	pool []net.Listener
	wg   sync.WaitGroup

	handler *TunnelProxy

	ctx       context.Context
	cancelCtx context.CancelFunc
}

func (this *HttpServer) ListenAndServe() error {

	this.handler = &TunnelProxy{
		Auth: this.Auth,
		Dns:  this.Dns,
	}

	portRange, err := utils.ParseRange(this.Config.PortRange)
	if err != nil {
		return fmt.Errorf("invalid port range: '%v'", this.Config.PortRange)
	}

	this.ctx, this.cancelCtx = context.WithCancel(context.Background())

	for port := portRange.Begin; port <= portRange.End && portRange.Begin != portRange.End; port++ {

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			this.shutdown()
			return err
		}

		this.pool = append(this.pool, listener)
		this.wg.Add(1)

		go func() {

			defer this.wg.Done()
			defer listener.Close()

			for this.ctx.Err() == nil {

				next, err := listener.Accept()
				if err != nil {

					if this.ctx.Err() != nil {
						return
					}

					slog.Debug("http server: failed to accept",
						slog.String("err", err.Error()))

					continue
				}

				go func(conn net.Conn) {

					defer func() {
						if err := recover(); err != nil {
							slog.Error("http server: handler panic recovered",
								slog.Any("err", err))
						}
					}()

					defer conn.Close()

					this.handler.HandleConnection(this.ctx, conn)
				}(next)
			}
		}()
	}

	<-this.ctx.Done()
	return nil
}

func (this *HttpServer) shutdown() {

	this.cancelCtx()

	for _, listener := range this.pool {
		if listener != nil {
			listener.Close()
		}
	}

	this.wg.Wait()

	this.ctx = nil
	this.cancelCtx = nil
}

func (this *HttpServer) Close() error {

	if this.ctx == nil {
		return nil
	}

	this.shutdown()
	return nil
}

type AddrPorter interface {
	AddrPort() netip.AddrPort
}
