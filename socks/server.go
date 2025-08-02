package socks

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type Config struct {
	PortRange string `yaml:"port_range"`
}

type SocksServer struct {
	Config

	Auth auth.Controller
	Dns  *net.Resolver

	pool []net.Listener
	wg   sync.WaitGroup

	handler *Proxy

	ctx       context.Context
	cancelCtx context.CancelFunc
}

func (this *SocksServer) ListenAndServe() error {

	this.handler = &Proxy{
		Auth: this.Auth,
		Dns:  this.Dns,
	}

	portRange, err := utils.ParseRange(this.Config.PortRange)
	if err != nil {
		return fmt.Errorf("invalid port range: '%v'", this.Config.PortRange)
	}

	this.ctx, this.cancelCtx = context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	defer close(errChan)

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

			defer func() {
				if err := recover(); err != nil {
					errChan <- fmt.Errorf("handler for '%s' panicked: %v", listener.Addr().String(), err)
				}
			}()

			for this.ctx.Err() == nil {

				next, err := listener.Accept()
				if err != nil {

					if this.ctx.Err() != nil {
						return
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

					this.handler.HandleConnection(this.ctx, next)

				}(next)
			}
		}()
	}

	select {
	case err := <-errChan:
		this.shutdown()
		return err
	case <-this.ctx.Done():
		return nil
	}
}

func (this *SocksServer) shutdown() {

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

func (this *SocksServer) Close() error {

	if this.ctx == nil {
		return nil
	}

	this.shutdown()
	return nil
}
