package socks

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type ServerConfig struct {
	PortRange string `yaml:"port_range"`
}

func (this *ServerConfig) Validate() error {

	if this.PortRange == "" {
		return fmt.Errorf("port_range is missing")
	}

	if _, err := utils.ParseRange(this.PortRange); err != nil {
		return fmt.Errorf("port_range format invalid")
	}

	return nil
}

func (this ServerConfig) BindsPorts() []string {

	var ports []string

	if portRange, err := utils.ParseRange(this.PortRange); err == nil {
		for port := portRange.Begin; port <= portRange.End; port++ {
			ports = append(ports, fmt.Sprintf("%d/tcp", port))
		}
	}

	return ports
}

type SocksServer struct {
	ServerConfig

	Auth auth.Controller
	Dns  *net.Resolver

	pool []net.Listener
	wg   sync.WaitGroup

	ctx       context.Context
	cancelCtx context.CancelFunc
}

func (this *SocksServer) ListenAndServe() error {

	connectionHandler := &SocksProxy{
		Auth: this.Auth,
		Dns:  this.Dns,
	}

	portRange, err := utils.ParseRange(this.ServerConfig.PortRange)
	if err != nil {
		return fmt.Errorf("invalid port range: '%v'", this.ServerConfig.PortRange)
	}

	this.ctx, this.cancelCtx = context.WithCancel(context.Background())

	for port := portRange.Begin; port <= portRange.End && portRange.Begin != portRange.End; port++ {

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			this.Close()
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

					slog.Debug("socks server: failed to accept",
						slog.String("err", err.Error()))

					continue
				}

				go func(conn net.Conn) {

					defer func() {
						if err := recover(); err != nil {
							slog.Error("socks server: handler panic recovered",
								slog.Any("err", err))
							fmt.Println("Stack:", string(debug.Stack()))
						}
					}()

					defer conn.Close()

					connectionHandler.HandleConnection(this.ctx, conn)

				}(next)
			}
		}()
	}

	<-this.ctx.Done()
	return nil
}

func (this *SocksServer) Close() {

	if this.ctx == nil {
		return
	}

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
