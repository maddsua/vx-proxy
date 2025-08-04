package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

type Config struct {
	PortRange string `yaml:"port_range"`
}

func (this *Config) Validate() error {

	if this.PortRange == "" {
		return fmt.Errorf("port_range is missing")
	}

	if _, err := utils.ParseRange(this.PortRange); err != nil {
		return fmt.Errorf("port_range format invalid")
	}

	return nil
}

func (this Config) BindsPorts() []string {

	var ports []string

	if portRange, err := utils.ParseRange(this.PortRange); err == nil {
		for port := portRange.Begin; port <= portRange.End; port++ {
			ports = append(ports, fmt.Sprintf("%d/tcp", port))
		}
	}

	return ports
}

type HttpServer struct {
	Config

	Auth auth.Controller
	Dns  *net.Resolver

	pool []*http.Server
	wg   sync.WaitGroup

	ctx       context.Context
	cancelCtx context.CancelFunc
}

func (this *HttpServer) ListenAndServe() error {

	requestHandler := &HttpProxy{
		Auth: this.Auth,
		Dns:  this.Dns,
	}

	portRange, err := utils.ParseRange(this.Config.PortRange)
	if err != nil {
		return fmt.Errorf("invalid port range: '%v'", this.Config.PortRange)
	}

	errorCh := make(chan error, 1)

	this.ctx, this.cancelCtx = context.WithCancel(context.Background())

	for port := portRange.Begin; port <= portRange.End && portRange.Begin != portRange.End; port++ {

		portSrv := http.Server{
			Addr:        fmt.Sprintf(":%d", port),
			Handler:     requestHandler,
			ConnContext: setContextConn,
		}

		this.pool = append(this.pool, &portSrv)

		this.wg.Add(1)

		go func() {

			defer this.wg.Done()

			if err := portSrv.ListenAndServe(); err != nil && this.ctx.Err() == nil {
				errorCh <- fmt.Errorf("serve: %s: %v", portSrv.Addr, err)
			}
		}()
	}

	select {
	case err := <-errorCh:
		this.Close()
		return err
	case <-this.ctx.Done():
		return nil
	}
}

func (this *HttpServer) Close() {

	if this.ctx == nil {
		return
	}

	this.cancelCtx()

	for _, srv := range this.pool {
		if srv != nil {
			srv.Close()
		}
	}

	this.wg.Wait()

	this.ctx = nil
	this.cancelCtx = nil
}

type httpRequestContext struct{}

func setContextConn(parentCtx context.Context, conn net.Conn) context.Context {
	return context.WithValue(parentCtx, httpRequestContext{}, conn)
}

func getContextConn(ctx context.Context) net.Conn {
	if val, ok := ctx.Value(httpRequestContext{}).(net.Conn); ok && val != nil {
		return val
	}
	return nil
}
