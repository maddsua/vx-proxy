package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

type SwarmServer struct {
	Network string
	Host    string
	Handler ConnectionHandler
	Ports   []int

	pool      []net.Listener
	wg        sync.WaitGroup
	ctx       context.Context
	cancelCtx context.CancelFunc
}

type ConnectionHandler func(ctx context.Context, listener net.Listener)

func (this *SwarmServer) Serve() error {

	if this.Handler == nil {
		return errors.New("handler is nil")
	} else if len(this.Ports) == 0 {
		return errors.New("ports list is empty")
	}

	ctx, cancel := context.WithCancel(context.Background())
	this.ctx = ctx
	this.cancelCtx = cancel

	errChan := make(chan error, 1)
	defer close(errChan)

	for _, port := range this.Ports {

		network := this.Network
		if network == "" {
			network = "tcp"
		}

		listener, err := net.Listen(network, net.JoinHostPort(this.Host, strconv.Itoa(port)))
		if err != nil {
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

			this.Handler(this.ctx, listener)
		}()
	}

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (this *SwarmServer) Close() error {

	if this.ctx == nil {
		return errors.New("swarm context is nil")
	}

	this.cancelCtx()
	this.wg.Wait()
	return nil
}

func UnwarpPortRange(portRange [2]int) []int {

	var result []int

	for port := portRange[0]; port <= portRange[1]; port++ {
		result = append(result, port)
	}

	return result
}
