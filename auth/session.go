package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/maddsua/vx-proxy/utils"
)

type Session struct {
	ID       uuid.UUID
	UserName *string
	ClientID string

	//	An outbound IP assigned to this session
	FramedIP net.IP

	//	Session state timeouts
	Timeout     time.Duration
	IdleTimeout time.Duration

	//	Sets the limit of concurrent connection
	MaxConcurrentConnections int

	//	An http client to be used by the client
	FramedHttpClient *http.Client

	//	Traffic controller shit
	TrafficCtl *TrafficCtl

	//	Accounting tracking
	lastActivity time.Time
	lastUpdated  time.Time

	//	Session wait group makes sure a session isn't closed until all the operations have been finished
	Wg sync.WaitGroup

	//	Internal context controls
	ctx       context.Context
	cancelCtx context.CancelFunc
}

type SessionOptions struct {
	Timeout     time.Duration
	IdleTimeout time.Duration

	MaxConcurrentConnections int

	ActualRateRx int
	ActualRateTx int

	MaximumRateRx int
	MaximumRateTx int

	MinimumRateRx int
	MinimumRateTx int
}

func (this *Session) Context() context.Context {
	return this.ctx
}

func (this *Session) BumpActive() {
	this.lastActivity = time.Now()
}

func (this *Session) IsCancelled() bool {

	if this.ctx == nil {
		return true
	}

	return this.ctx.Err() != nil
}

func (this *Session) IsIdle() bool {

	if this.IdleTimeout > 0 && !this.lastActivity.IsZero() {
		return time.Since(this.lastActivity) > this.IdleTimeout
	}

	return false
}

func (this *Session) Expired() bool {

	if this.ctx == nil {
		return true
	}

	deadline, ok := this.ctx.Deadline()
	return ok && deadline.Before(time.Now())
}

func (this *Session) CanAcceptConnection() bool {
	return this.MaxConcurrentConnections <= 0 || this.TrafficCtl.Connections() < this.MaxConcurrentConnections
}

func (this *Session) Close() {

	if this.ctx.Err() == nil {
		this.cancelCtx()
	}

	this.TrafficCtl.Close()

	this.Wg.Wait()

	if this.FramedHttpClient != nil {

		if transport, ok := this.FramedHttpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}

		this.FramedHttpClient = nil
	}
}

type CredentialsMiss struct {
	Expires  time.Time
	Username string
}

func (this *CredentialsMiss) Expired() bool {
	return !this.Expires.IsZero() && this.Expires.Before(time.Now())
}

// SessionConfig provides default session options.
//
//	These options can be overriden by radius
type SessionConfig struct {
	Timeout     string `yaml:"timeout"`
	IdleTimeout string `yaml:"idle_timeout"`

	MaxConcurrentConnections int `yaml:"max_concurrent_connections"`

	ActualRateRx string `yaml:"actual_rate_rx"`
	ActualRateTx string `yaml:"actual_rate_tx"`

	MaximumRateRx string `yaml:"maximum_rate_rx"`
	MaximumRateTx string `yaml:"maximum_rate_tx"`

	MinimumRateRx string `yaml:"minimum_rate_rx"`
	MinimumRateTx string `yaml:"minimum_rate_tx"`
}

func (this SessionConfig) Parse() (SessionOptions, error) {

	opts := SessionOptions{}

	if attr := this.Timeout; attr != "" {
		val, err := time.ParseDuration(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("timeout value too small")
		}
		opts.Timeout = val
	}

	if attr := this.IdleTimeout; attr != "" {
		val, err := time.ParseDuration(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing idle_timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("idle_timeout value too small")
		}
		opts.IdleTimeout = val
	}

	if attr := this.MaxConcurrentConnections; attr > 0 {
		opts.MaxConcurrentConnections = attr
	}

	if attr := this.ActualRateRx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing actual_rate_rx: %v", err)
		}
		opts.ActualRateRx = val
	}

	if attr := this.ActualRateTx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing actual_rate_tx: %v", err)
		}
		opts.ActualRateTx = val
	}

	if attr := this.MaximumRateRx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing maximum_rate_rx: %v", err)
		}
		opts.MaximumRateRx = val
	}

	if attr := this.MaximumRateTx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing maximum_rate_tx: %v", err)
		}
		opts.MaximumRateTx = val
	}

	if attr := this.MinimumRateRx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing minimum_rate_rx: %v", err)
		}
		opts.MinimumRateRx = val
	}

	if attr := this.MinimumRateTx; attr != "" {
		val, err := utils.ParseDataRate(attr)
		if err != nil {
			return opts, fmt.Errorf("error parsing minimum_rate_tx: %v", err)
		}
		opts.MinimumRateTx = val
	}

	return opts, nil
}

func (this SessionConfig) Unwrap() SessionOptions {

	opts, _ := this.Parse()

	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Minute
	}

	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 5 * time.Minute
	}

	if opts.MaxConcurrentConnections == 0 {
		opts.MaxConcurrentConnections = 256
	}

	if opts.ActualRateRx == 0 {
		opts.ActualRateRx = 50_000_000
	}

	if opts.ActualRateTx == 0 {
		opts.ActualRateTx = 25_000_000
	}

	return opts
}
