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
	Timeout                  time.Duration
	IdleTimeout              time.Duration
	MaxConcurrentConnections int
	MaxRxRate                int
	MaxTxRate                int
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

func (this *Session) Terminate() {

	if this.cancelCtx != nil {
		this.cancelCtx()
	}

	this.closeDependencies()
}

func (this *Session) closeDependencies() {

	this.TrafficCtl.Close()

	if this.FramedHttpClient != nil {
		if tr, ok := this.FramedHttpClient.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
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
	Timeout                  string `yaml:"timeout"`
	IdleTimeout              string `yaml:"idle_timeout"`
	MaxConcurrentConnections int    `yaml:"max_concurrent_connections"`
	MaxDownloadRate          string `yaml:"max_download_rate"`
	MaxUploadRate            string `yaml:"max_upload_rate"`
}

func (this SessionConfig) Parse() (SessionOptions, error) {

	opts := SessionOptions{
		MaxConcurrentConnections: this.MaxConcurrentConnections,
	}

	if this.Timeout != "" {
		val, err := time.ParseDuration(this.Timeout)
		if err != nil {
			return opts, fmt.Errorf("error parsing timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("timeout value too small")
		}
		opts.Timeout = val
	}

	if this.IdleTimeout != "" {
		val, err := time.ParseDuration(this.IdleTimeout)
		if err != nil {
			return opts, fmt.Errorf("error parsing idle_timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("idle_timeout value too small")
		}
		opts.IdleTimeout = val
	}

	if this.MaxConcurrentConnections < 0 {
		return opts, fmt.Errorf("max_concurrent_connections value invalid")
	}

	if this.MaxDownloadRate != "" {
		val, err := utils.ParseDataRate(this.MaxDownloadRate)
		if err != nil {
			return opts, fmt.Errorf("error parsing max_download_rate: %v", err)
		}
		opts.MaxRxRate = val
	}

	if this.MaxUploadRate != "" {
		val, err := utils.ParseDataRate(this.MaxUploadRate)
		if err != nil {
			return opts, fmt.Errorf("error parsing max_upload_rate: %v", err)
		}
		opts.MaxTxRate = val
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

	if opts.MaxRxRate == 0 {
		opts.MaxRxRate = 50_000_000
	}

	if opts.MaxTxRate == 0 {
		opts.MaxTxRate = 25_000_000
	}

	return opts
}
