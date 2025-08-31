package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/maddsua/vx-proxy/utils"
)

type Session struct {
	SessionOptions

	ID       uuid.UUID
	UserName *string
	ClientID string

	//	An outbound IP assigned to this session
	FramedIP net.IP

	//	An http client to be used by the client
	FramedHttpClient *http.Client

	//	Accounting tracking
	lastActivity time.Time
	lastUpdated  time.Time

	//	Data volume accounting
	AcctRxBytes atomic.Int64
	AcctTxBytes atomic.Int64

	//	Session controls
	ctx       context.Context
	cancelCtx context.CancelFunc
	wg        sync.WaitGroup
	cc        atomic.Int64
}

type SessionOptions struct {
	Timeout                  time.Duration
	IdleTimeout              time.Duration
	MaxConcurrentConnections int
	EnforceTotalBandwidth    bool
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

func (this *Session) TrackConn() {
	this.wg.Add(1)
	this.cc.Add(1)
}

func (this *Session) ConnDone() {
	this.wg.Done()
	this.cc.Add(-1)
}

func (this *Session) WaitDone() {
	this.wg.Wait()
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
	return this.MaxConcurrentConnections <= 0 || this.cc.Load() < int64(this.MaxConcurrentConnections)
}

func (this *Session) Terminate() {

	if this.cancelCtx != nil {
		this.cancelCtx()
	}

	this.closeDependencies()
}

func (this *Session) closeDependencies() {
	if this.FramedHttpClient != nil {
		if tr, ok := this.FramedHttpClient.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

// todo: rename: BandwidthRx
func (this *Session) ConnectionMaxRx() dynamicSpeedLimiter {

	if this.EnforceTotalBandwidth {
		return dynamicSpeedLimiter{
			bandwidth: this.MaxRxRate,
			peers:     &this.cc,
		}
	}

	return dynamicSpeedLimiter{bandwidth: this.MaxRxRate}
}

// todo: rename: BandwidthTx
func (this *Session) ConnectionMaxTx() dynamicSpeedLimiter {

	if this.EnforceTotalBandwidth {
		return dynamicSpeedLimiter{
			bandwidth: this.MaxTxRate,
			peers:     &this.cc,
		}
	}

	return dynamicSpeedLimiter{bandwidth: this.MaxTxRate}
}

type dynamicSpeedLimiter struct {
	bandwidth int
	peers     *atomic.Int64
}

func (this dynamicSpeedLimiter) Chunker() *utils.IoChunker {

	if this.bandwidth <= 0 {
		return nil
	} else if this.peers == nil {
		return &utils.IoChunker{Bandwidth: this.bandwidth}
	}

	count := this.peers.Load()
	if count <= 1 {
		return &utils.IoChunker{Bandwidth: this.bandwidth}
	}

	return &utils.IoChunker{Bandwidth: this.bandwidth / int(count)}
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
	EnforceTotalBandwidth    bool   `yaml:"enforce_total_bandwidth"`
	MaxDownloadRate          string `yaml:"max_download_rate"`
	MaxUploadRate            string `yaml:"max_upload_rate"`
}

func (this SessionConfig) Parse() (SessionOptions, error) {

	opts := SessionOptions{
		EnforceTotalBandwidth:    this.EnforceTotalBandwidth,
		MaxConcurrentConnections: this.MaxConcurrentConnections,
	}

	if this.Timeout != "" {
		if val, err := time.ParseDuration(this.Timeout); err != nil {
			return opts, fmt.Errorf("error parsing timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("timeout value too small")
		} else {
			opts.Timeout = val
		}
	}

	if this.IdleTimeout != "" {
		if val, err := time.ParseDuration(this.IdleTimeout); err != nil {
			return opts, fmt.Errorf("error parsing idle_timeout: %v", err)
		} else if val < time.Second {
			return opts, fmt.Errorf("idle_timeout value too small")
		} else {
			opts.IdleTimeout = val
		}
	}

	if this.MaxConcurrentConnections < 0 {
		return opts, fmt.Errorf("max_concurrent_connections value invalid")
	}

	if this.MaxDownloadRate != "" {
		if val, err := utils.ParseDataRate(this.MaxDownloadRate); err != nil {
			return opts, fmt.Errorf("error parsing max_download_rate: %v", err)
		} else {
			opts.MaxRxRate = val
		}
	}

	if this.MaxUploadRate != "" {
		if val, err := utils.ParseDataRate(this.MaxUploadRate); err != nil {
			return opts, fmt.Errorf("error parsing max_upload_rate: %v", err)
		} else {
			opts.MaxTxRate = val
		}
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
