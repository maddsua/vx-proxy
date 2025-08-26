package auth

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID          uuid.UUID
	UserName    *string
	ClientID    string
	IdleTimeout time.Duration

	//	Max total RX/TX data rate per sessio
	MaxDataRateRx int
	MaxDataRateTx int

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

func (this *Session) ConnectionMaxRx() dynamicSpeedLimiter {
	return dynamicSpeedLimiter{
		maxrate: this.MaxDataRateRx,
		conns:   &this.cc,
	}
}

func (this *Session) ConnectionMaxTx() dynamicSpeedLimiter {
	return dynamicSpeedLimiter{
		maxrate: this.MaxDataRateTx,
		conns:   &this.cc,
	}
}

type dynamicSpeedLimiter struct {
	maxrate int
	conns   *atomic.Int64
}

func (this dynamicSpeedLimiter) Limit() (int, bool) {

	if this.maxrate <= 0 {
		return 0, false
	}

	count := this.conns.Load()
	if count <= 1 {
		return this.maxrate, true
	}

	return this.maxrate / int(count), true
}

type CredentialsMiss struct {
	Expires  time.Time
	Username string
}

func (this *CredentialsMiss) Expired() bool {
	return !this.Expires.IsZero() && this.Expires.Before(time.Now())
}
