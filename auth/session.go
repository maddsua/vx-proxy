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
	ID            uuid.UUID
	UserName      *string
	ClientID      string
	MaxDataRateRx int
	MaxDataRateTx int
	IdleTimeout   time.Duration

	//	An outbound IP assigned to this session
	FramedIP net.IP

	//	An http client to be used by the client
	FramedHttpClient *http.Client

	lastActivity time.Time
	lastUpdated  time.Time

	AcctRxBytes atomic.Int64
	AcctTxBytes atomic.Int64

	ctx       context.Context
	cancelCtx context.CancelFunc

	wg sync.WaitGroup
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
}

func (this *Session) ConnDone() {
	this.wg.Done()
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

type CredentialsMiss struct {
	Expires  time.Time
	Username string
}

func (this *CredentialsMiss) Expired() bool {
	return !this.Expires.IsZero() && this.Expires.Before(time.Now())
}
