package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

func framedClient(sess *auth.Session, dns *net.Resolver) *http.Client {

	if sess.FramedHttpClient == nil {

		if sess.FramedIP == nil {
			return http.DefaultClient
		}

		dialer := utils.NewTcpDialer(sess.FramedIP, dns)

		var dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {

			baseConn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}

			return &framedConn{
				BaseConn:    baseConn,
				RxAcct:      &sess.AcctRxBytes,
				TxAcct:      &sess.AcctTxBytes,
				RxBandwidth: sess.BandwidthRx(),
				TxBandwidth: sess.BandwidthTx(),
			}, nil
		}

		sess.FramedHttpClient = &http.Client{
			Transport: &http.Transport{
				DialContext:           dialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}

	return sess.FramedHttpClient
}

type framedConn struct {
	BaseConn net.Conn

	RxDeadline time.Time
	TxDeadline time.Time

	RxAcct *atomic.Int64
	TxAcct *atomic.Int64

	RxBandwidth utils.Bandwidther
	TxBandwidth utils.Bandwidther
}

func (this *framedConn) Read(b []byte) (n int, err error) {

	started := time.Now()

	n, err = this.BaseConn.Read(b)

	if n > 0 && this.RxAcct != nil {
		this.RxAcct.Add(int64(n))
	}

	if bandwidth, has := this.RxBandwidth.Bandwidth(); has {
		if err != nil || err == io.EOF {
			framedConnSlowdown(started, this.RxDeadline, bandwidth, n)
		}
	}

	return
}

func (this *framedConn) Write(b []byte) (n int, err error) {

	started := time.Now()

	n, err = this.BaseConn.Write(b)

	if n > 0 && this.TxAcct != nil {
		this.TxAcct.Add(int64(n))
	}

	if bandwidth, has := this.TxBandwidth.Bandwidth(); has {
		if err != nil || err == io.EOF {
			framedConnSlowdown(started, this.TxDeadline, bandwidth, n)
		}
	}

	return
}

func (this *framedConn) Close() error {
	return this.BaseConn.Close()
}

func (this *framedConn) LocalAddr() net.Addr {
	return this.BaseConn.LocalAddr()
}

func (this *framedConn) RemoteAddr() net.Addr {
	return this.BaseConn.RemoteAddr()
}

func (this *framedConn) SetDeadline(t time.Time) error {

	this.RxDeadline = t
	this.TxDeadline = t

	return this.BaseConn.SetDeadline(t)
}

func (this *framedConn) SetReadDeadline(t time.Time) error {

	this.RxDeadline = t

	return this.BaseConn.SetReadDeadline(t)
}

func (this *framedConn) SetWriteDeadline(t time.Time) error {

	this.TxDeadline = t

	return this.BaseConn.SetWriteDeadline(t)
}

func framedConnSlowdown(started time.Time, deadline time.Time, bandwidth int, size int) {

	elapsed := time.Since(started)
	expected := utils.ExpectIoDoneIn(bandwidth, size)
	if elapsed >= expected {
		return
	}

	deadlineExceeded := make(<-chan time.Time)
	if until := time.Until(deadline); until > 0 {
		deadlineExceeded = time.After(until)
	}

	select {
	case <-deadlineExceeded:
	case <-time.After(expected - elapsed):
	}
}
