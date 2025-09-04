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

	RxAcct *atomic.Int64
	TxAcct *atomic.Int64

	RxBandwidth utils.Bandwidther
	TxBandwidth utils.Bandwidther
}

//	note: should use a buffer here for smoother operations, but this would do for now

func (this *framedConn) Read(b []byte) (int, error) {

	var bandwidth int
	if this.TxBandwidth != nil {
		bandwidth, _ = this.TxBandwidth.Bandwidth()
	}

	//	a short path for when bandwidth limiter is not provided
	if bandwidth <= 0 {

		n, err := this.BaseConn.Read(b)

		if this.TxAcct != nil {
			this.TxAcct.Add(int64(n))
		}

		return n, err
	}

	//	the full bandwidth-controlled path
	maxRead := utils.FramedChunkSize(bandwidth)
	chunkSize := min(maxRead, len(b))
	chunk := make([]byte, chunkSize)
	started := time.Now()

	read, err := this.BaseConn.Read(chunk)
	if read == 0 {
		return read, err
	}

	copy(b, chunk[:read])

	if read < chunkSize {
		select {
		case <-time.After(utils.ExpectIoDoneIn(bandwidth, read)):
		case <-time.After(time.Second - time.Since(started)):
		}
	} else {
		time.Sleep(time.Second - time.Since(started))
	}

	if this.RxAcct != nil {
		this.RxAcct.Add(int64(read))
	}

	return read, err
}

func (this *framedConn) Write(b []byte) (int, error) {

	if len(b) == 0 {
		return 0, nil
	}

	var bandwidth int
	if this.RxBandwidth != nil {
		bandwidth, _ = this.RxBandwidth.Bandwidth()
	}

	//	a short path for when bandwidth limiter is not provided
	if bandwidth <= 0 {

		n, err := this.BaseConn.Write(b)

		if this.TxAcct != nil {
			this.TxAcct.Add(int64(n))
		}

		return n, err
	}

	//	the full bandwidth-controlled path
	var total int
	n := len(b)
	writeMax := utils.FramedChunkSize(bandwidth)

	for total < n {

		chunkSize := min(n-total, writeMax)
		chunk := b[total : total+chunkSize]

		started := time.Now()

		written, err := this.BaseConn.Write(chunk)

		if this.TxAcct != nil {
			this.TxAcct.Add(int64(written))
		}

		total += written

		if err != nil {
			return total, err
		} else if written < chunkSize {
			return total, io.ErrShortWrite
		}

		if written < writeMax {
			select {
			case <-time.After(utils.ExpectIoDoneIn(bandwidth, written)):
			case <-time.After(time.Second - time.Since(started)):
			}
		} else {
			time.Sleep(time.Second - time.Since(started))
		}
	}

	return total, nil
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
	return this.BaseConn.SetDeadline(t)
}

func (this *framedConn) SetReadDeadline(t time.Time) error {
	return this.BaseConn.SetReadDeadline(t)
}

func (this *framedConn) SetWriteDeadline(t time.Time) error {
	return this.BaseConn.SetWriteDeadline(t)
}
