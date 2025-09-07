package http

import (
	"context"
	"io"
	"net"
	"net/http"
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

			tctl, err := sess.TrafficCtl.Next()
			if err != nil {
				return nil, err
			}

			return &framedConn{
				BaseConn: baseConn,
				Ctl:      tctl,
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
	Ctl      *auth.ConnCtl
}

func (this *framedConn) Read(buff []byte) (int, error) {

	var bandwidth int
	if bw := this.Ctl.BandwidthRx(); bw != nil {
		if val, has := bw.Bandwidth(); has {
			bandwidth = val
		}
	}

	acct := this.Ctl.AccounterRx()

	//	a short path for when bandwidth limiter is not provided
	if bandwidth <= 0 {

		n, err := this.BaseConn.Read(buff)

		if acct != nil {
			acct.Account(n)
		}

		return n, err
	}

	//	the full bandwidth-controlled path
	chunkSize := min(utils.FramedVolume(bandwidth), len(buff))
	chunk := make([]byte, chunkSize)
	started := time.Now()

	read, err := this.BaseConn.Read(chunk)
	if read == 0 {
		return read, err
	}

	if acct != nil {
		acct.Account(read)
	}

	copy(buff, chunk[:read])

	utils.FramedIoWait(bandwidth, read, started)

	return read, err
}

func (this *framedConn) Write(buff []byte) (int, error) {

	if len(buff) == 0 {
		return 0, nil
	}

	var bandwidth int
	if bw := this.Ctl.BandwidthTx(); bw != nil {
		if val, has := bw.Bandwidth(); has {
			bandwidth = val
		}
	}

	acct := this.Ctl.AccounterTx()

	//	a short path for when bandwidth limiter is not provided
	if bandwidth <= 0 {

		n, err := this.BaseConn.Write(buff)

		if acct != nil {
			acct.Account(n)
		}

		return n, err
	}

	//	the full bandwidth-controlled path
	var total int
	buffSize := len(buff)

	for total < buffSize {

		chunkSize := min(utils.FramedVolume(bandwidth), buffSize-total)
		chunk := buff[total : total+chunkSize]

		started := time.Now()
		written, err := this.BaseConn.Write(chunk)

		if acct != nil {
			acct.Account(written)
		}

		total += written

		if err != nil {
			return total, err
		} else if written < chunkSize {
			return total, io.ErrShortWrite
		}

		utils.FramedIoWait(bandwidth, written, started)
	}

	return total, nil
}

func (this *framedConn) Close() error {
	this.Ctl.Close()
	return this.BaseConn.Close()
}

func (this *framedConn) LocalAddr() net.Addr {
	return this.BaseConn.LocalAddr()
}

func (this *framedConn) RemoteAddr() net.Addr {
	return this.BaseConn.RemoteAddr()
}

func (this *framedConn) SetDeadline(deadline time.Time) error {
	return this.BaseConn.SetDeadline(deadline)
}

func (this *framedConn) SetReadDeadline(deadline time.Time) error {
	return this.BaseConn.SetReadDeadline(deadline)
}

func (this *framedConn) SetWriteDeadline(deadline time.Time) error {
	return this.BaseConn.SetWriteDeadline(deadline)
}
