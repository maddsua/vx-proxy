package utils

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func ReadBuffN(reader io.Reader, n int) ([]byte, error) {

	if n <= 0 {
		return nil, errors.New("buffer size is zero")
	}

	buff := make([]byte, n)
	bytesRead, err := reader.Read(buff)
	if bytesRead == len(buff) {
		return buff, nil
	} else if err == nil && bytesRead != len(buff) {
		return nil, io.EOF
	}

	return buff, err
}

func ReadByte(reader io.Reader) (byte, error) {
	buff, err := ReadBuffN(reader, 1)
	return buff[0], err
}

type SpeedLimiter interface {
	Limit() (int, bool)
}

// Piper splices two network connections into one and acts as a middleman between the hosts.
//
// 'RX' stands for data received from remote, where 'TX' stands for client-sent data respectively
type ConnectionPiper struct {
	Remote    net.Conn
	RxAcct    *atomic.Int64
	RxMaxRate SpeedLimiter

	Client    net.Conn
	TxAcct    *atomic.Int64
	TxMaxRate SpeedLimiter
}

func (this *ConnectionPiper) Pipe(ctx context.Context) (err error) {

	txCtx, cancelTx := context.WithCancel(ctx)
	rxCtx, cancelRx := context.WithCancel(ctx)

	doneCh := make(chan error, 2)
	defer close(doneCh)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		doneCh <- PipeIO(txCtx, this.Remote, this.Client, this.TxMaxRate, this.TxAcct)
	}()

	go func() {
		defer wg.Done()
		doneCh <- PipeIO(rxCtx, this.Client, this.Remote, this.RxMaxRate, this.RxAcct)
	}()

	select {
	case err = <-doneCh:
	case <-ctx.Done():
	}

	cancelRx()
	cancelTx()

	_ = this.Remote.SetReadDeadline(time.Unix(1, 0))
	_ = this.Client.SetReadDeadline(time.Unix(1, 0))

	wg.Wait()
	return
}

// Direct connection piper function. Use with ConnectionPiper to get automatic controls such as cancellation and what not
func PipeIO(ctx context.Context, dst io.Writer, src io.Reader, limiter SpeedLimiter, acct *atomic.Int64) error {

	const chunkSize = 32 * 1024

	for ctx.Err() == nil {

		copyStarted := time.Now()

		written, err := io.CopyN(dst, src, chunkSize)
		if written > 0 && acct != nil {
			acct.Add(written)
		}

		if flusher, ok := dst.(http.Flusher); ok && (err == nil || err == io.EOF) {
			flusher.Flush()
		}

		if err != nil {
			if ctx.Err() != nil || err == io.EOF {
				return nil
			}
			return err
		}

		//	apply speed limiting by calculating ideal chunk copy time
		//	and waiting any extra time if the operation was completed sooner
		if limiter != nil && written > 0 {
			if limit, has := limiter.Limit(); has {
				expected := time.Duration((int64(time.Second) * written) / int64(limit))
				if delta := expected - time.Since(copyStarted); delta > 0 {
					time.Sleep(delta)
				}
			}
		}
	}

	return nil
}
