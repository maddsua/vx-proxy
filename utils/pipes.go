package utils

import (
	"context"
	"errors"
	"io"
	"net"
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
func PipeIO(ctx context.Context, dst io.Writer, src io.Reader, limiter SpeedLimiter, transferAcct *atomic.Int64) error {

	const buffSize = 32 * 1024

	for ctx.Err() == nil {

		chunkCopyStarted := time.Now()

		bytesSent, err := io.CopyN(dst, src, buffSize)
		if bytesSent > 0 && transferAcct != nil {
			transferAcct.Add(bytesSent)
		}

		if err != nil {
			if ctx.Err() != nil || err == io.EOF {
				return nil
			}
			return err
		}

		//	apply speed limiting by calculating ideal chunk copy time
		//	and waiting any extra time if the operation was completed sooner
		if limiter != nil {
			if limit, has := limiter.Limit(); has {
				chunkTimeout := time.Duration(int64(time.Second*buffSize) / int64(limit))
				if delay := chunkTimeout - time.Since(chunkCopyStarted); delay > 0 {
					time.Sleep(delay)
				}
			}
		}
	}

	return nil
}
