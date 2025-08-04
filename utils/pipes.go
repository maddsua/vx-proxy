package utils

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Piper splices two connections into one and acts as a middleman between two hosts in a cross pattern like so:
//
//	--------------
//	|  A ---> B  |
//	--------------
//	|  B ---> A  |
//	--------------
type ConnectionPiper struct {
	RemoteConn net.Conn
	ClientConn net.Conn

	TotalCounterRx *atomic.Int64
	TotalCounterTx *atomic.Int64
	SpeedCapRx     int
	SpeedCapTx     int
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
		doneCh <- PipeConnection(txCtx, this.RemoteConn, this.ClientConn, this.SpeedCapTx, this.TotalCounterTx)
	}()

	go func() {
		defer wg.Done()
		doneCh <- PipeConnection(rxCtx, this.ClientConn, this.RemoteConn, this.SpeedCapRx, this.TotalCounterRx)
	}()

	select {
	case err = <-doneCh:
	case <-ctx.Done():
	}

	cancelRx()
	cancelTx()

	_ = this.RemoteConn.SetReadDeadline(time.Unix(1, 0))
	_ = this.ClientConn.SetReadDeadline(time.Unix(1, 0))

	wg.Wait()
	return
}

// Direct connection piper function. Use with ConnectionPiper to get automatic controls such as cancellation and what not
func PipeConnection(ctx context.Context, dst net.Conn, src net.Conn, speedCap int, transferAcct *atomic.Int64) error {

	const buffSize = 32 * 1024

	var copyStarted time.Time
	var chunkDelay time.Duration

	if speedCap > 0 {
		chunkDelay = (time.Second * buffSize) / time.Duration(speedCap)
	}

	for ctx.Err() == nil {

		copyStarted = time.Now()

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

		if chunkDelay > 0 {
			time.Sleep(chunkDelay - time.Since(copyStarted))
		}
	}

	return nil
}
