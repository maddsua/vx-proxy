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

type Bandwidther interface {
	Bandwidth() (int, bool)
}

// Piper splices two network connections into one and acts as a middleman between the hosts.
//
// 'RX' stands for data received from remote, where 'TX' stands for client-sent data respectively
type ConnectionPiper struct {
	Remote    net.Conn
	RxAcct    *atomic.Int64
	RxMaxRate Bandwidther

	Client    net.Conn
	TxAcct    *atomic.Int64
	TxMaxRate Bandwidther
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
func PipeIO(ctx context.Context, dst io.Writer, src io.Reader, limiter Bandwidther, acct *atomic.Int64) error {

	var copyStarted time.Time

	for ctx.Err() == nil {

		var bandwidth int
		if limiter != nil {
			if val, has := limiter.Bandwidth(); has {
				bandwidth = val
			}
		}

		chunkSize := chunkSizeFor(bandwidth)
		copyStarted = time.Now()

		written, err := io.CopyN(dst, src, int64(chunkSize))
		if written > 0 && acct != nil {
			acct.Add(written)
		}

		if flusher, ok := dst.(http.Flusher); ok && (err == nil || err == io.EOF) {
			flusher.Flush()
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if bandwidth > 0 {
			chunkSlowdown(ctx, chunkSize, bandwidth, copyStarted)
		}
	}

	return nil
}

func FramedChunkSize(bandwidth int) int {
	return ((bandwidth / 8) * 95) / 100
}

// Creates a fake io delay to achieve a target data transfer rate
func chunkSlowdown(ctx context.Context, size int, bandwidth int, started time.Time) {

	elapsed := time.Since(started)
	expected := ExpectIoDoneIn(bandwidth, size)
	if elapsed >= expected {
		return
	}

	select {
	case <-ctx.Done():
	case <-time.After(expected - elapsed):
	}
}

// Returns the amount of time it's expected for an IO operation to take. Bandwidth in bps, size in bytes
func ExpectIoDoneIn(bandwidth int, size int) time.Duration {
	//	using a hacky ass formula: to_bits(size)*0.95
	tp := ((bandwidth / 8) * 100) / 95
	return time.Duration(int64(time.Second) * int64(size) / int64(tp))
}

// This wacky lookup table is here to try to fix bandwidth deviations
// caused by inaccurate system timers and various unaccounted I/O delays
func chunkSizeFor(bandwidth int) int {
	switch {
	case bandwidth > 1_000_000_000:
		return 10 * 1024 * 1024
	case bandwidth > 300_000_000:
		return 4 * 1024 * 1024
	case bandwidth > 150_000_000:
		return 2 * 1024 * 1024
	case bandwidth > 100_000_000:
		return 1024 * 1024
	case bandwidth > 50_000_000:
		return 256 * 1024
	case bandwidth > 25_000_000:
		return 128 * 1024
	case bandwidth > 10_000_000:
		return 64 * 1024
	case bandwidth > 1_000_000:
		return 32 * 1024
	default:
		return 16 * 1024
	}
}

type FlushWriter struct {
	io.Writer
}

func (this FlushWriter) Write(p []byte) (n int, err error) {

	if n, err = this.Writer.Write(p); n > 0 {
		if flusher, ok := this.Writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	return
}
