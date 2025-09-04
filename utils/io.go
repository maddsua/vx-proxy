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

	const defaultChunkSize = 32 * 1024

	var copyLimit = func(bandwidth int) error {

		chunk := make([]byte, FramedThroughput(bandwidth))
		started := time.Now()

		read, err := src.Read(chunk)

		if read > 0 {

			written, err := dst.Write(chunk[:read])

			if acct != nil {
				acct.Add(int64(written))
			}

			if err != nil {
				return err
			} else if written < read {
				return io.ErrShortWrite
			}

			FramedIoWait(bandwidth, min(written, read), started)
		}

		return err
	}

	var copyDirect = func() error {

		written, err := io.CopyN(dst, src, defaultChunkSize)

		if acct != nil {
			acct.Add(written)
		}

		return err
	}

	for ctx.Err() == nil {

		var bandwidth int
		if limiter != nil {
			bandwidth, _ = limiter.Bandwidth()
		}

		var err error
		if bandwidth > 0 {
			err = copyLimit(bandwidth)
		} else {
			err = copyDirect()
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

// Returns the amount of time it's expected for an IO operation to take. Bandwidth in bps, size in bytes
func FramedIoDuration(bandwidth int, size int) time.Duration {
	tp := FramedThroughput(bandwidth)
	return time.Duration(int64(time.Second) * int64(size) / int64(tp))
}

// Returns bandwidth converted into a chunk size in bytes (per second)
func FramedThroughput(bandwidth int) int {
	//	using a hacky ass formula: to_bits(size)*0.95
	return ((bandwidth / 8) * 100) / 95
}

// Creates a fake delay that can be used to limit data transfer rate
func FramedIoWait(bandwidth int, size int, started time.Time) {
	elapsed := time.Since(started)
	time.Sleep(FramedIoDuration(bandwidth, size) - elapsed)
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
