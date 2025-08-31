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
	Chunker() *IoChunker
}

// Chunker implements data transfer speed control
type IoChunker struct {
	Bandwidth int
	started   time.Time
	done      bool
}

func (this *IoChunker) Size() int {
	//	defaults to 128 KBIT/s just in case
	const defaultSize = 16 * 1024
	if this.Bandwidth > 0 {
		//	convert bandwidth to block size in bytes
		return this.Bandwidth / 8
	}
	return defaultSize
}

func (this *IoChunker) Start() {
	this.started = time.Now()
}

func (this *IoChunker) Wait() {

	if this.done {
		return
	}

	if delta := time.Second - time.Since(this.started); delta > 0 {
		time.Sleep(delta)
		this.done = true
	}
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

//	todo: test

// Direct connection piper function. Use with ConnectionPiper to get automatic controls such as cancellation and what not
func PipeIO(ctx context.Context, dst io.Writer, src io.Reader, limiter SpeedLimiter, acct *atomic.Int64) error {

	const defaultChunkSize = 32 * 1024

	for ctx.Err() == nil {

		var chunker *IoChunker
		chunkSize := defaultChunkSize

		if limiter != nil {
			chunker = limiter.Chunker()
			if chunker != nil {
				chunkSize = chunker.Size()
				chunker.Start()
			}
		}

		written, err := io.CopyN(dst, src, int64(chunkSize))
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

		if chunker != nil {
			chunker.Wait()
		}
	}

	return nil
}
