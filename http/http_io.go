package http

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

type BodyReader struct {
	Reader  io.Reader
	Acct    *atomic.Int64
	MaxRate utils.Bandwidther
}

func (this *BodyReader) Read(buff []byte) (int, error) {

	var acct = func(delta int) {
		if this.Acct != nil {
			this.Acct.Add(int64(delta))
		}
	}

	if this.MaxRate != nil {

		if bandwidth, has := this.MaxRate.Bandwidth(); has {

			copyStarted := time.Now()

			chunkSize := min(utils.ChunkSizeFor(bandwidth), len(buff))
			chunk := make([]byte, chunkSize)

			size, err := this.Reader.Read(chunk)
			if err == nil {
				//	todo: this crap needs to be kicked the fuck out
				utils.ChunkSlowdown(context.Background(), chunkSize, bandwidth, copyStarted)
			}

			copyN(buff, chunk, size)

			acct(int(size))

			return int(size), err
		}
	}

	size, err := this.Reader.Read(buff)
	acct(size)

	return size, err
}

func (this *BodyReader) Close() error {
	if closer, ok := this.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func copyN(dst []byte, src []byte, n int) {
	for idx := range min(len(dst), len(src), n) {
		dst[idx] = src[idx]
	}
}
