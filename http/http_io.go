package http

import (
	"io"
	"sync/atomic"

	"github.com/maddsua/vx-proxy/utils"
)

type BodyReader struct {
	Reader  io.Reader
	Acct    *atomic.Int64
	MaxRate utils.SpeedLimiter
}

func (this *BodyReader) Read(p []byte) (n int, err error) {

	n, err = this.Reader.Read(p)

	if this.Acct != nil {
		this.Acct.Add(int64(n))
	}

	if this.MaxRate != nil {
		if limit, has := this.MaxRate.Limit(); has {
			//	todo: add a delay
		}
	}

	return
}

func (this *BodyReader) Close() error {
	if closer, ok := this.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
