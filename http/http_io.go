package http

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

type BodyReader struct {
	Reader  io.Reader
	Acct    *atomic.Int64
	MaxRate utils.SpeedLimiter
}

func (this *BodyReader) Read(buff []byte) (int, error) {

	size, err := this.Reader.Read(buff)

	if this.Acct != nil {
		this.Acct.Add(int64(size))
	}

	if this.MaxRate != nil {
		if limit, has := this.MaxRate.Limit(); has {
			//	this isn't optimal and will ondershoot the speed
			//	but it's the best shot with the current http implementation
			expected := time.Duration((int64(time.Second) * int64(size)) / int64(limit))
			time.Sleep(expected)
		}
	}

	return size, err
}

func (this *BodyReader) Close() error {
	if closer, ok := this.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
