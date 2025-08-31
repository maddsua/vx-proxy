package http

import (
	"bytes"
	"io"
	"sync/atomic"

	"github.com/maddsua/vx-proxy/utils"
)

type BodyReader struct {
	Reader  io.Reader
	Acct    *atomic.Int64
	MaxRate utils.Bandwidther
}

func (this *BodyReader) Read(buff []byte) (int, error) {

	//	todo: test

	var acct = func(delta int) {
		if this.Acct != nil {
			this.Acct.Add(int64(delta))
		}
	}

	if this.MaxRate != nil {

		if chunker := this.MaxRate.Chunker(); chunker != nil {

			chunker.Start()

			size, err := io.CopyN(bytes.NewBuffer(buff), this.Reader, int64(chunker.Size()))

			if err != nil {
				chunker.Wait()
			}

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
