package http

import (
	"io"
)

type BodyReader struct {
	Reader    io.Reader
	TotalRead int64
}

func (this *BodyReader) Read(p []byte) (n int, err error) {
	n, err = this.Reader.Read(p)
	this.TotalRead += int64(n)
	return
}

func (this *BodyReader) Close() error {
	if closer, ok := this.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
