package http

import (
	"io"
	"net/http"
)

type BodyWriter struct {
	Writer     http.ResponseWriter
	TotalWrite int64
}

func (this *BodyWriter) Write(p []byte) (n int, err error) {

	if n, err = this.Writer.Write(p); n > 0 {

		if flusher, ok := this.Writer.(http.Flusher); ok {
			flusher.Flush()
		}

		this.TotalWrite += int64(n)
	}

	return
}

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
