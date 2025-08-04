package utils

import (
	"io"
	"net/http"
)

type FlushWriter struct {
	Writer io.Writer
}

func (this *FlushWriter) Write(p []byte) (n int, err error) {

	if n, err = this.Writer.Write(p); err != nil {
		return
	}

	if flusher, ok := this.Writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return
}

type WriteAccounter struct {
	Writer     io.Writer
	TotalWrite int64
}

func (this *WriteAccounter) Write(p []byte) (n int, err error) {
	if n, err = this.Writer.Write(p); n > 0 {
		this.TotalWrite += int64(n)
	}
	return
}
