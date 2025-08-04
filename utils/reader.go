package utils

import (
	"errors"
	"io"
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

type ReadAccounter struct {
	Reader    io.Reader
	TotalRead int64
}

func (this *ReadAccounter) Read(p []byte) (n int, err error) {
	n, err = this.Reader.Read(p)
	this.TotalRead += int64(n)
	return
}

func (this *ReadAccounter) Close() error {
	if closer, ok := this.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
