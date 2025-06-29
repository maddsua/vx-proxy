package utils

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// arguments here:
// ctx - own ctx, signals this half of a pipe when to exit;
// cancelOther - callback function to cancel the other context (when we get EOF and want to stop transferring data);
// dst - destination connection;
// src - source connection;
// acct - traffic accounting callback
func PipeConnection(ctx context.Context, cancelOther context.CancelFunc, dst net.Conn, src net.Conn, speedCap int, transferAcct *atomic.Int64) {

	if ctx == nil {
		panic("context is nil")
	} else if dst == nil {
		panic("dst is nil")
	} else if src == nil {
		panic("src is nil")
	}

	var shutdownDuplex = func() {
		dst.SetReadDeadline(time.Unix(1, 0))
	}

	var reportBrokenPipe = func(err error) {
		slog.Debug("Proxy pipe broken",
			slog.String("err", err.Error()),
			slog.String("src", src.RemoteAddr().String()),
			slog.String("dst", dst.RemoteAddr().String()))
	}

	defer shutdownDuplex()

	if cancelOther != nil {
		defer cancelOther()
	}

	const buffSize = 32 * 1024

	var copyStarted time.Time
	var chunkDelay time.Duration

	if speedCap > 0 {
		chunkDelay = (time.Second * buffSize) / time.Duration(speedCap)
	}

	for ctx.Err() == nil {

		copyStarted = time.Now()

		bytesSent, err := io.CopyN(dst, src, buffSize)
		if bytesSent == 0 {
			break
		}

		if transferAcct != nil {
			transferAcct.Add(bytesSent)
		}

		if ctx.Err() != nil || err == io.EOF {
			break
		}

		if err != nil {
			reportBrokenPipe(err)
			break
		}

		if chunkDelay > 0 {
			time.Sleep(chunkDelay - time.Since(copyStarted))
		}
	}
}
