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
// cancelDuplex - callback function to cancel the other context (when we get EOF and want to stop transferring data);
// dst - destination connection;
// src - source connection;
// acct - traffic accounting callback
func PipeConnection(ctx context.Context, cancelDuplex context.CancelFunc, dst net.Conn, src net.Conn, speedCap int, transferAcct *atomic.Int64) {

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
	defer cancelDuplex()

	//	branch for non-speed-limited connections
	if speedCap <= 0 {

		for ctx.Err() == nil {

			bytesSent, err := io.Copy(dst, src)
			if bytesSent == 0 {
				break
			}

			transferAcct.Add(bytesSent)

			if ctx.Err() != nil {
				break
			}

			if err != nil {
				reportBrokenPipe(err)
				break
			}
		}

		return
	}

	const buffSize = 32 * 1024

	var copyStarted time.Time
	idealDelay := (time.Second * buffSize) / time.Duration(speedCap)

	for ctx.Err() == nil {

		copyStarted = time.Now()

		bytesSent, err := io.CopyN(dst, src, buffSize)
		if bytesSent == 0 {
			break
		}

		transferAcct.Add(bytesSent)

		if ctx.Err() != nil || err == io.EOF {
			break
		}

		if err != nil {
			reportBrokenPipe(err)
			break
		}

		time.Sleep(idealDelay - time.Since(copyStarted))
	}
}
