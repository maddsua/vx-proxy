package vxproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

func testData(n int) io.Reader {

	buff := make([]byte, n)
	for idx := range n {
		buff[idx] = byte(rand.Intn(math.MaxUint8))
	}

	return bytes.NewReader(buff)
}

type testLimiter struct {
	Val int
}

func (this testLimiter) Limit() (int, bool) {
	return this.Val, this.Val > 0
}

type nopWriter struct{}

func (this nopWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func elapsedExpect(expect time.Duration, countdown time.Time) error {

	elapsed := time.Since(countdown)

	delta := expect - elapsed
	if delta < 0 {
		delta *= -1
	}

	if float64(delta) > float64(expect)*0.05 {
		return fmt.Errorf("time deviation >10%% (%v)", elapsed)
	}

	return nil
}

func TestPipeRate_1(t *testing.T) {

	data := testData(1_000_000)
	limiter := testLimiter{Val: 500_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, limiter, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(time.Second*2, started); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_2(t *testing.T) {

	data := testData(1_000_000)
	limiter := testLimiter{Val: 333_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, limiter, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(time.Second*3, started); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_3(t *testing.T) {

	data := testData(1_000_000)
	limiter := testLimiter{Val: 250_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, limiter, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(time.Second*4, started); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_4(t *testing.T) {

	data := testData(100_000_000)
	limiter := testLimiter{Val: 50_000_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, limiter, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(time.Second*2, started); err != nil {
		t.Fatal(err)
	}
}
