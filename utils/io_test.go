package utils_test

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

func testReader(n int) io.Reader {

	buff := make([]byte, n)
	for idx := range n {
		buff[idx] = byte(rand.Intn(math.MaxUint8))
	}

	return bytes.NewReader(buff)
}

type testTctl struct {
	Val int
}

func (this testTctl) Bandwidth() (int, bool) {
	return this.Val, true
}

type nopWriter struct{}

func (this nopWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func elapsedExpect(expect time.Duration, countdown time.Time, deviation int) error {

	elapsed := time.Since(countdown)

	delta := expect - elapsed
	if delta < 0 {
		delta *= -1
	}

	if int64(delta) > ((int64(expect) * int64(deviation)) / 100) {
		return fmt.Errorf("time deviation >%d%% (%v)", deviation, elapsed)
	}

	return nil
}

func TestPipeRate_1(t *testing.T) {

	//	copy 25 MB of data at 100 mbit/s

	data := testReader(25 * 1024 * 1024)
	tctl := testTctl{Val: 100_000_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, tctl, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(2*time.Second, started, 10); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_2(t *testing.T) {

	//	copy 2 MB of data at 25 mbit/s

	data := testReader(2 * 1024 * 1024)
	tctl := testTctl{Val: 25_000_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, tctl, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(650*time.Millisecond, started, 10); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_3(t *testing.T) {

	//	copy 100 KB of data at 5 mbit/s

	data := testReader(100 * 1024)
	tctl := testTctl{Val: 5_000_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, tctl, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(150*time.Millisecond, started, 10); err != nil {
		t.Fatal(err)
	}
}

func TestPipeRate_4(t *testing.T) {

	//	copy 100 MB of data at 500 mbit/s

	data := testReader(100 * 1024 * 1024)
	tctl := testTctl{Val: 500_000_000}

	wrt := nopWriter{}

	started := time.Now()

	err := utils.PipeIO(context.Background(), wrt, data, tctl, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := elapsedExpect(1600*time.Millisecond, started, 10); err != nil {
		t.Fatal(err)
	}
}
