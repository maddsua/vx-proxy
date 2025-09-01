package http_test

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/maddsua/vx-proxy/http"
	"github.com/maddsua/vx-proxy/utils"
)

func testBuff(n int) []byte {

	buff := make([]byte, n)
	for idx := range n {
		buff[idx] = byte(rand.Intn(math.MaxUint8))
	}

	return buff
}

func cmpBuffN(a, b []byte, n int) error {

	if len(a) < n || len(b) < n {
		return fmt.Errorf("the n value is too big")
	}

	for idx := range n {
		if a[idx] != b[idx] {
			return fmt.Errorf("value mismatch at position %d (%x|%x)", idx, a[idx], b[idx])
		}
	}

	return nil
}

func cmpBuff(a, b []byte) error {

	if len(a) != len(b) {
		return fmt.Errorf("buffer lengths are different")
	}

	for idx, val := range a {
		if val != b[idx] {
			return fmt.Errorf("value mismatch at position %d (%x|%x)", idx, a[idx], b[idx])
		}
	}

	return nil
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

type testTctl struct {
	Val int
}

func (this testTctl) Bandwidth() (int, bool) {
	return this.Val, true
}

func TestRead_1(t *testing.T) {

	const expectSize = 64 * 1024

	data := testBuff(25 * 1024 * 1024)

	reader := http.BodyReader{
		Reader:  bytes.NewReader(data),
		MaxRate: testTctl{Val: 100_000_000},
	}

	chunk := make([]byte, 64*1024)

	n, err := reader.Read(chunk)
	if err != nil {
		t.Fatal("err", err)
	} else if n != expectSize {
		t.Fatal("expected", expectSize, "got:", n)
	}

	if err := cmpBuffN(data, chunk, n); err != nil {
		t.Fatal("err", err)
	}
}

func TestRead_2(t *testing.T) {

	const expectSize = 64 * 1024

	data := testBuff(5 * 1024 * 1024)

	reader := http.BodyReader{
		Reader:  bytes.NewReader(data),
		MaxRate: testTctl{Val: 25_000_000},
	}

	chunk := make([]byte, 64*1024)

	n, err := reader.Read(chunk)
	if err != nil {
		t.Fatal("err", err)
	} else if n != expectSize {
		t.Fatal("expected", expectSize, "got:", n)
	}

	if err := cmpBuffN(data, chunk, n); err != nil {
		t.Fatal("err", err)
	}
}

func TestRead_3(t *testing.T) {

	data := testBuff(3 * 1024 * 1024)

	reader := http.BodyReader{
		Reader:  bytes.NewReader(data),
		MaxRate: testTctl{Val: 75_000_000},
	}

	var joined []byte

	for {

		chunk := make([]byte, 50_000)
		n, err := reader.Read(chunk)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal("err", err)
		}

		joined = append(joined, chunk[:n]...)
	}

	if err := cmpBuff(data, joined); err != nil {
		t.Fatal("err", err)
	}
}

func TestRead_4(t *testing.T) {

	data := testBuff(10 * 1024 * 1024)

	const bandwidth = 100_000_000

	reader := http.BodyReader{
		Reader:  bytes.NewReader(data),
		MaxRate: testTctl{Val: bandwidth},
	}

	started := time.Now()

	for {

		chunk := make([]byte, utils.ChunkSizeFor(bandwidth))
		_, err := reader.Read(chunk)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal("err", err)
		}
	}

	if err := elapsedExpect(850*time.Millisecond, started, 10); err != nil {
		t.Fatal("err", err)
	}
}
