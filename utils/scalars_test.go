package utils_test

import (
	"testing"

	"github.com/maddsua/vx-proxy/utils"
)

func TestParseDataRate_1(t *testing.T) {
	const expect = 1000
	val, err := utils.ParseDataRate("1000")
	if err != nil {
		t.Fatal("err", err)
	} else if val != expect {
		t.Fatal("expected:", expect, "got:", val)
	}
}

func TestParseDataRate_2(t *testing.T) {
	const expect = 15_000
	val, err := utils.ParseDataRate("15K")
	if err != nil {
		t.Fatal("err", err)
	} else if val != expect {
		t.Fatal("expected:", expect, "got:", val)
	}
}

func TestParseDataRate_3(t *testing.T) {
	const expect = 25_000_000
	val, err := utils.ParseDataRate("25M")
	if err != nil {
		t.Fatal("err", err)
	} else if val != expect {
		t.Fatal("expected:", expect, "got:", val)
	}
}
