package auth_test

import (
	"testing"

	"github.com/maddsua/vx-proxy/auth"
)

func TestTraffic_1(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Delta:     1_000_000,
			Bandwidth: 300_000,
		},
		{
			ID:        2,
			Delta:     1_000,
			Bandwidth: 300_000,
		},
		{
			ID:        3,
			Delta:     4_000,
			Bandwidth: 300_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	var expectBandwidth = func(entry auth.TrafficState, expect int) {
		if entry.Bandwidth != expect {
			t.Fatal("unexpected entry bandwidth: expected:", expect, "got:", entry.Bandwidth)
		}
	}

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(item, 860_000)
		case 2:
			expectBandwidth(item, 8000)
		case 3:
			expectBandwidth(item, 32000)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}
