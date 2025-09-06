package auth_test

import (
	"testing"

	"github.com/maddsua/vx-proxy/auth"
)

var expectBandwidth = func(t *testing.T, entry auth.TrafficState, expect int) {
	if entry.Bandwidth != expect {
		t.Errorf("unexpected entry %d bandwidth: expected: %d, got: %d", entry.ID, expect, entry.Bandwidth)
	}
}

func TestTraffic_1(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    1_000_000,
			Bandwidth: 300_000,
		},
		{
			ID:        2,
			Volume:    1_000,
			Bandwidth: 300_000,
		},
		{
			ID:        3,
			Volume:    4_000,
			Bandwidth: 300_000,
		},
		{
			ID:        4,
			Volume:    4_000,
			Bandwidth: 32_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 302_230)
		case 2:
			expectBandwidth(t, item, 8192)
		case 3:
			expectBandwidth(t, item, 32000)
		case 4:
			expectBandwidth(t, item, 589_577)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_2(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    100,
			Bandwidth: 250_000,
		},
		{
			ID:        2,
			Volume:    10,
			Bandwidth: 250_000,
		},
		{
			ID:        3,
			Volume:    0,
			Bandwidth: 250_000,
		},
		{
			ID:        4,
			Volume:    36_000,
			Bandwidth: 250_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 8192)
		case 2:
			expectBandwidth(t, item, 8192)
		case 3:
			expectBandwidth(t, item, 8192)
		case 4:
			expectBandwidth(t, item, 975_424)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_3(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    100,
			Bandwidth: 250_000,
		},
		{
			ID:        2,
			Volume:    10,
			Bandwidth: 250_000,
		},
		{
			ID:        3,
			Volume:    0,
			Bandwidth: 250_000,
		},
		{
			ID:        4,
			Volume:    36_000,
			Bandwidth: 250_000,
		},
		{
			ID:        5,
			Volume:    36_000,
			Bandwidth: 250_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 8192)
		case 2:
			expectBandwidth(t, item, 8192)
		case 3:
			expectBandwidth(t, item, 8192)
		case 4:
			expectBandwidth(t, item, 488_000)
		case 5:
			expectBandwidth(t, item, 488_000)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}
