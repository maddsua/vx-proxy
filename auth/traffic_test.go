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

func TestTraffic_InitDistribution(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    31_000,
			Bandwidth: 250_000,
		},
		{
			ID:        2,
			Volume:    1_000,
			Bandwidth: 250_000,
		},
		{
			ID:        3,
			Volume:    4_000,
			Bandwidth: 250_000,
		},
		{
			ID:        4,
			Volume:    31_000,
			Bandwidth: 250_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 479_904)
		case 2:
			expectBandwidth(t, item, 8192)
		case 3:
			expectBandwidth(t, item, 32000)
		case 4:
			expectBandwidth(t, item, 479_904)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_DynamicRedistribution(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    59_988,
			Bandwidth: 479_904,
		},
		{
			ID:        2,
			Volume:    1_024,
			Bandwidth: 8192,
		},
		{
			ID:        3,
			Volume:    4_000,
			Bandwidth: 32_000,
		},
		{
			ID:        4,
			Volume:    26_000,
			Bandwidth: 479_904,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 490_410)
		case 2:
			expectBandwidth(t, item, 142_002)
		case 3:
			expectBandwidth(t, item, 159_587)
		case 4:
			expectBandwidth(t, item, 208_000)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_Idle(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    12_000,
			Bandwidth: 500_916,
		},
		{
			ID:        2,
			Volume:    5_000,
			Bandwidth: 275_813,
		},
		{
			ID:        3,
			Volume:    26_000,
			Bandwidth: 287_174,
		},
		{
			ID:        4,
			Volume:    17_000,
			Bandwidth: 208_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 226_000)
		case 2:
			expectBandwidth(t, item, 170_000)
		case 3:
			expectBandwidth(t, item, 338_000)
		case 4:
			expectBandwidth(t, item, 266_000)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_ScaleDown(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    28_250,
			Bandwidth: 226_000,
		},
		{
			ID:        2,
			Volume:    21_250,
			Bandwidth: 170_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 485_292)
		case 2:
			expectBandwidth(t, item, 514_707)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_ScaleUp(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    12_000,
			Bandwidth: 485_292,
		},
		{
			ID:        2,
			Volume:    5_000,
			Bandwidth: 514_707,
		},
		{
			ID:        3,
			Volume:    0,
			Bandwidth: 250_000,
		},
		{
			ID:        4,
			Volume:    0,
			Bandwidth: 250_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 307_904)
		case 2:
			expectBandwidth(t, item, 251_904)
		case 3:
			expectBandwidth(t, item, 220_096)
		case 4:
			expectBandwidth(t, item, 220_096)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_BandwidthUp(t *testing.T) {

	const bandwidth = 10_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    38_488,
			Bandwidth: 307_904,
		},
		{
			ID:        2,
			Volume:    31_488,
			Bandwidth: 251_904,
		},
		{
			ID:        3,
			Volume:    27_512,
			Bandwidth: 220_096,
		},
		{
			ID:        4,
			Volume:    27_512,
			Bandwidth: 220_096,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 2_384_192)
		case 2:
			expectBandwidth(t, item, 2_496_192)
		case 3:
			expectBandwidth(t, item, 2_559_808)
		case 4:
			expectBandwidth(t, item, 2_559_808)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}

func TestTraffic_ScaleUpAndActiate(t *testing.T) {

	const bandwidth = 1_000_000

	entries := []auth.TrafficState{
		{
			ID:        1,
			Volume:    5_000,
			Bandwidth: 307_904,
		},
		{
			ID:        2,
			Volume:    5_000,
			Bandwidth: 251_904,
		},
		{
			ID:        3,
			Volume:    5_000,
			Bandwidth: 220_096,
		},
		{
			ID:        4,
			Volume:    5_000,
			Bandwidth: 220_096,
		},
		{
			ID:        5,
			Volume:    25_000,
			Bandwidth: 200_000,
		},
	}

	auth.RecalculateBandwidth(entries, bandwidth)

	for _, item := range entries {
		switch item.ID {
		case 1:
			expectBandwidth(t, item, 40_000)
		case 2:
			expectBandwidth(t, item, 40_000)
		case 3:
			expectBandwidth(t, item, 40_000)
		case 4:
			expectBandwidth(t, item, 40_000)
		case 5:
			expectBandwidth(t, item, 840_000)
		default:
			t.Fatal("unexpected entry id:", item.ID)
		}
	}
}
