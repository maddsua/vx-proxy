package auth

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

type trafficCtl struct {
	nextId int
	pool   map[int]*connCtl
	mtx    sync.Mutex
	ticker *time.Ticker
	done   chan struct{}

	BandwidthRx int
	BandwidthTx int
}

func (this *trafficCtl) refreshRoutine() {

	//	todo: add cleanups

	this.done = make(chan struct{})
	this.ticker = time.NewTicker(time.Second)

	var doRefresh = func() {

		this.mtx.Lock()
		defer this.mtx.Unlock()

		var entriesRx, entriesTx []TrafficState

		for _, item := range this.pool {
			entriesRx = append(entriesRx, TrafficState{ID: item.id, Delta: item.deltaRx, Bandwidth: item.bandwidthRx})
			entriesTx = append(entriesTx, TrafficState{ID: item.id, Delta: item.deltaTx, Bandwidth: item.bandwidthTx})
		}

		RecalculateBandwidth(entriesRx, this.BandwidthRx)
		RecalculateBandwidth(entriesTx, this.BandwidthTx)

		for idx, itemRx := range entriesRx {
			itemTx := entriesTx[idx]
			this.pool[itemRx.ID].bandwidthRx = itemRx.Bandwidth
			this.pool[itemTx.ID].bandwidthTx = itemTx.Bandwidth
		}
	}

	for {
		select {
		case <-this.ticker.C:
			doRefresh()
		case <-this.done:
			this.ticker.Stop()
			this.done = nil
			return
		}
	}
}

func (this *trafficCtl) Close() {
	if this.done != nil {
		this.done <- struct{}{}
	}
}

func (this *trafficCtl) Connections() int {
	return len(this.pool)
}

func (this *trafficCtl) Next() *connCtl {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	var getID = func() int {

		this.mtx.Lock()
		defer this.mtx.Unlock()

		if this.nextId < math.MaxInt32 {
			if this.nextId > 0 {
				this.nextId++
			} else {
				this.nextId = 1
			}
			return this.nextId
		}

		for idx := range math.MaxInt64 {
			if _, has := this.pool[idx]; !has {
				return idx
			}
		}

		panic(errors.New("unable to generate id"))
	}

	var getBandwidth = func(totalBandwidth int) int {
		if len(this.pool) == 0 {
			return totalBandwidth
		}
		return totalBandwidth / len(this.pool)
	}

	next := &connCtl{
		id:          getID(),
		bandwidthRx: getBandwidth(this.BandwidthRx),
		bandwidthTx: getBandwidth(this.BandwidthTx),
	}

	this.pool[next.id] = next
	return next
}

type connCtl struct {
	id   int
	done bool

	deltaRx int64
	deltaTx int64

	bandwidthRx int
	bandwidthTx int
}

func (this *connCtl) Close() {
	this.done = true
}

func (this *connCtl) BandwidthRx() utils.Bandwidther {
	return connBandwidthCtl{val: &this.bandwidthRx}
}

func (this *connCtl) BandwidthTx() utils.Bandwidther {
	return connBandwidthCtl{val: &this.bandwidthTx}
}

func (this *connCtl) AccounterRx() utils.Accounter {
	return connAccounter{val: &this.deltaRx}
}

func (this *connCtl) AccounterTx() utils.Accounter {
	return connAccounter{val: &this.deltaTx}
}

type connBandwidthCtl struct {
	val *int
}

func (this connBandwidthCtl) Bandwidth() (int, bool) {
	val := *this.val
	return int(val), val > 0
}

type connAccounter struct {
	val *int64
}

func (this connAccounter) Account(delta int) {
	if delta > 0 {
		*this.val += int64(delta)
	}
}

type TrafficState struct {
	ID        int
	Delta     int64
	Bandwidth int
}

func (this TrafficState) String() string {
	return fmt.Sprintf("{ ID: %d, Bandwidth: %d, Delta: %d }", this.ID, this.Bandwidth, this.Delta)
}

func RecalculateBandwidth(entries []TrafficState, bandwidth int) {

	if len(entries) == 0 {
		return
	}

	if bandwidth <= 0 {
		for idx := range entries {
			entries[idx].Bandwidth = 0
		}
		return
	}

	var storedBandwidth int
	var saturated []*TrafficState

	for idx, item := range entries {

		maxTransfer := utils.FramedVolume(item.Bandwidth)

		if item.Delta < int64(maxTransfer) {

			unused := utils.FramedBandwidth(maxTransfer - int(item.Delta))
			newBandwidth := item.Bandwidth - unused

			//	this thing here prevents connections from getting zero bandwidth
			if newBandwidth > 0 {
				entries[idx].Bandwidth = newBandwidth
			} else {
				entries[idx].Bandwidth = bandwidth / len(entries)
			}

			storedBandwidth += unused

		} else {
			saturated = append(saturated, &entries[idx])
		}
	}

	//	todo: use a priority list to redistribute qouta

	if len(saturated) > 0 {
		boost := storedBandwidth / len(saturated)
		for _, item := range saturated {
			item.Bandwidth += boost
		}
	}
}
