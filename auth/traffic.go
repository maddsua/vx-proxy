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

	this.done = make(chan struct{})
	this.ticker = time.NewTicker(time.Second)

	var doRefresh = func() {

		this.mtx.Lock()
		defer this.mtx.Unlock()

		var entriesRx, entriesTx []TrafficState

		for key, item := range this.pool {

			if item.done {
				delete(this.pool, key)
				continue
			}

			entriesRx = append(entriesRx, TrafficState{ID: item.id, Volume: item.deltaRx, Bandwidth: item.bandwidthRx})
			entriesTx = append(entriesTx, TrafficState{ID: item.id, Volume: item.deltaTx, Bandwidth: item.bandwidthTx})
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
	Volume    int64
	Bandwidth int
}

func (this TrafficState) String() string {
	return fmt.Sprintf("{ ID: %d, Bandwidth: %d, Delta: %d }", this.ID, this.Bandwidth, this.Volume)
}

func RecalculateBandwidth(entries []TrafficState, bandwidth int) {

	var minConnBandwidth = utils.FramedBandwidth(1024)

	//	exit early if there's no entries
	if len(entries) == 0 {
		return
	}

	//	another early exit for the cases when bandwidth is set as unlimited
	if bandwidth <= 0 {
		for idx := range entries {
			entries[idx].Bandwidth = 0
		}
		return
	}

	var saturated []*TrafficState
	var storedBandwidth int
	var saturatedVolume int64

	for idx, item := range entries {

		maxTransfer := utils.FramedVolume(item.Bandwidth)

		if item.Volume < int64(maxTransfer) {

			unused := utils.FramedBandwidth(maxTransfer - int(item.Volume))
			newBandwidth := item.Bandwidth - unused

			//	this thing here prevents connections from getting zero bandwidth
			entries[idx].Bandwidth = max(newBandwidth, minConnBandwidth)
			storedBandwidth += unused

		} else {
			saturated = append(saturated, &entries[idx])
			saturatedVolume += item.Volume
		}
	}

	if len(saturated) > 1 {
		for _, item := range saturated {
			quota := 1 - float64(item.Volume)/float64(saturatedVolume)
			item.Bandwidth += int(quota * float64(storedBandwidth))
		}
	} else if len(saturated) == 1 {
		saturated[0].Bandwidth += storedBandwidth
	}
}
