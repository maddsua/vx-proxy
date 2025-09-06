package auth

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

func NewTrafficCtl() *TrafficCtl {

	this := &TrafficCtl{
		pool:   map[int]*connCtl{},
		done:   make(chan struct{}),
		ticker: time.NewTicker(time.Second),
	}

	go this.refreshRoutine()

	return this
}

type TrafficCtl struct {
	nextId int
	pool   map[int]*connCtl
	mtx    sync.Mutex
	ticker *time.Ticker
	done   chan struct{}

	BandwidthRx int
	BandwidthTx int
}

func (this *TrafficCtl) refreshRoutine() {

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

func (this *TrafficCtl) Close() {
	if this.done != nil {
		this.done <- struct{}{}
	}
}

func (this *TrafficCtl) Connections() int {
	return len(this.pool)
}

func (this *TrafficCtl) Next() *connCtl {

	if this.pool == nil {
		panic("not initialized")
	}

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

	deltaRx int
	deltaTx int

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
	val *int
}

func (this connAccounter) Account(delta int) {
	if delta > 0 {
		*this.val += delta
	}
}

type TrafficState struct {
	ID        int
	Volume    int
	Bandwidth int
}

func (this TrafficState) String() string {
	return fmt.Sprintf("{ ID: %d, Bandwidth: %d, Delta: %d }", this.ID, this.Bandwidth, this.Volume)
}

func RecalculateBandwidth(entries []TrafficState, bandwidth int) {

	const minConnTransfer = 1024
	var minConnBandwidth = utils.FramedBandwidth(minConnTransfer)

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
	var svolume int64
	var used int

	connBaseBandwidth := bandwidth / len(entries)

	for idx := range entries {

		item := &entries[idx]

		equivBandwidth := utils.FramedBandwidth(item.Volume)
		threshold := equivBandwidth + minConnBandwidth

		//	this makes sure connections are able to trigger 'saturation' state and grow up
		if threshold >= connBaseBandwidth || threshold >= item.Bandwidth {
			saturated = append(saturated, item)
			svolume += int64(item.Volume)
		} else {
			// this ensures no connection is scaled down to zero, to prevent lockups
			item.Bandwidth = max(minConnBandwidth, equivBandwidth)
		}

		used += item.Bandwidth
	}

	if avail := bandwidth - used; avail > 0 && len(saturated) > 0 {

		if len(saturated) == 1 {
			saturated[0].Bandwidth += avail
			return
		}

		for _, entry := range saturated {
			quota := (1 - float64(entry.Volume)/float64(svolume)) / float64(max(1, len(saturated)-1))
			extra := int(quota * float64(avail))
			entry.Bandwidth += extra
			used += extra
		}
	}

	if extra := (bandwidth - used) / len(entries); extra > 0 {
		for idx := range entries {
			entries[idx].Bandwidth += extra
		}
	}
}
