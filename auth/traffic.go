package auth

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maddsua/vx-proxy/utils"
)

var errTooManyConnections = errors.New("too many connections")

func NewTrafficCtl() *TrafficCtl {

	this := &TrafficCtl{
		pool:   map[int]*ConnCtl{},
		doneCh: make(chan struct{}),
		ticker: time.NewTicker(time.Second),
	}

	go this.refreshRoutine()

	return this
}

type TrafficCtl struct {
	nextId int
	pool   map[int]*ConnCtl
	mtx    sync.Mutex
	ticker *time.Ticker
	doneCh chan struct{}
	done   atomic.Bool

	ConnectionLimit int

	ActualRateRx int
	ActualRateTx int

	MaximumRateRx int
	MaximumRateTx int

	MinimumRateRx int
	MinimumRateTx int

	AccountingRx atomic.Int64
	AccountingTx atomic.Int64
}

func (this *TrafficCtl) refreshRoutine() {

	var doRefresh = func() {

		this.mtx.Lock()
		defer this.mtx.Unlock()

		var entriesRx, entriesTx []TrafficState

		for key, entry := range this.pool {

			//	load transferred data volume
			deltaRx := entry.deltaRx.Swap(0)
			deltaTx := entry.deltaTx.Swap(0)

			this.AccountingRx.Add(deltaRx)
			this.AccountingTx.Add(deltaTx)

			//	remove connections that have been closed
			if entry.done {
				delete(this.pool, key)
				continue
			}

			entriesRx = append(entriesRx, TrafficState{ID: entry.id, Volume: int(deltaRx), Bandwidth: entry.rateRx})
			entriesTx = append(entriesTx, TrafficState{ID: entry.id, Volume: int(deltaTx), Bandwidth: entry.rateTx})
		}

		RecalculateBandwidthLax(entriesRx, this.ActualRateRx)
		RecalculateBandwidthLax(entriesTx, this.ActualRateTx)

		for idx, itemRx := range entriesRx {

			itemTx := entriesTx[idx]

			//	this should never fire
			if itemRx.ID != itemTx.ID {
				panic(errors.New("logic error: RX and TX id mismatch"))
			}

			entry := this.pool[itemRx.ID]

			//	apply recalculated bandwidth
			entry.rateRx = itemRx.Bandwidth
			entry.rateRx = itemTx.Bandwidth

			//	apply minimal bandwidth
			entry.minRateRx = this.MinimumRateRx
			entry.minRateTx = this.MinimumRateTx

			//	apply maximal bandwidth
			entry.maxRateRx = this.MaximumRateRx
			entry.maxRateTx = this.MaximumRateTx
		}
	}

	for {
		select {
		case <-this.ticker.C:
			doRefresh()
		case <-this.doneCh:
			return
		}
	}
}

func (this *TrafficCtl) Close() {

	if !this.done.CompareAndSwap(false, true) {
		return
	}

	this.ticker.Stop()

	if this.doneCh != nil {
		this.doneCh <- struct{}{}
		close(this.doneCh)
	}
}

func (this *TrafficCtl) Connections() int {
	return len(this.pool)
}

func (this *TrafficCtl) Next() (*ConnCtl, error) {

	if this.pool == nil || this.done.Load() {
		return nil, errors.New("controller closed")
	}

	this.mtx.Lock()
	defer this.mtx.Unlock()

	if this.ConnectionLimit > 0 && len(this.pool) >= this.ConnectionLimit {
		return nil, errTooManyConnections
	}

	var getID = func() int {

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

	next := &ConnCtl{
		id:        getID(),
		rateRx:    getBandwidth(this.ActualRateRx),
		rateTx:    getBandwidth(this.ActualRateTx),
		maxRateRx: this.MaximumRateRx,
		maxRateTx: this.MaximumRateTx,
		minRateRx: this.MinimumRateRx,
		minRateTx: this.MinimumRateTx,
	}

	this.pool[next.id] = next
	return next, nil
}

type ConnCtl struct {
	id   int
	done bool

	deltaRx atomic.Int64
	deltaTx atomic.Int64

	rateRx int
	rateTx int

	maxRateRx int
	maxRateTx int

	minRateRx int
	minRateTx int
}

func (this *ConnCtl) Close() {
	this.done = true
}

func (this *ConnCtl) BandwidthRx() utils.Bandwidther {
	return connBandwidthCtl{
		rate:    &this.rateRx,
		maxRate: &this.maxRateRx,
		minRate: &this.minRateRx,
	}
}

func (this *ConnCtl) BandwidthTx() utils.Bandwidther {
	return connBandwidthCtl{
		rate:    &this.rateTx,
		maxRate: &this.maxRateTx,
		minRate: &this.minRateTx,
	}
}

func (this *ConnCtl) AccounterRx() utils.Accounter {
	return connAccounter{val: &this.deltaRx}
}

func (this *ConnCtl) AccounterTx() utils.Accounter {
	return connAccounter{val: &this.deltaTx}
}

type connBandwidthCtl struct {
	rate    *int
	maxRate *int
	minRate *int
}

func (this connBandwidthCtl) Bandwidth() (int, bool) {

	//	Normal flow when base rate is recalculated and min/max limits can also be applied
	if val := *this.rate; val > 0 {

		//	apply minimal connection speed if set
		if minVal := *this.minRate; minVal > 0 && val < minVal {
			val = minVal
		}

		//	apply maximal connection speed if set
		if maxVal := *this.maxRate; maxVal > 0 && val > maxVal {
			val = maxVal
		}

		return val, true
	}

	//	This sets connection speed from the value of MaximumDataRate or equivalent
	if val := *this.maxRate; val > 0 {
		return val, true
	}

	return 0, false
}

type connAccounter struct {
	val *atomic.Int64
}

func (this connAccounter) Account(delta int) {
	if delta > 0 {
		this.val.Add(int64(delta))
	}
}

type TrafficState struct {
	ID        int
	Volume    int
	Bandwidth int
}

// Redistributes connection bandwidth without sticking to a strict limit
// (gives a better user experience but creates intermittent overprovision)
func RecalculateBandwidthLax(entries []TrafficState, bandwidth int) {

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

	var extra int
	var svolume int64

	baseline := bandwidth / len(entries)
	margin := baseline / 10

	for idx := range entries {

		item := &entries[idx]

		equivBandwidth := utils.FramedBandwidth(item.Volume)

		if (equivBandwidth + margin) > baseline {
			saturated = append(saturated, item)
			svolume += int64(item.Volume)
		} else {
			extra += max(0, baseline-equivBandwidth)
		}

		item.Bandwidth = baseline
	}

	if extra > 0 {

		var distribute = func(volume int) int {

			nconn := len(saturated)

			if nconn < 2 {
				return extra
			}

			delta := int(((1 - float64(volume)/float64(svolume)) / float64(nconn-1)) * float64(extra))
			if delta > 0 && delta < extra {
				return delta
			}

			return extra / nconn
		}

		for _, entry := range saturated {
			entry.Bandwidth += distribute(entry.Volume)
		}
	}
}
