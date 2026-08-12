package pathmon

import (
	"math"
	"sync"
	"time"
)

// RxStats tracks what one path has received: the counters echoed back in
// CTRL feedback, and the relative one-way-delay samples used locally to
// size the reorder hold.
type RxStats struct {
	mu       sync.Mutex
	started  bool
	highest  uint32
	pkts     uint32
	bytes    uint64
	haveOwd  bool
	owdEwma  float64 // µs, relative clocks (offset cancels across paths)
	owdVar   float64 // mean absolute deviation, µs
	owdMin   int32   // window min, reset at each report
	haveWin  bool
	lastData time.Time
}

// OnData records one received data packet. owdUS is rx_local - tx_remote in
// microseconds (any constant clock offset is fine: only differences across
// paths are ever used).
func (r *RxStats) OnData(pathSeq uint32, size int, owdUS int32, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || int32(pathSeq-r.highest) > 0 {
		r.highest = pathSeq
		r.started = true
	}
	r.pkts++
	r.bytes += uint64(size)
	r.lastData = now

	o := float64(owdUS)
	if !r.haveOwd {
		r.owdEwma = o
		r.owdVar = 0
		r.haveOwd = true
	} else {
		dev := math.Abs(o - r.owdEwma)
		r.owdVar = 0.75*r.owdVar + 0.25*dev
		r.owdEwma = 0.875*r.owdEwma + 0.125*o
	}
	if !r.haveWin || owdUS < r.owdMin {
		r.owdMin = owdUS
		r.haveWin = true
	}
}

// Report reads the counters for a CTRL record and resets the window min.
// ok is false when this path has never received data.
func (r *RxStats) Report() (highest, pkts uint32, bytes uint64, owdMinUS, owdAvgUS uint32, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return 0, 0, 0, 0, 0, false
	}
	min := r.owdMin
	r.haveWin = false
	return r.highest, r.pkts, r.bytes, uint32(min), uint32(int32(r.owdEwma)), true
}

// Peek reads the counters without consuming the report window.
func (r *RxStats) Peek() (pkts uint32, bytes uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pkts, r.bytes
}

// OwdView returns the delay estimate for hold sizing. ok is false without
// recent data (within staleness).
func (r *RxStats) OwdView(now time.Time, staleness time.Duration) (ewmaUS, jitterUS float64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.haveOwd || now.Sub(r.lastData) > staleness {
		return 0, 0, false
	}
	return r.owdEwma, r.owdVar, true
}

// ComputeHold sizes the reorder gap timeout from the spread of per-path
// one-way delays plus jitter margin: hold = (max-min) + 2*max jitter.
// Returns 0 when fewer than two paths have fresh data (keep the current
// hold).
func ComputeHold(views [][2]float64) time.Duration {
	if len(views) < 2 {
		return 0
	}
	minE, maxE, maxJ := math.MaxFloat64, -math.MaxFloat64, 0.0
	for _, v := range views {
		e, j := v[0], v[1]
		if e < minE {
			minE = e
		}
		if e > maxE {
			maxE = e
		}
		if j > maxJ {
			maxJ = j
		}
	}
	spreadUS := (maxE - minE) + 2*maxJ
	return time.Duration(spreadUS) * time.Microsecond
}
