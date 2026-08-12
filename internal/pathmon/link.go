// Package pathmon estimates the quality of each WAN path (RTT, loss,
// capacity, one-way-delay spread) and its liveness. One Link exists per
// path per sending direction; its weight drives the scheduler.
package pathmon

import (
	"sync"
	"time"
)

// Probe/state thresholds from the design: 3 lost probes take a path DOWN,
// 3 consecutive acks bring it back UP.
const (
	ProbeInterval     = 100 * time.Millisecond
	ProbeIntervalDown = 500 * time.Millisecond
	probeLossDown     = 3
	probeAckUp        = 3
)

// capacityWindow is the sliding max window of delivery-rate samples.
const capacityWindow = 10 * time.Second

// Loss discount dynamics: a lossy feedback interval multiplies the weight
// by lossCut; clean intervals recover it toward 1.
const (
	lossCut       = 0.7
	lossRecover   = 0.05
	minLossFactor = 0.05
)

type capSample struct {
	t   time.Time
	bps float64
}

// Snapshot is a read-only view of a Link for scheduling and dashboards.
type Snapshot struct {
	Up          bool
	SRTT        time.Duration
	RTTVar      time.Duration
	LossEWMA    float64
	CapacityBps float64
	LossFactor  float64
	WeightBps   float64 // capacity discounted by loss; 0 = unknown
}

// Link tracks one path of one sending direction.
type Link struct {
	mu sync.Mutex

	up           bool
	srtt         time.Duration
	rttvar       time.Duration
	hasRTT       bool
	lossEWMA     float64
	lossFactor   float64
	capSamples   []capSample
	lastHighest  uint32
	haveCtrl     bool
	lastRxPkts   uint32
	lastRxBytes  uint64
	lastCtrlTime time.Time

	consecMissed     int
	consecAcked      int
	lastProbeSeq     uint32
	probeOutstanding bool
}

// NewLink starts in the DOWN state; the first probe acks bring it up.
func NewLink() *Link {
	return &Link{lossFactor: 1}
}

// OnProbeSent records that a probe left; if the previous one is still
// unanswered it counts as a miss, and enough misses take the path down.
// It returns the probe sequence to embed and whether the path just went
// down.
func (l *Link) OnProbeSent() (seq uint32, wentDown bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.probeOutstanding {
		l.consecMissed++
		l.consecAcked = 0
		if l.up && l.consecMissed >= probeLossDown {
			l.goDownLocked()
			wentDown = true
		}
	}
	l.lastProbeSeq++
	l.probeOutstanding = true
	return l.lastProbeSeq, wentDown
}

// OnProbeAck ingests a probe ack: an RTT sample (RFC 6298) and a liveness
// signal. It returns true when the path just transitioned to UP.
func (l *Link) OnProbeAck(seq uint32, rtt time.Duration) (cameUp bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq != l.lastProbeSeq {
		return false // stale ack; the newest probe is still outstanding
	}
	l.probeOutstanding = false
	l.consecMissed = 0
	l.consecAcked++

	if rtt > 0 {
		if !l.hasRTT {
			l.srtt = rtt
			l.rttvar = rtt / 2
			l.hasRTT = true
		} else {
			// RFC 6298: RTTVAR = 3/4*RTTVAR + 1/4*|SRTT-RTT|; SRTT = 7/8*SRTT + 1/8*RTT.
			dev := l.srtt - rtt
			if dev < 0 {
				dev = -dev
			}
			l.rttvar = (3*l.rttvar + dev) / 4
			l.srtt = (7*l.srtt + rtt) / 8
		}
	}

	if !l.up && l.consecAcked >= probeAckUp {
		l.up = true
		return true
	}
	return false
}

// MarkDown forces the path down (socket write error, address removed).
func (l *Link) MarkDown() {
	l.mu.Lock()
	l.goDownLocked()
	l.mu.Unlock()
}

func (l *Link) goDownLocked() {
	l.up = false
	l.consecAcked = 0
	// A returning path re-earns its share instead of instantly absorbing
	// its old ratio.
	l.lossFactor = minLossFactor * 4
}

// OnCtrl ingests the receiver's PathStats for this path: loss over the
// report interval, delivery-rate capacity samples, and the loss discount.
func (l *Link) OnCtrl(highest, rxPkts uint32, rxBytes uint64, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.haveCtrl {
		l.haveCtrl = true
		l.lastHighest = highest
		l.lastRxPkts = rxPkts
		l.lastRxBytes = rxBytes
		l.lastCtrlTime = now
		return
	}

	expected := int32(highest - l.lastHighest)
	received := int32(rxPkts - l.lastRxPkts)
	deltaBytes := rxBytes - l.lastRxBytes
	dt := now.Sub(l.lastCtrlTime)
	l.lastHighest = highest
	l.lastRxPkts = rxPkts
	l.lastRxBytes = rxBytes
	l.lastCtrlTime = now

	if dt <= 0 {
		return
	}

	if expected > 0 {
		loss := 1 - float64(received)/float64(expected)
		if loss < 0 {
			loss = 0
		}
		if loss > 1 {
			loss = 1
		}
		l.lossEWMA = 0.9*l.lossEWMA + 0.1*loss
		// An isolated packet in a large burst is noise, not congestion.
		if loss > 0.01 {
			l.lossFactor *= lossCut
			if l.lossFactor < minLossFactor {
				l.lossFactor = minLossFactor
			}
		} else {
			l.lossFactor += lossRecover * (1 - l.lossFactor)
		}
	} else if received == 0 {
		// Idle interval: decay loss memory slowly, recover the discount.
		l.lossEWMA *= 0.95
		l.lossFactor += lossRecover * (1 - l.lossFactor)
	}

	if deltaBytes > 0 && dt >= 10*time.Millisecond {
		bps := float64(deltaBytes) * 8 / dt.Seconds()
		l.capSamples = append(l.capSamples, capSample{t: now, bps: bps})
		cutoff := now.Add(-capacityWindow)
		for len(l.capSamples) > 0 && l.capSamples[0].t.Before(cutoff) {
			l.capSamples = l.capSamples[1:]
		}
	}
}

func (l *Link) capacityBpsLocked() float64 {
	max := 0.0
	for _, s := range l.capSamples {
		if s.bps > max {
			max = s.bps
		}
	}
	return max
}

// Snapshot returns the current state for scheduling decisions.
func (l *Link) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	capBps := l.capacityBpsLocked()
	return Snapshot{
		Up:          l.up,
		SRTT:        l.srtt,
		RTTVar:      l.rttvar,
		LossEWMA:    l.lossEWMA,
		CapacityBps: capBps,
		LossFactor:  l.lossFactor,
		WeightBps:   capBps * l.lossFactor,
	}
}

// Weight returns the scheduling weight (0 = capacity unknown).
func (l *Link) Weight() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.capacityBpsLocked() * l.lossFactor
}

// Up reports the path state.
func (l *Link) Up() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.up
}
