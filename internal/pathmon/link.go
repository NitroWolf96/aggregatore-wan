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

// Delay discount (LEDBAT-style): when a path's standing queue — its
// average one-way delay above the rolling baseline minimum — exceeds the
// target, its weight is cut so the queue drains. Keeping queues short
// keeps the inter-path delay spread inside the reorder hold budget and
// avoids self-induced loss.
const (
	targetQueueUS  = 30_000 // 30ms standing queue target
	delayCut       = 0.85
	delayRecover   = 0.05
	minDelayFactor = 0.1
	baselineWindow = 30 * time.Second
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
	DelayFactor float64
	QueueMs     float64 // standing queue estimate at the far receiver
	WeightBps   float64 // capacity discounted by loss and queueing; 0 = unknown
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
	delayFactor  float64
	queueUS      float64
	capSamples   []capSample
	lastHighest  uint32
	haveCtrl     bool
	lastRxPkts   uint32
	lastRxBytes  uint64
	lastCtrlTime time.Time

	// Rolling two-bucket minimum of the receiver-reported one-way delay:
	// the propagation baseline against which queueing is measured.
	owdBase     [2]int32
	owdBaseSet  [2]bool
	owdBucketAt time.Time

	consecAcked  int
	lastProbeSeq uint32
	outstanding  []probeSent // probes sent and not yet acked, oldest first
}

type probeSent struct {
	seq uint32
	at  time.Time
}

// NewLink starts in the DOWN state; the first probe acks bring it up.
func NewLink() *Link {
	return &Link{lossFactor: 1, delayFactor: 1}
}

// probeRTO is how long an unanswered probe may age before it means the
// path is dead. RTT-adaptive so queueing delay (bufferbloat under load)
// never masquerades as loss, floored well above the probe cadence.
func (l *Link) probeRTOLocked() time.Duration {
	rto := l.srtt + 4*l.rttvar
	if min := 3 * ProbeInterval; rto < min {
		rto = min
	}
	if rto > 2*time.Second {
		rto = 2 * time.Second
	}
	return rto
}

// OnProbeSent records that a probe left. The path goes down when the
// oldest unanswered probe exceeds the RTO — not merely when acks lag the
// send cadence. It returns the probe sequence to embed and whether the
// path just went down.
func (l *Link) OnProbeSent(now time.Time) (seq uint32, wentDown bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.outstanding) > 0 && l.up && now.Sub(l.outstanding[0].at) > l.probeRTOLocked() {
		l.goDownLocked()
		l.outstanding = l.outstanding[:0]
		wentDown = true
	}
	l.lastProbeSeq++
	l.outstanding = append(l.outstanding, probeSent{seq: l.lastProbeSeq, at: now})
	if len(l.outstanding) > 32 {
		l.outstanding = l.outstanding[len(l.outstanding)-32:]
	}
	return l.lastProbeSeq, wentDown
}

// OnProbeAck ingests a probe ack: an RTT sample (RFC 6298) and a liveness
// signal. Acks may arrive after newer probes were sent (RTT above the
// cadence); any recent sequence counts. It returns true when the path
// just transitioned to UP.
func (l *Link) OnProbeAck(seq uint32, rtt time.Duration) (cameUp bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	known := false
	for i, o := range l.outstanding {
		if o.seq == seq {
			l.outstanding = append(l.outstanding[:0], l.outstanding[i+1:]...)
			known = true
			break
		}
	}
	if !known {
		return false // duplicate or ancient ack
	}
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
	l.outstanding = l.outstanding[:0]
	// A returning path re-earns its share instead of instantly absorbing
	// its old ratio.
	l.lossFactor = minLossFactor * 4
}

// OnCtrl ingests the receiver's PathStats for this path: loss over the
// report interval, delivery-rate capacity samples, and the loss and
// queueing-delay discounts. owdMinUS/owdAvgUS are the receiver's relative
// one-way-delay stats for the window (clock offset cancels against the
// rolling baseline).
func (l *Link) OnCtrl(highest, rxPkts uint32, rxBytes uint64, owdMinUS, owdAvgUS int32, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.updateDelayLocked(owdMinUS, owdAvgUS, now)

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

// updateDelayLocked maintains the propagation baseline (two-bucket rolling
// minimum of the reported window-min OWD) and the queueing-delay discount.
func (l *Link) updateDelayLocked(owdMinUS, owdAvgUS int32, now time.Time) {
	if l.owdBucketAt.IsZero() {
		l.owdBucketAt = now
	}
	if now.Sub(l.owdBucketAt) > baselineWindow/2 {
		l.owdBase[0], l.owdBaseSet[0] = l.owdBase[1], l.owdBaseSet[1]
		l.owdBaseSet[1] = false
		l.owdBucketAt = now
	}
	if !l.owdBaseSet[1] || owdMinUS-l.owdBase[1] < 0 {
		l.owdBase[1], l.owdBaseSet[1] = owdMinUS, true
	}
	base := l.owdBase[1]
	if l.owdBaseSet[0] && l.owdBase[0]-base < 0 {
		base = l.owdBase[0]
	}

	q := float64(owdAvgUS - base)
	if q < 0 {
		q = 0
	}
	l.queueUS = q
	if q > 2*targetQueueUS {
		// Proportional cut: the deeper the standing queue, the harder the
		// weight drops (floor 0.5x per report), so overshoot drains fast.
		cut := 2 * targetQueueUS / q
		if cut < 0.5 {
			cut = 0.5
		}
		if cut > delayCut {
			cut = delayCut
		}
		l.delayFactor *= cut
		if l.delayFactor < minDelayFactor {
			l.delayFactor = minDelayFactor
		}
	} else if q < targetQueueUS {
		l.delayFactor += delayRecover * (1 - l.delayFactor)
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
		DelayFactor: l.delayFactor,
		QueueMs:     l.queueUS / 1000,
		WeightBps:   capBps * l.lossFactor * l.delayFactor,
	}
}

// Weight returns the scheduling weight (0 = capacity unknown).
func (l *Link) Weight() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.capacityBpsLocked() * l.lossFactor * l.delayFactor
}

// Up reports the path state.
func (l *Link) Up() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.up
}
