package pathmon

import (
	"testing"
	"time"
)

func ackN(l *Link, n int, rtt time.Duration) {
	for i := 0; i < n; i++ {
		seq, _ := l.OnProbeSent()
		l.OnProbeAck(seq, rtt)
	}
}

func TestUpAfterThreeAcks(t *testing.T) {
	l := NewLink()
	if l.Up() {
		t.Fatal("must start down")
	}
	ackN(l, probeAckUp-1, 20*time.Millisecond)
	if l.Up() {
		t.Fatal("up too early")
	}
	ackN(l, 1, 20*time.Millisecond)
	if !l.Up() {
		t.Fatal("must be up after 3 acks")
	}
}

func TestDownAfterThreeMisses(t *testing.T) {
	l := NewLink()
	ackN(l, probeAckUp, 20*time.Millisecond)
	var wentDown bool
	for i := 0; i < probeLossDown+1; i++ {
		_, wd := l.OnProbeSent()
		wentDown = wentDown || wd
	}
	if !wentDown || l.Up() {
		t.Fatalf("must go down after %d misses (up=%v)", probeLossDown, l.Up())
	}
	// A recovered path re-earns its share: the loss discount is small.
	if f := l.Snapshot().LossFactor; f > 0.5 {
		t.Fatalf("loss factor after down = %v, want small", f)
	}
	ackN(l, probeAckUp, 20*time.Millisecond)
	if !l.Up() {
		t.Fatal("must recover")
	}
}

func TestRFC6298(t *testing.T) {
	l := NewLink()
	seq, _ := l.OnProbeSent()
	l.OnProbeAck(seq, 100*time.Millisecond)
	s := l.Snapshot()
	if s.SRTT != 100*time.Millisecond || s.RTTVar != 50*time.Millisecond {
		t.Fatalf("first sample: srtt=%v rttvar=%v", s.SRTT, s.RTTVar)
	}
	seq, _ = l.OnProbeSent()
	l.OnProbeAck(seq, 200*time.Millisecond)
	s = l.Snapshot()
	// SRTT = 7/8*100 + 1/8*200 = 112.5ms; RTTVAR = 3/4*50 + 1/4*|100-200| = 62.5ms
	if s.SRTT != 112500*time.Microsecond {
		t.Fatalf("srtt=%v want 112.5ms", s.SRTT)
	}
	if s.RTTVar != 62500*time.Microsecond {
		t.Fatalf("rttvar=%v want 62.5ms", s.RTTVar)
	}
}

func TestCapacityAndLossDiscount(t *testing.T) {
	l := NewLink()
	ackN(l, probeAckUp, 20*time.Millisecond)

	now := time.Unix(0, 0)
	l.OnCtrl(0, 0, 0, now) // baseline
	// Clean 50ms intervals delivering 350 kB each: ~56 Mbit/s.
	for i := 1; i <= 5; i++ {
		now = now.Add(50 * time.Millisecond)
		l.OnCtrl(uint32(250*i), uint32(250*i), uint64(350000*i), now)
	}
	s := l.Snapshot()
	if s.CapacityBps < 50e6 || s.CapacityBps > 65e6 {
		t.Fatalf("capacity=%v want ~56M", s.CapacityBps)
	}
	if s.WeightBps < s.CapacityBps*0.9 {
		t.Fatalf("clean path discounted: weight=%v capacity=%v", s.WeightBps, s.CapacityBps)
	}

	// Lossy interval: 250 expected, 200 received -> weight cut.
	now = now.Add(50 * time.Millisecond)
	l.OnCtrl(250*6, 250*5+200, 350000*6, now)
	s2 := l.Snapshot()
	if s2.LossEWMA <= 0 {
		t.Fatalf("lossEWMA = %v", s2.LossEWMA)
	}
	if s2.WeightBps >= s.WeightBps {
		t.Fatalf("weight did not drop on loss: %v -> %v", s.WeightBps, s2.WeightBps)
	}

	// Clean intervals recover the discount.
	for i := 7; i < 30; i++ {
		now = now.Add(50 * time.Millisecond)
		l.OnCtrl(uint32(250*i), uint32(250*(i-1)+200), uint64(350000*i), now)
	}
	if f := l.Snapshot().LossFactor; f < 0.5 {
		t.Fatalf("loss factor did not recover: %v", f)
	}
}

func TestComputeHold(t *testing.T) {
	if h := ComputeHold(nil); h != 0 {
		t.Fatalf("empty: %v", h)
	}
	// Path A owd 5000us jitter 200us, path B owd 45000us jitter 3000us:
	// spread 40ms + 2*3ms = 46ms.
	h := ComputeHold([][2]float64{{5000, 200}, {45000, 3000}})
	if h != 46*time.Millisecond {
		t.Fatalf("hold=%v want 46ms", h)
	}
}
