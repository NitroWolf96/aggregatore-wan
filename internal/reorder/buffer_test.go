package reorder

import (
	"math/rand"
	"testing"
	"time"
)

type harness struct {
	b       *Buffer[uint32]
	ordered []uint32 // in-order releases
	late    []uint32 // out-of-order passthroughs
	dropped []uint32
	now     time.Time
}

func newHarness() *harness {
	h := &harness{now: time.Unix(0, 0)}
	h.b = New(
		func(v uint32, late bool) {
			if late {
				h.late = append(h.late, v)
			} else {
				h.ordered = append(h.ordered, v)
			}
		},
		func(v uint32) { h.dropped = append(h.dropped, v) },
		func() time.Time { return h.now },
	)
	return h
}

func (h *harness) push(seqs ...uint32) {
	for _, s := range seqs {
		h.b.Push(s, s)
	}
}

func TestInOrderDelivery(t *testing.T) {
	h := newHarness()
	h.push(10, 11, 12, 13)
	if len(h.ordered) != 4 || len(h.late) != 0 {
		t.Fatalf("ordered %v late %v", h.ordered, h.late)
	}
}

func TestReordering(t *testing.T) {
	h := newHarness()
	h.push(5, 8, 6, 7, 9)
	want := []uint32{5, 6, 7, 8, 9}
	if len(h.ordered) != len(want) {
		t.Fatalf("ordered %v want %v", h.ordered, want)
	}
	for i, v := range want {
		if h.ordered[i] != v {
			t.Fatalf("ordered %v want %v", h.ordered, want)
		}
	}
}

func TestDuplicatesAndStragglers(t *testing.T) {
	h := newHarness()
	h.push(1, 3, 3, 2, 2)
	// 1 delivered; 3 buffered; second 3 dropped as duplicate; 2 releases
	// 2,3; second 2 is behind the release point -> late passthrough.
	if got := h.b.Snapshot(); got.Duplicates != 1 || got.Late != 1 {
		t.Fatalf("stats %+v", got)
	}
	if len(h.ordered) != 3 || len(h.late) != 1 || h.late[0] != 2 {
		t.Fatalf("ordered %v late %v", h.ordered, h.late)
	}
	if len(h.dropped) != 1 || h.dropped[0] != 3 {
		t.Fatalf("dropped %v", h.dropped)
	}
}

func TestGapTimeout(t *testing.T) {
	h := newHarness()
	h.push(1, 3, 4) // 2 missing
	if len(h.ordered) != 1 {
		t.Fatalf("released early: %v", h.ordered)
	}
	h.now = h.now.Add(DefaultHold + time.Millisecond)
	h.b.Tick()
	if len(h.ordered) != 3 {
		t.Fatalf("after timeout: %v", h.ordered)
	}
	if got := h.b.Snapshot(); got.TimedOut != 1 {
		t.Fatalf("stats %+v", got)
	}
	// The straggler shows up afterwards and passes through late.
	h.push(2)
	if got := h.b.Snapshot(); got.Late != 1 {
		t.Fatalf("stats %+v", got)
	}
	if len(h.late) != 1 || h.late[0] != 2 {
		t.Fatalf("late %v", h.late)
	}
}

func TestWindowOverflowFlushes(t *testing.T) {
	h := newHarness()
	h.push(1, 3) // 2 missing, 3 waits
	h.push(1 + Size + 10)
	if got := h.b.Snapshot(); got.Overflows != 1 {
		t.Fatalf("stats %+v", got)
	}
	// 1 delivered normally; 3 flushed by the overflow; then the jump target.
	want := []uint32{1, 3, 1 + Size + 10}
	if len(h.ordered) != len(want) {
		t.Fatalf("ordered %v want %v", h.ordered, want)
	}
}

func TestPeerRestartResets(t *testing.T) {
	h := newHarness()
	h.push(1000000, 1000001)
	for i := uint32(0); i < resetThreshold; i++ {
		h.push(100 + i) // far behind: looks like a restarted sender
	}
	if got := h.b.Snapshot(); got.Resets != 1 {
		t.Fatalf("stats %+v", got)
	}
	// After the reset the new sequence range flows normally.
	before := len(h.ordered)
	h.push(100 + resetThreshold)
	if len(h.ordered) != before+1 {
		t.Fatalf("delivery after reset: %v", h.ordered)
	}
}

func TestWrapAround(t *testing.T) {
	h := newHarness()
	start := uint32(0xfffffff0)
	for i := uint32(0); i < 64; i++ {
		h.push(start + i)
	}
	if len(h.ordered) != 64 {
		t.Fatalf("delivered %d", len(h.ordered))
	}
	for i := 1; i < len(h.ordered); i++ {
		if h.ordered[i] != h.ordered[i-1]+1 {
			t.Fatalf("out of order at %d: %v", i, h.ordered[i-2:i+1])
		}
	}
}

// TestRandomPermutations is the property test: bounded-displacement
// permutations with duplicates must lose nothing, and the ordered stream
// must be strictly increasing.
func TestRandomPermutations(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 200; trial++ {
		h := newHarness()
		const n = 500
		base := rng.Uint32()
		seqs := make([]uint32, 0, n+50)
		for i := 0; i < n; i++ {
			seqs = append(seqs, base+uint32(i))
		}
		for i := range seqs {
			j := i + rng.Intn(64)
			if j >= len(seqs) {
				j = len(seqs) - 1
			}
			seqs[i], seqs[j] = seqs[j], seqs[i]
		}
		for i := 0; i < 50; i++ {
			seqs = append(seqs, base+uint32(rng.Intn(n)))
		}
		h.push(seqs...)
		h.now = h.now.Add(time.Second)
		h.b.Tick()

		// Nothing may be lost: every sequence appears in ordered or late.
		seen := make(map[uint32]bool, n)
		for _, v := range h.ordered {
			seen[v] = true
		}
		for _, v := range h.late {
			seen[v] = true
		}
		for i := uint32(0); i < n; i++ {
			if !seen[base+i] {
				t.Fatalf("trial %d: seq %d lost", trial, base+i)
			}
		}
		for i := 1; i < len(h.ordered); i++ {
			if int32(h.ordered[i]-h.ordered[i-1]) <= 0 {
				t.Fatalf("trial %d: ordered stream not increasing at %d", trial, i)
			}
		}
	}
}

func BenchmarkPushInOrder(b *testing.B) {
	buf := New(func(uint32, bool) {}, func(uint32) {}, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Push(uint32(i), uint32(i))
	}
}

func BenchmarkPushInterleaved(b *testing.B) {
	buf := New(func(uint32, bool) {}, func(uint32) {}, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Two-path interleave with displacement 8.
		var seq uint32
		if i%16 < 8 {
			seq = uint32(i + 8)
		} else {
			seq = uint32(i - 8)
		}
		buf.Push(seq, seq)
	}
}
