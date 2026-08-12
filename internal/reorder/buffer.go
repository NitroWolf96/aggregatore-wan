// Package reorder implements the receive-side resequencing buffer of the
// multipath tunnel. Packets striped across paths with different latencies
// arrive out of order; the buffer releases them in global-sequence order,
// waiting at most a hold time on gaps, and deduplicates redundant copies.
package reorder

import (
	"sync"
	"time"
)

// Size is the ring capacity in packets. At 1400 B per packet this is ~11 MB
// of in-flight window, enough for 1 Gbps with ~90 ms of inter-path delay
// spread.
const Size = 8192

// DefaultHold is the initial gap timeout, generous enough to cover a
// typical fiber-vs-LTE delay spread before the first measurement lands;
// the link estimator retunes it within 250ms of traffic flowing. Starting
// too low causes early out-of-order passthroughs that scare the inner
// TCP out of slow start.
const DefaultHold = 75 * time.Millisecond

// resetThreshold is how many consecutive far-out-of-window packets trigger
// a buffer reset (peer restarted and its sequence numbers started over).
const resetThreshold = 16

// Stats counts buffer outcomes; read them only through Snapshot.
type Stats struct {
	Delivered  uint64
	Duplicates uint64
	Late       uint64
	TimedOut   uint64 // gaps released by the hold timer
	Overflows  uint64
	Resets     uint64
	Depth      int // occupied slots right now
}

type slot[T any] struct {
	occupied bool
	seq      uint32
	arrival  time.Time
	val      T
}

// Buffer is a sequence-ordered release ring. deliver is called under the
// buffer lock, so it must not block; late=true marks packets released out
// of order because they arrived behind the release point — the payload is
// WireGuard ciphertext, so passing them through beats dropping them: the
// inner anti-replay window deduplicates and inner protocols tolerate the
// blip. drop releases packets that are never delivered (duplicate copies
// inside the window, far-out-of-window noise).
type Buffer[T any] struct {
	mu           sync.Mutex
	slots        [Size]slot[T]
	started      bool
	nextExpected uint32
	occupied     int
	hold         time.Duration
	farLate      int

	deliver func(T, bool)
	drop    func(T)
	now     func() time.Time
	timer   *time.Timer

	stats Stats
}

// New builds a buffer. now may be nil (wall clock); it exists for tests.
func New[T any](deliver func(T, bool), drop func(T), now func() time.Time) *Buffer[T] {
	if now == nil {
		now = time.Now
	}
	return &Buffer[T]{
		hold:    DefaultHold,
		deliver: deliver,
		drop:    drop,
		now:     now,
	}
}

// SetHold adjusts the gap timeout (clamped to [2ms, 250ms]). Only the
// bulk stream pays this latency — realtime and interactive classes bypass
// the buffer — so a generous ceiling beats mass timeouts when a path's
// queue momentarily bloats.
func (b *Buffer[T]) SetHold(d time.Duration) {
	if d < 2*time.Millisecond {
		d = 2 * time.Millisecond
	}
	if d > 250*time.Millisecond {
		d = 250 * time.Millisecond
	}
	b.mu.Lock()
	b.hold = d
	b.mu.Unlock()
}

// Snapshot returns current statistics.
func (b *Buffer[T]) Snapshot() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.stats
	s.Depth = b.occupied
	return s
}

// Push inserts one packet. Contiguous sequences are delivered immediately;
// gaps wait for the hold timer.
func (b *Buffer[T]) Push(seq uint32, val T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.started {
		b.started = true
		b.nextExpected = seq
	}

	diff := int32(seq - b.nextExpected)
	switch {
	case diff < 0:
		if diff < -Size {
			// Far behind: noise, or a peer restart with fresh sequence
			// numbers.
			b.farLate++
			if b.farLate >= resetThreshold {
				b.resetLocked(seq)
				b.insertLocked(seq, val)
				b.drainLocked()
				return
			}
			b.stats.Late++
			b.drop(val)
			return
		}
		// Just behind the release point (slow-path straggler): pass it
		// through out of order rather than losing it.
		b.stats.Late++
		b.deliver(val, true)
		return
	case diff >= Size:
		if diff > 4*Size {
			// Far ahead of the window: sequence restart, not congestion.
			b.farLate++
			if b.farLate >= resetThreshold {
				b.resetLocked(seq)
				b.insertLocked(seq, val)
				b.drainLocked()
				return
			}
			b.stats.Late++
			b.drop(val)
			return
		}
		// Window overrun: release everything pending in order, then jump.
		b.stats.Overflows++
		b.flushLocked()
		b.nextExpected = seq
	}
	b.farLate = 0

	b.insertLocked(seq, val)
	b.drainLocked()
	b.armTimerLocked()
}

func (b *Buffer[T]) insertLocked(seq uint32, val T) {
	s := &b.slots[seq%Size]
	if s.occupied {
		// Same window position means same sequence: a duplicate copy.
		b.stats.Duplicates++
		b.drop(val)
		return
	}
	s.occupied = true
	s.seq = seq
	s.arrival = b.now()
	s.val = val
	b.occupied++
}

// drainLocked delivers the contiguous run starting at nextExpected.
func (b *Buffer[T]) drainLocked() {
	for {
		s := &b.slots[b.nextExpected%Size]
		if !s.occupied || s.seq != b.nextExpected {
			return
		}
		b.deliver(s.val, false)
		b.stats.Delivered++
		var zero T
		s.occupied = false
		s.val = zero
		b.occupied--
		b.nextExpected++
	}
}

// flushLocked delivers every occupied slot in sequence order (used on
// overflow and shutdown).
func (b *Buffer[T]) flushLocked() {
	for i := 0; i < Size && b.occupied > 0; i++ {
		s := &b.slots[(b.nextExpected+uint32(i))%Size]
		if s.occupied {
			b.deliver(s.val, false)
			b.stats.Delivered++
			var zero T
			s.occupied = false
			s.val = zero
			b.occupied--
		}
	}
}

func (b *Buffer[T]) resetLocked(seq uint32) {
	b.flushLocked()
	b.nextExpected = seq
	b.farLate = 0
	b.stats.Resets++
}

// armTimerLocked schedules a gap-expiry pass while packets are waiting.
func (b *Buffer[T]) armTimerLocked() {
	if b.occupied == 0 || b.timer != nil {
		return
	}
	b.timer = time.AfterFunc(b.hold, b.onTimer)
}

func (b *Buffer[T]) onTimer() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timer = nil
	b.expireLocked()
	if b.occupied > 0 {
		b.timer = time.AfterFunc(b.hold, b.onTimer)
	}
}

// expireLocked skips gaps whose oldest waiting packet exceeded the hold
// time: nextExpected jumps to the first occupied slot, then the contiguous
// run drains.
func (b *Buffer[T]) expireLocked() {
	now := b.now()
	for b.occupied > 0 {
		// Find the first waiting packet at or after the release point.
		var first *slot[T]
		for i := 0; i < Size; i++ {
			s := &b.slots[(b.nextExpected+uint32(i))%Size]
			if s.occupied {
				first = s
				break
			}
		}
		if first == nil || now.Sub(first.arrival) < b.hold {
			return
		}
		b.stats.TimedOut++
		b.nextExpected = first.seq
		b.drainLocked()
	}
}

// Tick forces an expiry pass; tests use it instead of waiting on timers.
func (b *Buffer[T]) Tick() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
}

// Close stops the timer and flushes whatever is pending, in order.
func (b *Buffer[T]) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.flushLocked()
}
