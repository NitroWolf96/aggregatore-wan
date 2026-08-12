package wgbridge

import (
	"testing"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

func TestExpectedCtLen(t *testing.T) {
	// 16B header + padded plaintext + 16B tag.
	cases := map[int]int{0: 32, 1: 48, 16: 48, 17: 64, 1344: 1376}
	for pt, want := range cases {
		if got := ExpectedCtLen(pt); got != want {
			t.Fatalf("pt=%d: got %d want %d", pt, got, want)
		}
	}
}

func TestCorrelatorMatch(t *testing.T) {
	c := &Correlator{}
	c.PushPlain(wire.ClassRealtime, 160)
	c.PushPlain(wire.ClassBulk, 1344)
	if got := c.MatchCiphertext(ExpectedCtLen(160)); got != wire.ClassRealtime {
		t.Fatalf("got %d", got)
	}
	if got := c.MatchCiphertext(ExpectedCtLen(1344)); got != wire.ClassBulk {
		t.Fatalf("got %d", got)
	}
}

func TestCorrelatorScanAhead(t *testing.T) {
	c := &Correlator{}
	// WireGuard dropped the first packet internally: its entry is stale.
	c.PushPlain(wire.ClassInteractive, 48)
	c.PushPlain(wire.ClassRealtime, 160)
	if got := c.MatchCiphertext(ExpectedCtLen(160)); got != wire.ClassRealtime {
		t.Fatalf("got %d", got)
	}
	_, _, drops := c.Stats()
	if drops != 1 {
		t.Fatalf("drops=%d", drops)
	}
}

func TestCorrelatorMissFallsBackToBulk(t *testing.T) {
	c := &Correlator{}
	if got := c.MatchCiphertext(ExpectedCtLen(999)); got != wire.ClassBulk {
		t.Fatalf("got %d", got)
	}
	_, miss, _ := c.Stats()
	if miss != 1 {
		t.Fatalf("miss=%d", miss)
	}
}

func TestCorrelatorAmbiguousLengthsKeepOrder(t *testing.T) {
	// Same-size packets of different classes must map FIFO.
	c := &Correlator{}
	c.PushPlain(wire.ClassRealtime, 100)
	c.PushPlain(wire.ClassInteractive, 100)
	if got := c.MatchCiphertext(ExpectedCtLen(100)); got != wire.ClassRealtime {
		t.Fatalf("first: got %d", got)
	}
	if got := c.MatchCiphertext(ExpectedCtLen(100)); got != wire.ClassInteractive {
		t.Fatalf("second: got %d", got)
	}
}
