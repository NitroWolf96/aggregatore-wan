package fec

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

type emitted struct {
	group uint32
	index uint8
	k, m  uint8
	shard []byte
}

type harness struct {
	enc      *Encoder
	dec      *Decoder
	parity   []emitted
	repaired map[uint32][]byte
}

func newHarness(p Params) *harness {
	h := &harness{repaired: make(map[uint32][]byte)}
	h.enc = NewEncoder(func(group uint32, index, k, m uint8, shard []byte) {
		h.parity = append(h.parity, emitted{group, index, k, m, append([]byte(nil), shard...)})
	})
	h.enc.SetParams(p)
	h.dec = NewDecoder(func(seq uint32, ct []byte) {
		h.repaired[seq] = append([]byte(nil), ct...)
	})
	return h
}

func pkt(seq uint32, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(seq + uint32(i))
	}
	return b
}

func TestOffByDefault(t *testing.T) {
	h := newHarness(Params{})
	if _, _, on := h.enc.Add(1, pkt(1, 100), time.Now()); on {
		t.Fatal("FEC on with zero params")
	}
}

func TestGroupCloseEmitsParity(t *testing.T) {
	h := newHarness(Params{K: 4, M: 2})
	now := time.Now()
	for seq := uint32(1); seq <= 4; seq++ {
		group, idx, on := h.enc.Add(seq, pkt(seq, 100+int(seq)), now)
		if !on || group != 0 || idx != uint8(seq-1) {
			t.Fatalf("seq %d: group=%d idx=%d on=%v", seq, group, idx, on)
		}
	}
	if len(h.parity) != 2 {
		t.Fatalf("parity emitted: %d", len(h.parity))
	}
	if h.parity[0].k != 4 || h.parity[0].m != 2 || h.parity[0].index != 4 {
		t.Fatalf("parity meta: %+v", h.parity[0])
	}
}

func TestFlushClosesPartialGroup(t *testing.T) {
	h := newHarness(Params{K: 10, M: 1})
	now := time.Now()
	h.enc.Add(1, pkt(1, 200), now)
	h.enc.Add(2, pkt(2, 200), now)
	h.enc.Flush(now.Add(FlushTimeout / 2))
	if len(h.parity) != 0 {
		t.Fatal("flushed too early")
	}
	h.enc.Flush(now.Add(FlushTimeout * 2))
	if len(h.parity) != 1 {
		t.Fatalf("parity after flush: %d", len(h.parity))
	}
	if h.parity[0].k != 2 { // partial group: k = shards actually present
		t.Fatalf("partial k = %d", h.parity[0].k)
	}
}

// TestEndToEndRecovery drops data packets and repairs them from parity.
func TestEndToEndRecovery(t *testing.T) {
	for _, loss := range [][]int{{2}, {0, 3}} {
		h := newHarness(Params{K: 5, M: 2})
		now := time.Now()
		packets := make(map[uint32][]byte)
		type sent struct {
			group uint32
			idx   uint8
			seq   uint32
		}
		var stream []sent
		for seq := uint32(100); seq < 105; seq++ {
			ct := pkt(seq, 150+int(seq%3)*40)
			packets[seq] = ct
			group, idx, on := h.enc.Add(seq, ct, now)
			if !on {
				t.Fatal("FEC off")
			}
			stream = append(stream, sent{group, idx, seq})
		}
		lost := map[int]bool{}
		for _, i := range loss {
			lost[i] = true
		}
		for i, s := range stream {
			if !lost[i] {
				h.dec.AddData(s.group, s.idx, s.seq, packets[s.seq], now)
			}
		}
		for _, p := range h.parity {
			h.dec.AddParity(p.group, p.index, p.k, p.m, p.shard, now)
		}
		for _, i := range loss {
			seq := stream[i].seq
			got, ok := h.repaired[seq]
			if !ok {
				t.Fatalf("loss %v: seq %d not repaired", loss, seq)
			}
			if !bytes.Equal(got, packets[seq]) {
				t.Fatalf("loss %v: seq %d repaired wrong", loss, seq)
			}
		}
		if h.dec.RecoveredCount() != uint64(len(loss)) {
			t.Fatalf("recovered count %d", h.dec.RecoveredCount())
		}
	}
}

func TestTooManyLossesNoRepair(t *testing.T) {
	h := newHarness(Params{K: 4, M: 1})
	now := time.Now()
	var seqs []uint32
	groups := make(map[uint32]uint8)
	for seq := uint32(1); seq <= 4; seq++ {
		_, idx, _ := h.enc.Add(seq, pkt(seq, 100), now)
		groups[seq] = idx
		seqs = append(seqs, seq)
	}
	// Lose two of four data packets with only one parity: unrecoverable.
	h.dec.AddData(0, groups[1], 1, pkt(1, 100), now)
	h.dec.AddData(0, groups[2], 2, pkt(2, 100), now)
	for _, p := range h.parity {
		h.dec.AddParity(p.group, p.index, p.k, p.m, p.shard, now)
	}
	if len(h.repaired) != 0 {
		t.Fatalf("repaired the unrepairable: %v", h.repaired)
	}
	_ = seqs
}

func TestPickParamsTable(t *testing.T) {
	cases := []struct {
		loss float64
		want string
	}{
		{0.0001, "off"}, {0.003, "10:1"}, {0.01, "10:2"}, {0.03, "8:3"}, {0.10, "5:2"},
	}
	for _, c := range cases {
		if got := PickParams(c.loss).String(); got != c.want {
			t.Fatalf("loss %v: got %s want %s", c.loss, got, c.want)
		}
	}
}

func TestParseForce(t *testing.T) {
	p, err := ParseForce("10:2")
	if err != nil || p.K != 10 || p.M != 2 {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if _, err := ParseForce("banana"); err == nil {
		t.Fatal("accepted garbage")
	}
	if _, err := ParseForce("100:1"); err == nil {
		t.Fatal("accepted out-of-range k")
	}
}

func BenchmarkEncode10_2(b *testing.B) {
	enc := NewEncoder(func(uint32, uint8, uint8, uint8, []byte) {})
	enc.SetParams(Params{K: 10, M: 2})
	ct := pkt(1, 1376)
	now := time.Now()
	b.SetBytes(1376)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc.Add(uint32(i), ct, now)
	}
}

var _ = fmt.Sprintf
