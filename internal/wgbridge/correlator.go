package wgbridge

import (
	"sync"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Correlator matches classified plaintext packets with the ciphertext
// datagrams WireGuard produces from them. wireguard-go preserves per-peer
// ordering between TUN reads and Bind sends, so a FIFO of expected
// ciphertext lengths is enough; a bounded scan-ahead absorbs packets
// WireGuard drops internally (full staged queues), and any residual
// mismatch falls back to BULK and is counted.
//
// WireGuard transport framing: 16-byte header (type+reserved, receiver,
// counter) + plaintext padded to a 16-byte multiple + 16-byte tag.
type Correlator struct {
	mu    sync.Mutex
	fifo  []corrEntry
	hits  uint64
	miss  uint64
	drops uint64 // entries discarded by scan-ahead
}

type corrEntry struct {
	class uint8
	ctLen int
}

// scanAhead bounds how many stale entries a match may skip.
const scanAhead = 8

// fifoCap bounds memory if ciphertext stops flowing entirely.
const fifoCap = 4096

// ExpectedCtLen returns the ciphertext length WireGuard will produce for a
// plaintext of the given length.
func ExpectedCtLen(ptLen int) int {
	padded := (ptLen + 15) &^ 15
	return 16 + padded + 16
}

// PushPlain records one classified plaintext heading into WireGuard.
func (c *Correlator) PushPlain(class uint8, ptLen int) {
	c.mu.Lock()
	if len(c.fifo) < fifoCap {
		c.fifo = append(c.fifo, corrEntry{class: class, ctLen: ExpectedCtLen(ptLen)})
	}
	c.mu.Unlock()
}

// MatchCiphertext pops the class expected for a transport ciphertext of
// the given length. Mismatches scan ahead up to scanAhead entries; a total
// miss returns BULK.
func (c *Correlator) MatchCiphertext(ctLen int) uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := len(c.fifo)
	if limit > scanAhead {
		limit = scanAhead
	}
	for i := 0; i < limit; i++ {
		if c.fifo[i].ctLen == ctLen {
			class := c.fifo[i].class
			c.fifo = c.fifo[i+1:]
			c.drops += uint64(i)
			c.hits++
			return class
		}
	}
	c.miss++
	return wire.ClassBulk
}

// Flush clears pending entries (handshake boundaries).
func (c *Correlator) Flush() {
	c.mu.Lock()
	c.fifo = c.fifo[:0]
	c.mu.Unlock()
}

// Stats returns hits, misses and scan-ahead drops.
func (c *Correlator) Stats() (hits, miss, drops uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.miss, c.drops
}
