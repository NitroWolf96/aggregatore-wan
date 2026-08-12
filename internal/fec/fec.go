// Package fec adds adaptive Reed-Solomon forward error correction to the
// BULK stream: every k data packets the sender emits m parity shards, so
// the receiver repairs up to m losses per group without waiting for
// end-to-end retransmissions. The (k,m) ratio follows the measured loss.
package fec

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Params is one group geometry. K == 0 means FEC is off.
type Params struct {
	K, M int
}

func (p Params) String() string {
	if p.K == 0 {
		return "off"
	}
	return fmt.Sprintf("%d:%d", p.K, p.M)
}

// PickParams maps the aggregate loss EWMA to a group geometry
// (the design's controller table).
func PickParams(loss float64) Params {
	switch {
	case loss < 0.001:
		return Params{}
	case loss < 0.005:
		return Params{K: 10, M: 1}
	case loss < 0.02:
		return Params{K: 10, M: 2}
	case loss < 0.05:
		return Params{K: 8, M: 3}
	default:
		return Params{K: 5, M: 2}
	}
}

// ParseForce parses a "k:m" override string.
func ParseForce(s string) (Params, error) {
	var p Params
	if _, err := fmt.Sscanf(s, "%d:%d", &p.K, &p.M); err != nil {
		return Params{}, fmt.Errorf("fec force %q: want \"k:m\"", s)
	}
	if p.K < 1 || p.K > 64 || p.M < 1 || p.M > 16 {
		return Params{}, fmt.Errorf("fec force %q: k in [1,64], m in [1,16]", s)
	}
	return p, nil
}

// FlushTimeout closes a partial group so parity never waits long on a
// quiet stream.
const FlushTimeout = 8 * time.Millisecond

// shardHeader prefixes each shard with the packet's global sequence and
// ciphertext length so a reconstructed shard is self-describing.
const shardHeader = 6

func buildShard(seq uint32, ct []byte) []byte {
	s := make([]byte, shardHeader+len(ct))
	binary.BigEndian.PutUint32(s, seq)
	binary.BigEndian.PutUint16(s[4:], uint16(len(ct)))
	copy(s[shardHeader:], ct)
	return s
}

func parseShard(s []byte) (seq uint32, ct []byte, ok bool) {
	if len(s) < shardHeader {
		return 0, nil, false
	}
	l := int(binary.BigEndian.Uint16(s[4:]))
	if shardHeader+l > len(s) {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(s), s[shardHeader : shardHeader+l], true
}

type codecCache struct {
	mu     sync.Mutex
	codecs map[[2]int]reedsolomon.Encoder
}

func (c *codecCache) get(k, m int) (reedsolomon.Encoder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codecs == nil {
		c.codecs = make(map[[2]int]reedsolomon.Encoder)
	}
	key := [2]int{k, m}
	if enc, ok := c.codecs[key]; ok {
		return enc, nil
	}
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	c.codecs[key] = enc
	return enc, nil
}

// ParityFunc emits one parity shard datagram.
type ParityFunc func(group uint32, index, k, m uint8, shard []byte)

// Encoder groups outgoing bulk packets and emits parity.
type Encoder struct {
	mu        sync.Mutex
	params    Params // desired geometry, applied at each new group
	nextGroup uint32
	shards    [][]byte
	maxLen    int
	firstAt   time.Time
	groupID   uint32
	m         int
	emit      ParityFunc
	codecs    codecCache

	// Stats (guarded by mu).
	GroupsClosed  uint64
	ParityEmitted uint64
}

func NewEncoder(emit ParityFunc) *Encoder {
	return &Encoder{emit: emit}
}

// SetParams changes the geometry from the next group on.
func (e *Encoder) SetParams(p Params) {
	e.mu.Lock()
	e.params = p
	e.mu.Unlock()
}

// Enabled reports whether new packets are being protected.
func (e *Encoder) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.params.K > 0
}

// Add registers one outgoing bulk packet. When FEC is active it returns
// the group/index to stamp into the DATA header (on=true); reaching k
// shards closes the group and emits parity synchronously.
func (e *Encoder) Add(seq uint32, ct []byte, now time.Time) (group uint32, index uint8, on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.shards) == 0 {
		if e.params.K == 0 {
			return 0, 0, false
		}
		// New group adopts the current geometry.
		e.groupID = e.nextGroup & 0xffffff
		e.nextGroup++
		e.m = e.params.M
		e.firstAt = now
		e.maxLen = 0
	}
	e.shards = append(e.shards, buildShard(seq, ct))
	if l := shardHeader + len(ct); l > e.maxLen {
		e.maxLen = l
	}
	group, index = e.groupID, uint8(len(e.shards)-1)
	if len(e.shards) >= e.params.K {
		e.closeLocked()
	}
	return group, index, true
}

// Flush closes a stale partial group.
func (e *Encoder) Flush(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.shards) > 0 && now.Sub(e.firstAt) >= FlushTimeout {
		e.closeLocked()
	}
}

func (e *Encoder) closeLocked() {
	k := len(e.shards)
	m := e.m
	if m == 0 || k == 0 {
		e.shards = e.shards[:0]
		return
	}
	all := make([][]byte, k+m)
	for i, s := range e.shards {
		if len(s) < e.maxLen {
			padded := make([]byte, e.maxLen)
			copy(padded, s)
			s = padded
		}
		all[i] = s
	}
	for i := 0; i < m; i++ {
		all[k+i] = make([]byte, e.maxLen)
	}
	codec, err := e.codecs.get(k, m)
	if err == nil {
		err = codec.Encode(all)
	}
	if err == nil {
		for i := 0; i < m; i++ {
			e.emit(e.groupID, uint8(k+i), uint8(k), uint8(m), all[k+i])
			e.ParityEmitted++
		}
		e.GroupsClosed++
	}
	e.shards = e.shards[:0]
}

// RecoverFunc receives a repaired packet (sequence + ciphertext).
type RecoverFunc func(seq uint32, ct []byte)

// Decoder collects shards per group and repairs missing data packets.
type Decoder struct {
	mu        sync.Mutex
	groups    map[uint32]*dgroup
	codecs    codecCache
	recovered RecoverFunc
	adds      int

	// Stats (guarded by mu).
	Recovered uint64
}

const (
	maxGroups   = 512
	groupExpiry = time.Second
)

type dgroup struct {
	shards   map[uint8][]byte
	k, m     int // 0 until a parity shard reveals the geometry
	shardLen int
	touched  time.Time
	done     bool
}

func NewDecoder(recovered RecoverFunc) *Decoder {
	return &Decoder{groups: make(map[uint32]*dgroup), recovered: recovered}
}

func (d *Decoder) group(id uint32, now time.Time) *dgroup {
	g := d.groups[id]
	if g == nil {
		if len(d.groups) >= maxGroups {
			d.sweepLocked(now, true)
		}
		g = &dgroup{shards: make(map[uint8][]byte)}
		d.groups[id] = g
	}
	g.touched = now
	return g
}

// AddData registers a received bulk packet that belongs to a FEC group.
func (d *Decoder) AddData(groupID uint32, index uint8, seq uint32, ct []byte, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.maybeSweepLocked(now)
	g := d.group(groupID, now)
	if g.done {
		return
	}
	if _, dup := g.shards[index]; dup {
		return
	}
	g.shards[index] = buildShard(seq, ct)
	d.tryReconstructLocked(groupID, g)
}

// AddParity registers a parity shard.
func (d *Decoder) AddParity(groupID uint32, index, k, m uint8, shard []byte, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.maybeSweepLocked(now)
	g := d.group(groupID, now)
	if g.done || k == 0 {
		return
	}
	g.k, g.m, g.shardLen = int(k), int(m), len(shard)
	if _, dup := g.shards[index]; dup {
		return
	}
	g.shards[index] = append([]byte(nil), shard...)
	d.tryReconstructLocked(groupID, g)
}

func (d *Decoder) tryReconstructLocked(id uint32, g *dgroup) {
	if g.k == 0 {
		return // geometry unknown until parity arrives
	}
	dataHave := 0
	for idx := range g.shards {
		if int(idx) < g.k {
			dataHave++
		}
	}
	if dataHave >= g.k {
		g.done = true // complete: nothing to repair
		delete(d.groups, id)
		return
	}
	if len(g.shards) < g.k {
		return // not enough shards yet
	}
	all := make([][]byte, g.k+g.m)
	for idx, s := range g.shards {
		if int(idx) >= len(all) {
			continue
		}
		if len(s) < g.shardLen {
			padded := make([]byte, g.shardLen)
			copy(padded, s)
			s = padded
		}
		all[idx] = s[:g.shardLen]
	}
	codec, err := d.codecs.get(g.k, g.m)
	if err != nil {
		return
	}
	if err := codec.ReconstructData(all); err != nil {
		return
	}
	for i := 0; i < g.k; i++ {
		if _, had := g.shards[uint8(i)]; had {
			continue
		}
		if seq, ct, ok := parseShard(all[i]); ok {
			d.Recovered++
			d.recovered(seq, ct)
		}
	}
	g.done = true
	delete(d.groups, id)
}

func (d *Decoder) maybeSweepLocked(now time.Time) {
	d.adds++
	if d.adds%128 == 0 {
		d.sweepLocked(now, false)
	}
}

func (d *Decoder) sweepLocked(now time.Time, force bool) {
	cutoff := now.Add(-groupExpiry)
	for id, g := range d.groups {
		if g.touched.Before(cutoff) || (force && len(d.groups) >= maxGroups) {
			delete(d.groups, id)
			force = false
		}
	}
}

// RecoveredCount returns how many packets were repaired.
func (d *Decoder) RecoveredCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Recovered
}
