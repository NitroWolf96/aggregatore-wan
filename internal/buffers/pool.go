// Package buffers provides the pooled slabs used across the datapath so the
// per-packet hot path stays allocation-free.
package buffers

import "sync"

// SlabSize fits any outer datagram (WAN MTU 1500 max) with header room.
const SlabSize = 2048

var pool = sync.Pool{
	New: func() any {
		b := make([]byte, SlabSize)
		return &b
	},
}

// Get returns a SlabSize byte slab from the pool.
func Get() *[]byte { return pool.Get().(*[]byte) }

// Put returns a slab obtained from Get.
func Put(b *[]byte) { pool.Put(b) }

// Packet is a view into a pooled slab: the datagram bytes live at
// [Off, Off+Len). Whoever consumes the packet must return the slab with Put.
type Packet struct {
	Slab *[]byte
	Off  int
	Len  int
}

// Bytes returns the packet payload view.
func (p Packet) Bytes() []byte { return (*p.Slab)[p.Off : p.Off+p.Len] }

// Release returns the underlying slab to the pool.
func (p Packet) Release() {
	if p.Slab != nil {
		Put(p.Slab)
	}
}
