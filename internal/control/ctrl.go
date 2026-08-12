package control

import (
	"encoding/binary"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// CTRL is the receiver's periodic feedback: one PathStats record per path
// it has heard from, TLV-encoded so future record types (FEC stats, SACK
// bitmaps) can ride along.

// TLV record types inside CTRL.
const (
	tlvPathStats = 1
)

// PathStats reports what one direction of one path has received. The
// sender derives loss (from Highest vs RxPkts deltas), delivery rate (from
// RxBytes over the report interval) and in-flight (its sent counter minus
// Highest).
type PathStats struct {
	PathID   uint8
	Highest  uint32 // highest path_seq seen
	RxPkts   uint32
	RxBytes  uint64
	OwdMinUS uint32 // min one-way-delay sample in the report window (relative clock)
	OwdAvgUS uint32 // EWMA of one-way-delay (relative clock)
}

const pathStatsSize = 1 + 4 + 4 + 8 + 4 + 4

// Ctrl is one feedback datagram.
type Ctrl struct {
	Session uint32
	Paths   []PathStats
}

// MaxCtrlPaths bounds records to keep CTRL inside one MTU.
const MaxCtrlPaths = 40

// EncodeCtrl builds an authenticated CTRL datagram.
func EncodeCtrl(h wire.Header, c Ctrl, mac *wire.MAC) []byte {
	h.Type = wire.TypeCtrl
	n := len(c.Paths)
	if n > MaxCtrlPaths {
		n = MaxCtrlPaths
	}
	buf := make([]byte, wire.HeaderSize+4, wire.HeaderSize+4+n*(2+pathStatsSize)+wire.MACSize)
	wire.PutHeader(buf, h)
	binary.BigEndian.PutUint32(buf[4:], c.Session)
	for _, ps := range c.Paths[:n] {
		var rec [2 + pathStatsSize]byte
		rec[0] = tlvPathStats
		rec[1] = pathStatsSize
		rec[2] = ps.PathID
		binary.BigEndian.PutUint32(rec[3:], ps.Highest)
		binary.BigEndian.PutUint32(rec[7:], ps.RxPkts)
		binary.BigEndian.PutUint64(rec[11:], ps.RxBytes)
		binary.BigEndian.PutUint32(rec[19:], ps.OwdMinUS)
		binary.BigEndian.PutUint32(rec[23:], ps.OwdAvgUS)
		buf = append(buf, rec[:]...)
	}
	return mac.AppendTag(buf)
}

// ParseCtrl authenticates and decodes a CTRL datagram; unknown TLV records
// are skipped.
func ParseCtrl(datagram []byte, mac *wire.MAC) (wire.Header, Ctrl, bool) {
	msg, ok := mac.Verify(datagram)
	if !ok || len(msg) < wire.HeaderSize+4 {
		return wire.Header{}, Ctrl{}, false
	}
	h, err := wire.ParseHeader(msg)
	if err != nil || h.Type != wire.TypeCtrl {
		return wire.Header{}, Ctrl{}, false
	}
	c := Ctrl{Session: binary.BigEndian.Uint32(msg[4:])}
	rest := msg[wire.HeaderSize+4:]
	for len(rest) >= 2 {
		typ, l := rest[0], int(rest[1])
		if len(rest) < 2+l {
			return wire.Header{}, Ctrl{}, false
		}
		body := rest[2 : 2+l]
		rest = rest[2+l:]
		if typ != tlvPathStats || l != pathStatsSize {
			continue // unknown or resized record: skip
		}
		c.Paths = append(c.Paths, PathStats{
			PathID:   body[0],
			Highest:  binary.BigEndian.Uint32(body[1:]),
			RxPkts:   binary.BigEndian.Uint32(body[5:]),
			RxBytes:  binary.BigEndian.Uint64(body[9:]),
			OwdMinUS: binary.BigEndian.Uint32(body[17:]),
			OwdAvgUS: binary.BigEndian.Uint32(body[21:]),
		})
	}
	return h, c, true
}
