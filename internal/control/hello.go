// Package control implements the authenticated Treccia control plane:
// HELLO/HELLO_ACK path registration, BYE, and (from milestone M3) PROBE and
// CTRL feedback messages. Every control datagram carries a keyed
// BLAKE2s-128 tag over the entire datagram, header included, so the path id
// is authenticated too.
package control

import (
	"encoding/binary"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// ReplayWindow is the maximum clock skew accepted on authenticated
// timestamps.
const ReplayWindow = 30 * time.Second

// FreshTS reports whether a peer's unix timestamp is within the replay
// window of the local clock.
func FreshTS(unixTS int64, now time.Time) bool {
	d := now.Unix() - unixTS
	if d < 0 {
		d = -d
	}
	return d <= int64(ReplayWindow/time.Second)
}

// Hello registers one client path with the server. The same body layout is
// used by HELLO_ACK, where the server echoes ClientID and Session and
// substitutes its own timestamp and the negotiated feature bits.
type Hello struct {
	Session  uint32
	ClientID uint64
	Features uint32
	UnixTS   int64
}

const helloBodySize = 4 + 8 + 4 + 8

// HelloSize is the full datagram size of HELLO and HELLO_ACK.
const HelloSize = wire.HeaderSize + helloBodySize + wire.MACSize

// EncodeHello builds an authenticated HELLO (or HELLO_ACK when ack is true)
// datagram.
func EncodeHello(h wire.Header, m Hello, mac *wire.MAC, ack bool) []byte {
	h.Type = wire.TypeHello
	if ack {
		h.Type = wire.TypeHelloAck
	}
	buf := make([]byte, wire.HeaderSize+helloBodySize, HelloSize)
	wire.PutHeader(buf, h)
	binary.BigEndian.PutUint32(buf[4:], m.Session)
	binary.BigEndian.PutUint64(buf[8:], m.ClientID)
	binary.BigEndian.PutUint32(buf[16:], m.Features)
	binary.BigEndian.PutUint64(buf[20:], uint64(m.UnixTS))
	return mac.AppendTag(buf)
}

// ParseHello authenticates and decodes a HELLO or HELLO_ACK datagram.
func ParseHello(datagram []byte, mac *wire.MAC) (wire.Header, Hello, bool) {
	msg, ok := mac.Verify(datagram)
	if !ok || len(msg) != wire.HeaderSize+helloBodySize {
		return wire.Header{}, Hello{}, false
	}
	h, err := wire.ParseHeader(msg)
	if err != nil || (h.Type != wire.TypeHello && h.Type != wire.TypeHelloAck) {
		return wire.Header{}, Hello{}, false
	}
	m := Hello{
		Session:  binary.BigEndian.Uint32(msg[4:]),
		ClientID: binary.BigEndian.Uint64(msg[8:]),
		Features: binary.BigEndian.Uint32(msg[16:]),
		UnixTS:   int64(binary.BigEndian.Uint64(msg[20:])),
	}
	return h, m, true
}

// Bye announces the clean removal of one path (or, from the last path, the
// whole session).
type Bye struct {
	Session uint32
	UnixTS  int64
}

const byeBodySize = 4 + 8

// ByeSize is the full datagram size of BYE.
const ByeSize = wire.HeaderSize + byeBodySize + wire.MACSize

// EncodeBye builds an authenticated BYE datagram.
func EncodeBye(h wire.Header, m Bye, mac *wire.MAC) []byte {
	h.Type = wire.TypeBye
	buf := make([]byte, wire.HeaderSize+byeBodySize, ByeSize)
	wire.PutHeader(buf, h)
	binary.BigEndian.PutUint32(buf[4:], m.Session)
	binary.BigEndian.PutUint64(buf[8:], uint64(m.UnixTS))
	return mac.AppendTag(buf)
}

// ParseBye authenticates and decodes a BYE datagram.
func ParseBye(datagram []byte, mac *wire.MAC) (wire.Header, Bye, bool) {
	msg, ok := mac.Verify(datagram)
	if !ok || len(msg) != wire.HeaderSize+byeBodySize {
		return wire.Header{}, Bye{}, false
	}
	h, err := wire.ParseHeader(msg)
	if err != nil || h.Type != wire.TypeBye {
		return wire.Header{}, Bye{}, false
	}
	m := Bye{
		Session: binary.BigEndian.Uint32(msg[4:]),
		UnixTS:  int64(binary.BigEndian.Uint64(msg[8:])),
	}
	return h, m, true
}
