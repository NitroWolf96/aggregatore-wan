package control

import (
	"encoding/binary"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Probe measures per-path RTT and keeps NAT bindings warm. TxTS is the
// sender's monotonic clock in microseconds; the receiver echoes it in the
// ack together with its hold time, so RTT = now - TxTS - Hold.
type Probe struct {
	Session uint32
	Seq     uint32
	TxTS    uint64
}

const probeBodySize = 4 + 4 + 8

// ProbeSize is the full datagram size of PROBE.
const ProbeSize = wire.HeaderSize + probeBodySize + wire.MACSize

// EncodeProbe builds an authenticated PROBE datagram.
func EncodeProbe(h wire.Header, p Probe, mac *wire.MAC) []byte {
	h.Type = wire.TypeProbe
	buf := make([]byte, wire.HeaderSize+probeBodySize, ProbeSize)
	wire.PutHeader(buf, h)
	binary.BigEndian.PutUint32(buf[4:], p.Session)
	binary.BigEndian.PutUint32(buf[8:], p.Seq)
	binary.BigEndian.PutUint64(buf[12:], p.TxTS)
	return mac.AppendTag(buf)
}

// ParseProbe authenticates and decodes a PROBE datagram.
func ParseProbe(datagram []byte, mac *wire.MAC) (wire.Header, Probe, bool) {
	msg, ok := mac.Verify(datagram)
	if !ok || len(msg) != wire.HeaderSize+probeBodySize {
		return wire.Header{}, Probe{}, false
	}
	h, err := wire.ParseHeader(msg)
	if err != nil || h.Type != wire.TypeProbe {
		return wire.Header{}, Probe{}, false
	}
	return h, Probe{
		Session: binary.BigEndian.Uint32(msg[4:]),
		Seq:     binary.BigEndian.Uint32(msg[8:]),
		TxTS:    binary.BigEndian.Uint64(msg[12:]),
	}, true
}

// ProbeAck answers a Probe. HoldUS is the microseconds the responder spent
// between receiving the probe and sending the ack.
type ProbeAck struct {
	Session uint32
	Seq     uint32
	TxTS    uint64 // echoed from the probe
	HoldUS  uint32
}

const probeAckBodySize = 4 + 4 + 8 + 4

// ProbeAckSize is the full datagram size of PROBE_ACK.
const ProbeAckSize = wire.HeaderSize + probeAckBodySize + wire.MACSize

// EncodeProbeAck builds an authenticated PROBE_ACK datagram.
func EncodeProbeAck(h wire.Header, p ProbeAck, mac *wire.MAC) []byte {
	h.Type = wire.TypeProbeAck
	buf := make([]byte, wire.HeaderSize+probeAckBodySize, ProbeAckSize)
	wire.PutHeader(buf, h)
	binary.BigEndian.PutUint32(buf[4:], p.Session)
	binary.BigEndian.PutUint32(buf[8:], p.Seq)
	binary.BigEndian.PutUint64(buf[12:], p.TxTS)
	binary.BigEndian.PutUint32(buf[20:], p.HoldUS)
	return mac.AppendTag(buf)
}

// ParseProbeAck authenticates and decodes a PROBE_ACK datagram.
func ParseProbeAck(datagram []byte, mac *wire.MAC) (wire.Header, ProbeAck, bool) {
	msg, ok := mac.Verify(datagram)
	if !ok || len(msg) != wire.HeaderSize+probeAckBodySize {
		return wire.Header{}, ProbeAck{}, false
	}
	h, err := wire.ParseHeader(msg)
	if err != nil || h.Type != wire.TypeProbeAck {
		return wire.Header{}, ProbeAck{}, false
	}
	return h, ProbeAck{
		Session: binary.BigEndian.Uint32(msg[4:]),
		Seq:     binary.BigEndian.Uint32(msg[8:]),
		TxTS:    binary.BigEndian.Uint64(msg[12:]),
		HoldUS:  binary.BigEndian.Uint32(msg[20:]),
	}, true
}
