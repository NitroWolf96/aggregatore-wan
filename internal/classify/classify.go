// Package classify assigns a traffic class to each plaintext IP packet
// before encryption. The class drives the scheduler: BULK is striped for
// throughput, REALTIME is duplicated on the two best paths, INTERACTIVE
// sticks to the lowest-latency path.
package classify

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// Heuristic thresholds.
const (
	realtimeMaxUDPSize = 300 // UDP payloads this small at any rate look like VoIP/game traffic
	interactiveMaxTCP  = 64  // average TCP payload of ssh/acks
	flowTableCap       = 4096
)

// Rule is one user-configured override, matched on protocol and either
// port before any heuristic runs.
type Rule struct {
	Proto string `yaml:"proto"` // "tcp", "udp" or "any"
	Port  uint16 `yaml:"port"`
	Class string `yaml:"class"` // "bulk", "realtime", "interactive"
}

// ParseClass maps a config string to a wire class.
func ParseClass(s string) (uint8, bool) {
	switch s {
	case "bulk":
		return wire.ClassBulk, true
	case "realtime":
		return wire.ClassRealtime, true
	case "interactive":
		return wire.ClassInteractive, true
	}
	return 0, false
}

type flowKey struct {
	src, dst   netip.Addr
	proto      uint8
	sport, dpt uint16
}

type flowState struct {
	pkts    uint64
	payload uint64 // transport payload bytes total
	class   uint8
}

// Classifier is safe for concurrent use.
type Classifier struct {
	mu    sync.Mutex
	flows map[flowKey]*flowState
	rules map[[2]uint16]uint8 // {protoKey, port} -> class
}

const (
	protoTCP = 6
	protoUDP = 17
	protoAny = 0
)

// New builds a classifier from config rules (invalid rules are ignored by
// the config validator before this point).
func New(rules []Rule) *Classifier {
	c := &Classifier{
		flows: make(map[flowKey]*flowState),
		rules: make(map[[2]uint16]uint8),
	}
	for _, r := range rules {
		class, ok := ParseClass(r.Class)
		if !ok || r.Port == 0 {
			continue
		}
		var protoKey uint16
		switch r.Proto {
		case "tcp":
			protoKey = protoTCP
		case "udp":
			protoKey = protoUDP
		default:
			protoKey = protoAny
		}
		c.rules[[2]uint16{protoKey, r.Port}] = class
	}
	return c
}

// Classify inspects one outbound IP packet and returns its class.
func (c *Classifier) Classify(pkt []byte) uint8 {
	src, dst, proto, sport, dport, payload, ok := parse(pkt)
	if !ok {
		return wire.ClassBulk
	}
	// ICMP (echo, unreachable...) is tiny and latency-sensitive.
	if proto != protoTCP && proto != protoUDP {
		return wire.ClassInteractive
	}

	if class, ok := c.ruleFor(proto, sport, dport); ok {
		return class
	}

	// Built-in port defaults.
	if proto == protoUDP && (sport == 53 || dport == 53 || sport == 123 || dport == 123) {
		return wire.ClassInteractive
	}
	if proto == protoTCP && (sport == 22 || dport == 22 || sport == 53 || dport == 53) {
		return wire.ClassInteractive
	}

	// Flow heuristics on the running average payload size.
	key := flowKey{src: src, dst: dst, proto: proto, sport: sport, dpt: dport}
	c.mu.Lock()
	defer c.mu.Unlock()
	fs := c.flows[key]
	if fs == nil {
		if len(c.flows) >= flowTableCap {
			// Cheap eviction: drop the table; live flows re-learn in a few
			// packets and the hot path stays allocation-bounded.
			c.flows = make(map[flowKey]*flowState)
		}
		fs = &flowState{}
		c.flows[key] = fs
	}
	fs.pkts++
	fs.payload += uint64(payload)
	avg := fs.payload / fs.pkts

	switch proto {
	case protoUDP:
		if avg <= realtimeMaxUDPSize {
			fs.class = wire.ClassRealtime
		} else {
			fs.class = wire.ClassBulk
		}
	case protoTCP:
		if avg <= interactiveMaxTCP {
			fs.class = wire.ClassInteractive
		} else {
			fs.class = wire.ClassBulk
		}
	}
	return fs.class
}

func (c *Classifier) ruleFor(proto uint8, sport, dport uint16) (uint8, bool) {
	if len(c.rules) == 0 {
		return 0, false
	}
	for _, k := range [...][2]uint16{
		{uint16(proto), sport}, {uint16(proto), dport},
		{protoAny, sport}, {protoAny, dport},
	} {
		if class, ok := c.rules[k]; ok {
			return class, true
		}
	}
	return 0, false
}

// parse extracts the 5-tuple and transport payload length from an IPv4 or
// IPv6 packet.
func parse(pkt []byte) (src, dst netip.Addr, proto uint8, sport, dport uint16, payload int, ok bool) {
	if len(pkt) < 1 {
		return
	}
	var transport []byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return
		}
		proto = pkt[9]
		src, _ = netip.AddrFromSlice(pkt[12:16])
		dst, _ = netip.AddrFromSlice(pkt[16:20])
		transport = pkt[ihl:]
	case 6:
		if len(pkt) < 40 {
			return
		}
		proto = pkt[6] // next header; extension chains fall through to heuristics
		src, _ = netip.AddrFromSlice(pkt[8:24])
		dst, _ = netip.AddrFromSlice(pkt[24:40])
		transport = pkt[40:]
	default:
		return
	}

	switch proto {
	case protoTCP:
		if len(transport) < 20 {
			return
		}
		sport = binary.BigEndian.Uint16(transport[0:])
		dport = binary.BigEndian.Uint16(transport[2:])
		dataOff := int(transport[12]>>4) * 4
		if dataOff < 20 || len(transport) < dataOff {
			return
		}
		payload = len(transport) - dataOff
	case protoUDP:
		if len(transport) < 8 {
			return
		}
		sport = binary.BigEndian.Uint16(transport[0:])
		dport = binary.BigEndian.Uint16(transport[2:])
		payload = len(transport) - 8
	}
	return src, dst, proto, sport, dport, payload, true
}
