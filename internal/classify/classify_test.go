package classify

import (
	"encoding/binary"
	"testing"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

// buildUDP4 builds an IPv4/UDP packet with the given payload size.
func buildUDP4(sport, dport uint16, payload int) []byte {
	pkt := make([]byte, 20+8+payload)
	pkt[0] = 0x45
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:], sport)
	binary.BigEndian.PutUint16(pkt[22:], dport)
	return pkt
}

// buildTCP4 builds an IPv4/TCP packet with the given payload size.
func buildTCP4(sport, dport uint16, payload int) []byte {
	pkt := make([]byte, 20+20+payload)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:], sport)
	binary.BigEndian.PutUint16(pkt[22:], dport)
	pkt[32] = 5 << 4 // data offset 20
	return pkt
}

func TestSmallUDPIsRealtime(t *testing.T) {
	c := New(nil)
	if got := c.Classify(buildUDP4(40000, 27015, 120)); got != wire.ClassRealtime {
		t.Fatalf("got %d", got)
	}
}

func TestBigUDPIsBulk(t *testing.T) {
	c := New(nil)
	if got := c.Classify(buildUDP4(40000, 443, 1250)); got != wire.ClassBulk {
		t.Fatalf("got %d", got)
	}
}

func TestDNSIsInteractive(t *testing.T) {
	c := New(nil)
	if got := c.Classify(buildUDP4(40000, 53, 60)); got != wire.ClassInteractive {
		t.Fatalf("got %d", got)
	}
}

func TestSSHIsInteractive(t *testing.T) {
	c := New(nil)
	if got := c.Classify(buildTCP4(40000, 22, 48)); got != wire.ClassInteractive {
		t.Fatalf("got %d", got)
	}
}

func TestTCPBulkVsAcks(t *testing.T) {
	c := New(nil)
	// Pure-ack flow stays interactive.
	for i := 0; i < 10; i++ {
		if got := c.Classify(buildTCP4(50000, 443, 0)); got != wire.ClassInteractive {
			t.Fatalf("ack %d: got %d", i, got)
		}
	}
	// Data-bearing flow becomes bulk immediately.
	if got := c.Classify(buildTCP4(50001, 443, 1400)); got != wire.ClassBulk {
		t.Fatalf("got %d", got)
	}
}

func TestICMPIsInteractive(t *testing.T) {
	pkt := buildUDP4(0, 0, 32)
	pkt[9] = 1 // ICMP
	c := New(nil)
	if got := c.Classify(pkt); got != wire.ClassInteractive {
		t.Fatalf("got %d", got)
	}
}

func TestConfigRuleOverrides(t *testing.T) {
	c := New([]Rule{{Proto: "udp", Port: 27015, Class: "interactive"}})
	if got := c.Classify(buildUDP4(40000, 27015, 120)); got != wire.ClassInteractive {
		t.Fatalf("got %d", got)
	}
}

func TestFlowAverageFlipsClass(t *testing.T) {
	c := New(nil)
	// A UDP flow that starts small (looks realtime)...
	for i := 0; i < 3; i++ {
		c.Classify(buildUDP4(60000, 5000, 100))
	}
	// ...then sends many full-size packets: average rises, class flips to bulk.
	var got uint8
	for i := 0; i < 20; i++ {
		got = c.Classify(buildUDP4(60000, 5000, 1300))
	}
	if got != wire.ClassBulk {
		t.Fatalf("got %d", got)
	}
}
