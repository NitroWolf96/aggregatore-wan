package control

import (
	"testing"
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/wire"
)

var mac = wire.NewMAC(wire.DeriveKey("test"))

func TestHelloRoundTrip(t *testing.T) {
	in := Hello{Session: 7, ClientID: 0xabcdef, Features: 3, UnixTS: time.Now().Unix()}
	dg := EncodeHello(wire.Header{PathID: 4}, in, mac, false)
	h, out, ok := ParseHello(dg, mac)
	if !ok || h.Type != wire.TypeHello || h.PathID != 4 || out != in {
		t.Fatalf("h=%+v out=%+v ok=%v", h, out, ok)
	}
	ack := EncodeHello(wire.Header{PathID: 4}, in, mac, true)
	if h, _, ok := ParseHello(ack, mac); !ok || h.Type != wire.TypeHelloAck {
		t.Fatalf("ack parse failed")
	}
}

func TestProbeRoundTrip(t *testing.T) {
	in := Probe{Session: 9, Seq: 100, TxTS: 123456789}
	dg := EncodeProbe(wire.Header{PathID: 2}, in, mac)
	h, out, ok := ParseProbe(dg, mac)
	if !ok || h.PathID != 2 || out != in {
		t.Fatalf("out=%+v ok=%v", out, ok)
	}
	ackIn := ProbeAck{Session: 9, Seq: 100, TxTS: 123456789, HoldUS: 42}
	ackDg := EncodeProbeAck(wire.Header{PathID: 2}, ackIn, mac)
	if _, ackOut, ok := ParseProbeAck(ackDg, mac); !ok || ackOut != ackIn {
		t.Fatalf("ackOut=%+v ok=%v", ackOut, ok)
	}
}

func TestCtrlRoundTrip(t *testing.T) {
	in := Ctrl{Session: 5, Paths: []PathStats{
		{PathID: 0, Highest: 1000, RxPkts: 990, RxBytes: 1400000, OwdMinUS: 5000, OwdAvgUS: 5200},
		{PathID: 3, Highest: 500, RxPkts: 500, RxBytes: 700000, OwdMinUS: 45000, OwdAvgUS: 47000},
	}}
	dg := EncodeCtrl(wire.Header{PathID: 0}, in, mac)
	_, out, ok := ParseCtrl(dg, mac)
	if !ok || len(out.Paths) != 2 || out.Session != 5 {
		t.Fatalf("out=%+v ok=%v", out, ok)
	}
	for i := range in.Paths {
		if out.Paths[i] != in.Paths[i] {
			t.Fatalf("path %d: %+v != %+v", i, out.Paths[i], in.Paths[i])
		}
	}
}

func TestAuthRejects(t *testing.T) {
	other := wire.NewMAC(wire.DeriveKey("other"))
	dg := EncodeProbe(wire.Header{}, Probe{Session: 1}, mac)
	if _, _, ok := ParseProbe(dg, other); ok {
		t.Fatal("wrong key accepted")
	}
	dg[5] ^= 1
	if _, _, ok := ParseProbe(dg, mac); ok {
		t.Fatal("tampered accepted")
	}
}

func TestFreshTS(t *testing.T) {
	now := time.Now()
	if !FreshTS(now.Unix(), now) || !FreshTS(now.Unix()-29, now) || !FreshTS(now.Unix()+29, now) {
		t.Fatal("fresh rejected")
	}
	if FreshTS(now.Unix()-31, now) || FreshTS(now.Unix()+31, now) {
		t.Fatal("stale accepted")
	}
}
