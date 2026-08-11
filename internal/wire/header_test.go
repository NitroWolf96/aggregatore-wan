package wire

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	for typ := uint8(0); typ <= maxType; typ++ {
		h := Header{Type: typ, Flags: FlagDup | ClassFlags(ClassRealtime), PathID: 7, Epoch: 3}
		var b [HeaderSize]byte
		PutHeader(b[:], h)
		got, err := ParseHeader(b[:])
		if err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		if got != h {
			t.Fatalf("type %d: got %+v want %+v", typ, got, h)
		}
	}
}

func TestHeaderClass(t *testing.T) {
	for _, class := range []uint8{ClassBulk, ClassRealtime, ClassInteractive} {
		h := Header{Flags: ClassFlags(class) | FlagDup}
		if h.Class() != class {
			t.Fatalf("class %d: got %d", class, h.Class())
		}
	}
}

func TestParseHeaderErrors(t *testing.T) {
	if _, err := ParseHeader([]byte{1, 2}); err != ErrShortBuffer {
		t.Fatalf("short: got %v", err)
	}
	if _, err := ParseHeader([]byte{0x20, 0, 0, 0}); err != ErrVersion {
		t.Fatalf("version: got %v", err)
	}
	if _, err := ParseHeader([]byte{Version<<4 | 0x0f, 0, 0, 0}); err != ErrType {
		t.Fatalf("type: got %v", err)
	}
}

func TestDataHeaderRoundTrip(t *testing.T) {
	payload := []byte("wireguard ciphertext")
	cases := []DataHeader{
		{
			Header:    Header{Type: TypeData, Flags: ClassFlags(ClassBulk), PathID: 1},
			Session:   0xdeadbeef,
			GlobalSeq: 42, PathSeq: 41, TxTS: 123456,
		},
		{
			Header:  Header{Type: TypeData, Flags: FlagFECInfo | FlagDup | ClassFlags(ClassRealtime), PathID: 250, Epoch: 9},
			Session: 1, GlobalSeq: 0xffffffff, PathSeq: 0, TxTS: 0xffffffff,
			FECGroup: 0xabcdef, FECIndex: 3,
		},
	}
	for i, d := range cases {
		buf := make([]byte, d.Len()+len(payload))
		n := PutDataHeader(buf, &d)
		if n != d.Len() {
			t.Fatalf("case %d: wrote %d want %d", i, n, d.Len())
		}
		copy(buf[n:], payload)
		got, pl, err := ParseDataHeader(buf)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got != d {
			t.Fatalf("case %d: got %+v want %+v", i, got, d)
		}
		if !bytes.Equal(pl, payload) {
			t.Fatalf("case %d: payload %q", i, pl)
		}
	}
}

func TestParseDataHeaderErrors(t *testing.T) {
	var d = DataHeader{Header: Header{Type: TypeData, Flags: FlagFECInfo}}
	buf := make([]byte, DataHeaderFECSize)
	PutDataHeader(buf, &d)
	if _, _, err := ParseDataHeader(buf[:DataHeaderSize]); err != ErrShortBuffer {
		t.Fatalf("truncated FEC header: got %v", err)
	}
	probe := make([]byte, DataHeaderSize)
	PutHeader(probe, Header{Type: TypeProbe})
	if _, _, err := ParseDataHeader(probe); err != ErrType {
		t.Fatalf("non-DATA: got %v", err)
	}
}

func BenchmarkPutDataHeader(b *testing.B) {
	d := DataHeader{Header: Header{Type: TypeData}, Session: 1, GlobalSeq: 2, PathSeq: 3, TxTS: 4}
	buf := make([]byte, DataHeaderSize)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		PutDataHeader(buf, &d)
	}
}

func BenchmarkParseDataHeader(b *testing.B) {
	d := DataHeader{Header: Header{Type: TypeData}, Session: 1, GlobalSeq: 2, PathSeq: 3, TxTS: 4}
	buf := make([]byte, DataHeaderSize+1400)
	PutDataHeader(buf, &d)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ParseDataHeader(buf); err != nil {
			b.Fatal(err)
		}
	}
}
