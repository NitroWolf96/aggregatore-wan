package wire

import (
	"bytes"
	"testing"
)

// FuzzParseDataHeader checks that arbitrary input never panics and that
// anything that parses re-encodes to an identical wire image.
func FuzzParseDataHeader(f *testing.F) {
	seed := DataHeader{Header: Header{Type: TypeData, Flags: FlagFECInfo}, Session: 7, GlobalSeq: 8, PathSeq: 9, TxTS: 10, FECGroup: 11, FECIndex: 12}
	buf := make([]byte, DataHeaderFECSize+64)
	PutDataHeader(buf, &seed)
	f.Add(buf)
	f.Add([]byte{})
	f.Add([]byte{Version << 4, 0, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		d, payload, err := ParseDataHeader(b)
		if err != nil {
			return
		}
		out := make([]byte, d.Len()+len(payload))
		n := PutDataHeader(out, &d)
		copy(out[n:], payload)
		if !bytes.Equal(out, b) {
			t.Fatalf("re-encode mismatch:\n in %x\nout %x", b, out)
		}
	})
}

// FuzzParseHeader checks the common header parser never panics and
// round-trips whatever it accepts.
func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{Version<<4 | 3, 0xff, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeader(b)
		if err != nil {
			return
		}
		var out [HeaderSize]byte
		PutHeader(out[:], h)
		if !bytes.Equal(out[:], b[:HeaderSize]) {
			t.Fatalf("re-encode mismatch: in %x out %x", b[:HeaderSize], out)
		}
	})
}

// FuzzMACVerify checks Verify never panics on arbitrary input.
func FuzzMACVerify(f *testing.F) {
	mac := NewMAC(DeriveKey("fuzz"))
	f.Add(mac.AppendTag([]byte("valid")))
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, ok := mac.Verify(b)
		if ok {
			// Anything Verify accepts must re-sign to the same bytes.
			if !bytes.Equal(mac.AppendTag(append([]byte(nil), msg...)), b) {
				t.Fatal("verify/sign disagreement")
			}
		}
	})
}
