package wire

import "testing"

func TestMACRoundTrip(t *testing.T) {
	mac := NewMAC(DeriveKey("passphrase"))
	msg := []byte("hello control plane")
	signed := mac.AppendTag(append([]byte(nil), msg...))
	if len(signed) != len(msg)+MACSize {
		t.Fatalf("signed len %d", len(signed))
	}
	got, ok := mac.Verify(signed)
	if !ok {
		t.Fatal("verify failed")
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q", got)
	}
}

func TestMACRejects(t *testing.T) {
	mac := NewMAC(DeriveKey("passphrase"))
	other := NewMAC(DeriveKey("other"))
	signed := mac.AppendTag([]byte("msg"))

	if _, ok := other.Verify(signed); ok {
		t.Fatal("wrong key accepted")
	}
	tampered := append([]byte(nil), signed...)
	tampered[0] ^= 1
	if _, ok := mac.Verify(tampered); ok {
		t.Fatal("tampered message accepted")
	}
	if _, ok := mac.Verify(signed[:MACSize-1]); ok {
		t.Fatal("short buffer accepted")
	}
}

func TestDeriveKeyDistinct(t *testing.T) {
	if DeriveKey("a") == DeriveKey("b") {
		t.Fatal("different passphrases produced the same key")
	}
}

func BenchmarkMACSum(b *testing.B) {
	mac := NewMAC(DeriveKey("passphrase"))
	msg := make([]byte, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mac.Sum(msg)
	}
}
