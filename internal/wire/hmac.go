package wire

import (
	"crypto/subtle"

	"golang.org/x/crypto/blake2s"
)

// KeySize is the size of the control-plane MAC key.
const KeySize = 32

// DeriveKey expands the shared control passphrase into a MAC key. The label
// binds the key to this protocol so the same passphrase reused elsewhere
// yields an unrelated key.
func DeriveKey(psk string) [KeySize]byte {
	return blake2s.Sum256([]byte("treccia-control-v1:" + psk))
}

// MAC signs and verifies control-plane messages with keyed BLAKE2s-128.
// It is safe for concurrent use.
type MAC struct {
	key [KeySize]byte
}

func NewMAC(key [KeySize]byte) *MAC { return &MAC{key: key} }

// Sum computes the MACSize-byte tag of msg.
func (m *MAC) Sum(msg []byte) [MACSize]byte {
	h, err := blake2s.New128(m.key[:])
	if err != nil {
		// KeySize is always a valid BLAKE2s key length.
		panic(err)
	}
	h.Write(msg)
	var tag [MACSize]byte
	h.Sum(tag[:0])
	return tag
}

// AppendTag appends the tag of buf to buf and returns the extended slice.
func (m *MAC) AppendTag(buf []byte) []byte {
	tag := m.Sum(buf)
	return append(buf, tag[:]...)
}

// Verify checks that buf ends with a valid tag and returns the message
// without it. The comparison is constant-time.
func (m *MAC) Verify(buf []byte) ([]byte, bool) {
	if len(buf) < MACSize {
		return nil, false
	}
	msg, got := buf[:len(buf)-MACSize], buf[len(buf)-MACSize:]
	want := m.Sum(msg)
	if subtle.ConstantTimeCompare(got, want[:]) != 1 {
		return nil, false
	}
	return msg, true
}
