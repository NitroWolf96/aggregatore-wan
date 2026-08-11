package wgbridge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key is a WireGuard Curve25519 key, serialized as base64 like standard
// WireGuard tooling.
type Key [32]byte

// GeneratePrivateKey returns a fresh clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	// Standard Curve25519 clamping.
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return k, nil
}

// PublicKey derives the public key of a private key.
func (k Key) PublicKey() (Key, error) {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, err
	}
	var out Key
	copy(out[:], pub)
	return out, nil
}

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(raw) != 32 {
		return Key{}, fmt.Errorf("invalid key length %d", len(raw))
	}
	var k Key
	copy(k[:], raw)
	return k, nil
}

// String returns the base64 form.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the hex form used by the WireGuard UAPI.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }
