// Package wgkey generates/validates WireGuard (Curve25519) keypairs via stdlib
// crypto/ecdh, in the canonical `wg genkey` form (32 clamped bytes, base64).
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type Pair struct {
	PrivateKey string
	PublicKey  string
}

// clamp applies Curve25519 scalar clamping so the stored key matches `wg genkey`.
func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// Generate returns a fresh clamped X25519 keypair.
func Generate() (Pair, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return Pair{}, err
	}
	clamp(seed)
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return Pair{}, err
	}
	return Pair{
		PrivateKey: base64.StdEncoding.EncodeToString(seed),
		PublicKey:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// PublicFromPrivate derives the base64 public key from a base64 private key.
func PublicFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// Valid reports whether s decodes to a 32-byte base64 WireGuard key.
func Valid(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}
