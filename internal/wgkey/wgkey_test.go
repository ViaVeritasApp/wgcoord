package wgkey

import (
	"encoding/base64"
	"testing"
)

func TestGenerateProducesValidPair(t *testing.T) {
	p, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !Valid(p.PrivateKey) {
		t.Errorf("private key not a valid 32-byte key: %q", p.PrivateKey)
	}
	if !Valid(p.PublicKey) {
		t.Errorf("public key not a valid 32-byte key: %q", p.PublicKey)
	}
	if p.PrivateKey == p.PublicKey {
		t.Error("private and public keys are identical")
	}

	// The stored private key must be clamped (matches `wg genkey`).
	raw, err := base64.StdEncoding.DecodeString(p.PrivateKey)
	if err != nil {
		t.Fatalf("decode private: %v", err)
	}
	if raw[0]&0b111 != 0 || raw[31]&0b1000_0000 != 0 || raw[31]&0b0100_0000 == 0 {
		t.Error("private key is not Curve25519-clamped")
	}
}

func TestGenerateIsRandom(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	if a.PrivateKey == b.PrivateKey {
		t.Error("two Generate calls returned the same private key")
	}
}

func TestPublicFromPrivateMatchesGenerate(t *testing.T) {
	p, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicFromPrivate(p.PrivateKey)
	if err != nil {
		t.Fatalf("PublicFromPrivate: %v", err)
	}
	if pub != p.PublicKey {
		t.Errorf("derived public %q != generated public %q", pub, p.PublicKey)
	}
}

func TestPublicFromPrivateRejectsGarbage(t *testing.T) {
	if _, err := PublicFromPrivate("not-base64!!"); err == nil {
		t.Error("expected error for non-base64 input")
	}
	if _, err := PublicFromPrivate(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for a key that isn't 32 bytes")
	}
}

func TestValid(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !Valid(good) {
		t.Error("Valid rejected a 32-byte base64 key")
	}
	if Valid(base64.StdEncoding.EncodeToString(make([]byte, 31))) {
		t.Error("Valid accepted a 31-byte key")
	}
	if Valid("!!!not base64") {
		t.Error("Valid accepted non-base64 input")
	}
	if Valid("") {
		t.Error("Valid accepted empty string")
	}
}
