// Package token mints and verifies per-client auth tokens. Only a SHA-256 hash
// is stored; the plaintext is shown once at generation.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// Generate returns a new 256-bit URL-safe auth token.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash returns the hex SHA-256 of a token (plain hash is fine — tokens are
// already high-entropy, nothing to brute-force).
func Hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Equal reports whether a presented token matches a stored hash, comparing in
// constant time.
func Equal(presented, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(presented)), []byte(storedHash)) == 1
}
