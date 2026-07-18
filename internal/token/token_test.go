package token

import "testing"

func TestGenerateUniqueAndDecodable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if tok == "" {
			t.Fatal("Generate returned empty token")
		}
		if seen[tok] {
			t.Fatalf("Generate produced a duplicate token: %q", tok)
		}
		seen[tok] = true
	}
}

func TestHashIsDeterministic(t *testing.T) {
	h1 := Hash("s3cret-token")
	h2 := Hash("s3cret-token")
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 { // hex-encoded SHA-256
		t.Errorf("Hash length = %d; want 64 hex chars", len(h1))
	}
	if Hash("other") == h1 {
		t.Error("distinct inputs produced the same hash")
	}
}

func TestEqual(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	stored := Hash(tok)

	if !Equal(tok, stored) {
		t.Error("Equal(correct token, its hash) = false; want true")
	}
	if Equal(tok+"x", stored) {
		t.Error("Equal(wrong token, hash) = true; want false")
	}
	if Equal("", stored) {
		t.Error("Equal(empty, hash) = true; want false")
	}
	if Equal(tok, "") {
		t.Error("Equal(token, empty hash) = true; want false")
	}
}
