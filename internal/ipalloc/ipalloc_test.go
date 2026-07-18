package ipalloc

import "testing"

func TestPrefixBits(t *testing.T) {
	if bits, err := PrefixBits("10.8.0.0/24"); err != nil || bits != 24 {
		t.Errorf("PrefixBits(/24) = %d, %v; want 24, nil", bits, err)
	}
	if _, err := PrefixBits("not-a-cidr"); err == nil {
		t.Error("expected error for malformed CIDR")
	}
}

func TestFirstHost(t *testing.T) {
	cases := []struct{ cidr, want string }{
		{"10.8.0.0/24", "10.8.0.1"},
		{"10.8.0.0/16", "10.8.0.1"},
		{"192.168.5.0/24", "192.168.5.1"},
	}
	for _, c := range cases {
		got, err := FirstHost(c.cidr)
		if err != nil {
			t.Fatalf("FirstHost(%q): %v", c.cidr, err)
		}
		if got != c.want {
			t.Errorf("FirstHost(%q) = %q; want %q", c.cidr, got, c.want)
		}
	}
	if _, err := FirstHost("garbage"); err == nil {
		t.Error("expected error for malformed CIDR")
	}
}

func TestUsable(t *testing.T) {
	cases := []struct {
		name, addr string
		want       bool
	}{
		{"first host", "10.8.0.1", true},
		{"mid host", "10.8.0.42", true},
		{"last host", "10.8.0.254", true},
		{"network address", "10.8.0.0", false},
		{"broadcast address", "10.8.0.255", false},
		{"outside prefix", "10.9.0.1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Usable("10.8.0.0/24", c.addr)
			if err != nil {
				t.Fatalf("Usable(%q): %v", c.addr, err)
			}
			if got != c.want {
				t.Errorf("Usable(10.8.0.0/24, %q) = %v; want %v", c.addr, got, c.want)
			}
		})
	}
}

func TestUsableRejectsBadAddr(t *testing.T) {
	if _, err := Usable("10.8.0.0/24", "not-an-ip"); err == nil {
		t.Error("expected error for malformed address")
	}
}

func TestNextFree(t *testing.T) {
	// Empty pool → first usable host.
	if got, err := NextFree("10.8.0.0/24", nil); err != nil || got != "10.8.0.1" {
		t.Errorf("NextFree(empty) = %q, %v; want 10.8.0.1, nil", got, err)
	}
	// Skips taken addresses, ignoring gaps out of order.
	if got, err := NextFree("10.8.0.0/24", []string{"10.8.0.1", "10.8.0.3", "10.8.0.2"}); err != nil || got != "10.8.0.4" {
		t.Errorf("NextFree(1,2,3 taken) = %q, %v; want 10.8.0.4, nil", got, err)
	}
	// Garbage entries in `used` are ignored, not fatal.
	if got, err := NextFree("10.8.0.0/24", []string{"junk", "10.8.0.1"}); err != nil || got != "10.8.0.2" {
		t.Errorf("NextFree(junk,1) = %q, %v; want 10.8.0.2, nil", got, err)
	}
}

func TestNextFreeExhaustion(t *testing.T) {
	// /30 has host addresses .1 and .2 only (.0 network, .3 broadcast).
	used := []string{"10.8.0.1", "10.8.0.2"}
	if _, err := NextFree("10.8.0.0/30", used); err == nil {
		t.Error("expected exhaustion error when every host address is taken")
	}
}
