package valid

import (
	"strings"
	"testing"
)

func TestEndpointHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		ok   bool
	}{
		{"ipv4 literal", "203.0.113.10", true},
		{"ipv6 literal", "2001:db8::1", true},
		{"dns hostname", "vpn.viaveritas.app", true},
		{"hostname with hyphen", "wg-gateway-1.example", true},
		{"empty", "", false},
		{"newline injection", "1.2.3.4\nPersistentKeepalive = 1", false},
		{"carriage return", "host\rEndpoint = evil", false},
		{"space", "1.2.3.4 evil", false},
		{"colon (port smuggling)", "1.2.3.4:51820", false},
		{"underscore not allowed in host", "bad_host.example", false},
		{"slash", "host/../etc", false},
		{"null byte", "host\x00", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := EndpointHost(c.host)
			if c.ok && err != nil {
				t.Errorf("EndpointHost(%q) = %v; want nil", c.host, err)
			}
			if !c.ok && err == nil {
				t.Errorf("EndpointHost(%q) = nil; want error", c.host)
			}
		})
	}
}

func TestEndpointHostTooLong(t *testing.T) {
	if err := EndpointHost(strings.Repeat("a", 254)); err == nil {
		t.Error("expected error for 254-char host")
	}
	if err := EndpointHost(strings.Repeat("a", 253)); err != nil {
		t.Errorf("253-char host should be accepted: %v", err)
	}
}

func TestEndpointOverride(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"bare lan ip", "192.168.1.50", true},
		{"host and port", "192.168.1.50:51820", true},
		{"hostname", "pve-node2.lan", true},
		{"bracketed ipv6 with port", "[2001:db8::1]:51820", true},
		{"bare ipv6", "2001:db8::1", true},
		{"suppress endpoint", "-", true},
		{"empty", "", false},
		{"port zero", "192.168.1.50:0", false},
		{"port out of range", "192.168.1.50:70000", false},
		{"non-numeric port", "192.168.1.50:wg", false},
		{"unbracketed ipv6 with port", "2001:db8::1:51820", false}, // ambiguous; reads as a bare v6
		{"newline injection", "192.168.1.50\nEndpoint = evil", false},
		{"space", "192.168.1.50 evil", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := EndpointOverride(c.in)
			if c.ok && err != nil {
				t.Errorf("EndpointOverride(%q) = %v; want nil", c.in, err)
			}
			if !c.ok && err == nil {
				t.Errorf("EndpointOverride(%q) = nil; want error", c.in)
			}
		})
	}
}

func TestInterfaceName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"typical", "wg0", true},
		{"with hyphen", "wg-mesh", true},
		{"15 chars ok", "wg0123456789abc", true},
		{"empty", "", false},
		{"16 chars too long", "wg0123456789abcd", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"slash", "wg/0", false},
		{"space", "wg 0", false},
		{"newline", "wg0\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := InterfaceName(c.in)
			if c.ok && err != nil {
				t.Errorf("InterfaceName(%q) = %v; want nil", c.in, err)
			}
			if !c.ok && err == nil {
				t.Errorf("InterfaceName(%q) = nil; want error", c.in)
			}
		})
	}
}

func TestHasControlChars(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"clean-value", false},
		{"AbcDef123+/=", false},
		{"line\nbreak", true},
		{"carriage\rreturn", true},
		{"tab\there", true},
		{"null\x00byte", true},
	}
	for _, c := range cases {
		if got := HasControlChars(c.in); got != c.want {
			t.Errorf("HasControlChars(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}
