// Package valid holds strict validators for values that get rendered into a
// WireGuard config file or used as command/path arguments, so untrusted input
// can't inject extra directives or escape a directory.
package valid

import (
	"fmt"
	"net/netip"
	"strings"
)

// EndpointHost validates a bare host/IP for a WireGuard Endpoint. IP literals
// (v4/v6) are accepted as-is; otherwise only DNS hostname characters are
// allowed. It rejects empty values and anything with whitespace, control
// characters, ':' or newlines — which is what prevents config-file injection.
func EndpointHost(h string) error {
	if h == "" {
		return fmt.Errorf("endpoint host is empty")
	}
	if len(h) > 253 {
		return fmt.Errorf("endpoint host too long")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return nil // valid IPv4/IPv6 literal
	}
	for _, r := range h {
		if r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return fmt.Errorf("invalid endpoint host %q", h)
	}
	return nil
}

// InterfaceName validates a WireGuard/Linux interface name: 1-15 chars, no path
// separators or other surprises.
func InterfaceName(n string) error {
	if n == "" || len(n) > 15 {
		return fmt.Errorf("interface name must be 1-15 characters")
	}
	for _, r := range n {
		if r == '_' || r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return fmt.Errorf("invalid interface name %q", n)
	}
	if n == "." || n == ".." {
		return fmt.Errorf("invalid interface name %q", n)
	}
	return nil
}

// HasControlChars reports whether s contains any CR/LF/other control character —
// a last-line defense before writing a value into a config file.
func HasControlChars(s string) bool {
	return strings.ContainsAny(s, "\r\n\t\x00")
}
