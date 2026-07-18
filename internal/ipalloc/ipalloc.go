// Package ipalloc hands out mesh addresses from a CIDR pool, tracking bare host
// IPs and skipping the network and (IPv4) broadcast addresses.
package ipalloc

import (
	"fmt"
	"net/netip"
)

// PrefixBits returns the mask length of a CIDR (e.g. 24 for 10.8.0.0/24).
func PrefixBits(cidr string) (int, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid ip range %q: %w", cidr, err)
	}
	return p.Bits(), nil
}

// FirstHost returns the lowest usable host address of cidr (the address after
// the network address), used as the coordinator's own mesh IP by default.
func FirstHost(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid ip range %q: %w", cidr, err)
	}
	return prefix.Masked().Addr().Next().String(), nil
}

// Usable reports whether addr is a valid host address of cidr: inside the
// prefix, and neither the network nor (for IPv4) the broadcast address.
func Usable(cidr, addr string) (bool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid ip range %q: %w", cidr, err)
	}
	prefix = prefix.Masked()
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if !prefix.Contains(a) || a == prefix.Addr() {
		return false, nil
	}
	if prefix.Addr().Is4() && a == lastAddr(prefix) {
		return false, nil
	}
	return true, nil
}

// NextFree returns the lowest usable host address in cidr not present in used.
func NextFree(cidr string, used []string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid ip range %q: %w", cidr, err)
	}
	prefix = prefix.Masked()

	taken := make(map[netip.Addr]bool, len(used))
	for _, u := range used {
		if a, err := netip.ParseAddr(u); err == nil {
			taken[a] = true
		}
	}

	isV4 := prefix.Addr().Is4()
	last := lastAddr(prefix)
	addr := prefix.Addr().Next() // skip the network address (.0)
	for prefix.Contains(addr) {
		if isV4 && addr == last {
			break // reserve the broadcast address
		}
		if !taken[addr] {
			return addr.String(), nil
		}
		addr = addr.Next()
	}
	return "", fmt.Errorf("ip range %s is exhausted", cidr)
}

// lastAddr returns the highest address in a prefix (the IPv4 broadcast address).
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	if a.Is4() {
		v := a.As4()
		host := 32 - p.Bits()
		u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		if host >= 32 {
			u = 0xffffffff
		} else if host > 0 {
			u |= (uint32(1) << host) - 1
		}
		return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	}
	return a
}
