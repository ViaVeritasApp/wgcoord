// Package acl holds the pure building blocks of hub-only access control: port
// specs as typed on the command line, and the prefix arithmetic that cuts a
// grant down to what the mesh can actually route.
package acl

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// PortRange is one protocol plus an inclusive port range. From and To both 0
// means every port of the protocol.
type PortRange struct {
	Proto    string
	From, To uint16
}

// Whole reports whether the range covers every port of its protocol.
func (p PortRange) Whole() bool { return p.From == 0 && p.To == 0 }

// String renders the canonical form: "tcp", "tcp/5432" or "tcp/8000-8100".
func (p PortRange) String() string {
	switch {
	case p.Whole():
		return p.Proto
	case p.From == p.To:
		return fmt.Sprintf("%s/%d", p.Proto, p.From)
	default:
		return fmt.Sprintf("%s/%d-%d", p.Proto, p.From, p.To)
	}
}

func (p PortRange) bounds() (uint16, uint16) {
	if p.Whole() {
		return 1, 65535
	}
	return p.From, p.To
}

// ParsePort parses "tcp/5432", "udp/53", "tcp/8000-8100", "tcp" or "udp".
// A range spanning every port collapses to the bare protocol.
func ParsePort(s string) (PortRange, error) {
	raw := s
	s = strings.ToLower(strings.TrimSpace(s))
	proto, ports, hasPorts := strings.Cut(s, "/")
	if proto != "tcp" && proto != "udp" {
		return PortRange{}, fmt.Errorf("invalid port %q (want tcp/5432, udp/53, tcp/8000-8100, tcp or udp)", raw)
	}
	if !hasPorts {
		return PortRange{Proto: proto}, nil
	}
	lo, hi, isRange := strings.Cut(ports, "-")
	from, err := portNum(lo)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port %q: %w", raw, err)
	}
	to := from
	if isRange {
		if to, err = portNum(hi); err != nil {
			return PortRange{}, fmt.Errorf("invalid port %q: %w", raw, err)
		}
	}
	if to < from {
		return PortRange{}, fmt.Errorf("invalid port %q: range end is below its start", raw)
	}
	if from == 1 && to == 65535 {
		return PortRange{Proto: proto}, nil
	}
	return PortRange{Proto: proto, From: from, To: to}, nil
}

func portNum(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port must be 1-65535, got %q", s)
	}
	return uint16(n), nil
}

// ParsePorts parses every spec; nil or empty input is nil ("any port").
func ParsePorts(in []string) ([]PortRange, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]PortRange, 0, len(in))
	for _, s := range in {
		p, err := ParsePort(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return sortPorts(out), nil
}

// CanonPorts validates port specs and returns them canonical, sorted and
// deduplicated; nil when none are given.
func CanonPorts(in []string) ([]string, error) {
	ps, err := ParsePorts(in)
	if err != nil || ps == nil {
		return nil, err
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out, nil
}

// sortPorts orders by protocol then start port and drops exact duplicates.
func sortPorts(ps []PortRange) []PortRange {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Proto != ps[j].Proto {
			return ps[i].Proto < ps[j].Proto
		}
		fi, ti := ps[i].bounds()
		fj, tj := ps[j].bounds()
		if fi != fj {
			return fi < fj
		}
		return ti < tj
	})
	out := ps[:0]
	for i, p := range ps {
		if i > 0 && p == ps[i-1] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// IntersectPorts combines two port constraints that must both hold. nil means
// "any". ok is false when both constrain and nothing satisfies both.
func IntersectPorts(a, b []PortRange) ([]PortRange, bool) {
	if a == nil {
		return b, true
	}
	if b == nil {
		return a, true
	}
	var out []PortRange
	for _, x := range a {
		for _, y := range b {
			if x.Proto != y.Proto {
				continue
			}
			xf, xt := x.bounds()
			yf, yt := y.bounds()
			lo, hi := max(xf, yf), min(xt, yt)
			if lo > hi {
				continue
			}
			r := PortRange{Proto: x.Proto, From: lo, To: hi}
			if lo == 1 && hi == 65535 {
				r = PortRange{Proto: x.Proto}
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return sortPorts(out), true
}

// Rule is one destination a hub-only client may reach. Ports nil means every
// port and protocol.
type Rule struct {
	Prefix netip.Prefix
	Ports  []PortRange
}

// IntersectPrefix returns the overlap of two prefixes. CIDR blocks either nest
// or are disjoint, so the overlap is the narrower one, or nothing.
func IntersectPrefix(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Addr().Is4() != b.Addr().Is4() || !a.Overlaps(b) {
		return netip.Prefix{}, false
	}
	if a.Bits() >= b.Bits() {
		return a, true
	}
	return b, true
}

// Cover cuts p down to the parts that fall inside routable prefixes. full
// reports whether those parts add up to all of p.
func Cover(p netip.Prefix, routable []netip.Prefix) ([]netip.Prefix, bool) {
	var pieces []netip.Prefix
	for _, r := range routable {
		if x, ok := IntersectPrefix(p, r); ok {
			pieces = append(pieces, x)
		}
	}
	pieces = Minimal(pieces)
	if len(pieces) == 0 {
		return nil, false
	}
	total := new(big.Int)
	for _, x := range pieces {
		total.Add(total, size(x))
	}
	return pieces, total.Cmp(size(p)) == 0
}

func size(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// Minimal deduplicates prefixes, drops any nested inside another, and sorts
// the rest (IPv4 first, then by address).
func Minimal(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	sorted := append([]netip.Prefix(nil), ps...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Bits() != sorted[j].Bits() {
			return sorted[i].Bits() < sorted[j].Bits() // wider first
		}
		return sorted[i].Addr().Less(sorted[j].Addr())
	})
	var keep []netip.Prefix
	for _, p := range sorted {
		nested := false
		for _, k := range keep {
			if k.Addr().Is4() == p.Addr().Is4() && k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				nested = true
				break
			}
		}
		if !nested {
			keep = append(keep, p)
		}
	}
	sort.Slice(keep, func(i, j int) bool {
		if keep[i].Addr() != keep[j].Addr() {
			return keep[i].Addr().Less(keep[j].Addr())
		}
		return keep[i].Bits() < keep[j].Bits()
	})
	return keep
}
