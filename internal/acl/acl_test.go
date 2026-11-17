package acl

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePort(t *testing.T) {
	good := map[string]string{
		"tcp/5432":      "tcp/5432",
		" tcp/80 ":      "tcp/80",
		"TCP/443":       "tcp/443",
		"udp/53":        "udp/53",
		"tcp/8000-8100": "tcp/8000-8100",
		"tcp/8000-8000": "tcp/8000",
		"tcp":           "tcp",
		"udp":           "udp",
		"tcp/1-65535":   "tcp",
		"udp/65535":     "udp/65535",
	}
	for in, want := range good {
		p, err := ParsePort(in)
		if err != nil {
			t.Errorf("ParsePort(%q) error: %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("ParsePort(%q) = %q; want %q", in, p.String(), want)
		}
	}
	for _, in := range []string{"", "tcp/", "tcp/0", "tcp/70000", "tcp/9-5", "icmp/1", "5432", "tcp/abc", "tcp/1-", "tcp/-5", "sctp"} {
		if _, err := ParsePort(in); err == nil {
			t.Errorf("ParsePort(%q) should fail", in)
		}
	}
}

func TestCanonPorts(t *testing.T) {
	got, err := CanonPorts([]string{"udp/53", "tcp/5432", "tcp/80", "tcp/5432"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcp/80", "tcp/5432", "udp/53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CanonPorts = %v; want %v", got, want)
	}
	if got, _ := CanonPorts(nil); got != nil {
		t.Fatalf("CanonPorts(nil) = %v; want nil", got)
	}
}

func mustPorts(t *testing.T, ss ...string) []PortRange {
	t.Helper()
	out, err := ParsePorts(ss)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntersectPorts(t *testing.T) {
	pg := mustPorts(t, "tcp/5432")
	if out, ok := IntersectPorts(pg, nil); !ok || len(out) != 1 || out[0].String() != "tcp/5432" {
		t.Fatalf("with nil = %v %v", out, ok)
	}
	if out, ok := IntersectPorts(nil, nil); !ok || out != nil {
		t.Fatalf("nil,nil = %v %v; want nil,true", out, ok)
	}
	if out, ok := IntersectPorts(pg, mustPorts(t, "tcp/5000-6000")); !ok || len(out) != 1 || out[0].String() != "tcp/5432" {
		t.Fatalf("narrowing = %v %v", out, ok)
	}
	if out, ok := IntersectPorts(pg, mustPorts(t, "udp/53")); ok || out != nil {
		t.Fatalf("disjoint = %v %v; want not ok", out, ok)
	}
	if out, ok := IntersectPorts(mustPorts(t, "tcp"), mustPorts(t, "tcp/80", "udp/53")); !ok || len(out) != 1 || out[0].String() != "tcp/80" {
		t.Fatalf("whole proto = %v %v", out, ok)
	}
	if out, ok := IntersectPorts(mustPorts(t, "tcp/100-200"), mustPorts(t, "tcp/150-300")); !ok || out[0].String() != "tcp/150-200" {
		t.Fatalf("overlap = %v %v", out, ok)
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestCover(t *testing.T) {
	pieces, full := Cover(pfx("10.42.0.0/16"), []netip.Prefix{pfx("10.42.0.0/24"), pfx("10.42.1.0/24"), pfx("10.99.0.0/24")})
	if full || !reflect.DeepEqual(pieces, []netip.Prefix{pfx("10.42.0.0/24"), pfx("10.42.1.0/24")}) {
		t.Fatalf("partial = %v %v", pieces, full)
	}
	pieces, full = Cover(pfx("10.42.1.0/24"), []netip.Prefix{pfx("10.42.0.0/16")})
	if !full || !reflect.DeepEqual(pieces, []netip.Prefix{pfx("10.42.1.0/24")}) {
		t.Fatalf("contained = %v %v", pieces, full)
	}
	pieces, full = Cover(pfx("10.0.0.0/24"), []netip.Prefix{pfx("10.0.0.0/25"), pfx("10.0.0.128/25")})
	if !full || len(pieces) != 2 {
		t.Fatalf("two halves = %v %v; want full", pieces, full)
	}
	if pieces, full = Cover(pfx("192.168.0.0/24"), []netip.Prefix{pfx("10.0.0.0/8")}); full || pieces != nil {
		t.Fatalf("disjoint = %v %v", pieces, full)
	}
	if pieces, _ = Cover(pfx("10.0.0.0/24"), []netip.Prefix{pfx("fd00::/8")}); pieces != nil {
		t.Fatalf("mixed families = %v", pieces)
	}
}

func TestMinimal(t *testing.T) {
	got := Minimal([]netip.Prefix{pfx("10.42.1.0/24"), pfx("10.42.0.0/16"), pfx("10.8.0.5/32"), pfx("10.42.0.0/16")})
	want := []netip.Prefix{pfx("10.8.0.5/32"), pfx("10.42.0.0/16")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Minimal = %v; want %v", got, want)
	}
}

func TestIntersectPrefix(t *testing.T) {
	if p, ok := IntersectPrefix(pfx("10.0.0.0/8"), pfx("10.1.0.0/16")); !ok || p != pfx("10.1.0.0/16") {
		t.Fatalf("got %v %v", p, ok)
	}
	if _, ok := IntersectPrefix(pfx("10.0.0.0/16"), pfx("10.1.0.0/16")); ok {
		t.Fatal("disjoint should not intersect")
	}
}
