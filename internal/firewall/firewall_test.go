package firewall

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wgcoord/internal/acl"
)

func rules(t *testing.T, specs ...[2]string) []acl.Rule {
	t.Helper()
	var out []acl.Rule
	for _, s := range specs {
		var ports []string
		if s[1] != "" {
			ports = strings.Split(s[1], ",")
		}
		ps, err := acl.ParsePorts(ports)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, acl.Rule{Prefix: netip.MustParsePrefix(s[0]), Ports: ps})
	}
	return out
}

func TestRender(t *testing.T) {
	spec := Spec{
		Interface:   "wg0",
		Hub:         netip.MustParseAddr("10.8.0.1"),
		ControlPort: 51821,
		Mesh:        netip.MustParsePrefix("10.8.0.0/24"),
		Clients: []Client{
			{Name: `alice"; drop`, Addr: netip.MustParseAddr("10.8.0.101"), Rules: rules(t,
				[2]string{"10.8.0.0/28", "tcp/15432,tcp/16379"},
				[2]string{"10.42.0.0/24", "tcp/8000-8100,udp"},
			)},
			{Name: "bob", Addr: netip.MustParseAddr("10.8.0.102"), Rules: rules(t, [2]string{"10.42.0.0/16", ""})},
		},
		NAT: []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")},
	}
	want := `table inet wgcoord
delete table inet wgcoord
table inet wgcoord {
	chain hub_only {
		type filter hook prerouting priority -110; policy accept;
		iifname "wg0" ip saddr 10.8.0.101 jump client_0 comment "alice drop"
		iifname "wg0" ip saddr 10.8.0.102 jump client_1 comment "bob"
	}
	chain client_0 {
		ct state established,related accept
		ip daddr 10.8.0.1 tcp dport 51821 accept
		ip daddr 10.8.0.1 icmp type echo-request accept
		ip daddr 10.8.0.0/28 tcp dport 15432 accept
		ip daddr 10.8.0.0/28 tcp dport 16379 accept
		ip daddr 10.42.0.0/24 tcp dport 8000-8100 accept
		ip daddr 10.42.0.0/24 meta l4proto udp accept
		counter drop
	}
	chain client_1 {
		ct state established,related accept
		ip daddr 10.8.0.1 tcp dport 51821 accept
		ip daddr 10.8.0.1 icmp type echo-request accept
		ip daddr 10.42.0.0/16 accept
		counter drop
	}
	chain nat_routes {
		type nat hook postrouting priority 100; policy accept;
		oifname != "wg0" ip saddr 10.8.0.0/24 ip daddr 172.30.0.0/24 masquerade
	}
}
`
	if got := Render(spec); got != want {
		t.Fatalf("Render mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderNATOnlyAndIPv6(t *testing.T) {
	got := Render(Spec{Interface: "wg0", Mesh: netip.MustParsePrefix("10.8.0.0/24"),
		NAT: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("fd00::/64")}})
	if strings.Contains(got, "hub_only") || !strings.Contains(got, "ip daddr 10.0.0.0/16 masquerade") || strings.Contains(got, "fd00") {
		t.Fatalf("NAT-only render:\n%s", got)
	}
	got = Render(Spec{Interface: "wg0", Hub: netip.MustParseAddr("fd10::1"), ControlPort: 51821,
		Clients: []Client{{Name: "c", Addr: netip.MustParseAddr("fd10::5"), Rules: rules(t, [2]string{"fd20::/64", "tcp/443"})}}})
	for _, want := range []string{"ip6 saddr fd10::5 jump", "ip6 daddr fd10::1 tcp dport 51821", "icmpv6 type echo-request", "ip6 daddr fd20::/64 tcp dport 443 accept"} {
		if !strings.Contains(got, want) {
			t.Errorf("IPv6 render lacks %q:\n%s", want, got)
		}
	}
}

func TestEnableForwarding(t *testing.T) {
	dir := t.TempDir()
	procSys = dir
	t.Cleanup(func() { procSys = "/proc/sys" })
	v4 := filepath.Join(dir, "net/ipv4/ip_forward")
	v6 := filepath.Join(dir, "net/ipv6/conf/all/forwarding")
	for _, p := range []string{v4, v6} {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("0\n"), 0o644)
	}
	changed, err := EnableForwarding(false)
	if err != nil || !changed {
		t.Fatalf("first enable: %v %v", changed, err)
	}
	if b, _ := os.ReadFile(v6); strings.TrimSpace(string(b)) != "0" {
		t.Fatal("IPv6 forwarding must not change unless asked")
	}
	if changed, _ := EnableForwarding(false); changed {
		t.Fatal("already-on forwarding should report no change")
	}
	if changed, _ := EnableForwarding(true); !changed {
		t.Fatal("IPv6 should have been enabled")
	}
}
