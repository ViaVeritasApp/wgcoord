// Package firewall renders and applies the coordinator's nftables table. It
// limits what hub-only clients can open through the hub to their grants, and
// masquerades mesh traffic into networks that sit next to the coordinator
// (NAT routes).
//
// Everything lives in one table, "inet wgcoord", replaced atomically on each
// apply, so wgcoord never touches rules it does not own.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"wgcoord/internal/acl"
)

// Table is the nftables table wgcoord owns, in the inet family.
const Table = "wgcoord"

// Client is one hub-only client: its mesh address and what it may open.
type Client struct {
	Name  string
	Addr  netip.Addr
	Rules []acl.Rule
}

// Spec is the full desired firewall state of the coordinator.
type Spec struct {
	Interface   string       // WireGuard interface, e.g. wg0
	Hub         netip.Addr   // the coordinator's mesh address
	ControlPort int          // always reachable by hub-only clients
	Mesh        netip.Prefix // the mesh range, the source of masqueraded traffic
	Clients     []Client
	NAT         []netip.Prefix // destinations next to the coordinator
}

// Empty reports whether there is nothing to enforce.
func (s Spec) Empty() bool { return len(s.Clients) == 0 && len(s.NAT) == 0 }

// NeedsIPv6 reports whether any address in the spec is IPv6, so IPv6
// forwarding must be on as well.
func (s Spec) NeedsIPv6() bool {
	if s.Mesh.IsValid() && s.Mesh.Addr().Is6() {
		return true
	}
	for _, p := range s.NAT {
		if p.Addr().Is6() {
			return true
		}
	}
	for _, c := range s.Clients {
		for _, r := range c.Rules {
			if r.Prefix.Addr().Is6() {
				return true
			}
		}
	}
	return false
}

// Render produces an `nft -f` script that replaces the wgcoord table in one
// transaction. The first line creates the table if it is missing, so the
// delete that follows always succeeds.
//
// Hub-only traffic is filtered in prerouting, before any DNAT (Kubernetes
// ServiceLB, kube-proxy), so rules match the address and port the client
// actually asked for, whether the hub delivers the packet locally or forwards
// it. Replies to connections someone else opened are always allowed.
func Render(s Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	if len(s.Clients) > 0 {
		b.WriteString("\tchain hub_only {\n")
		b.WriteString("\t\ttype filter hook prerouting priority -110; policy accept;\n")
		for i, c := range s.Clients {
			fmt.Fprintf(&b, "\t\tiifname %q %s saddr %s jump client_%d comment %q\n",
				s.Interface, family(c.Addr), c.Addr, i, comment(c.Name))
		}
		b.WriteString("\t}\n")
		for i, c := range s.Clients {
			fmt.Fprintf(&b, "\tchain client_%d {\n", i)
			b.WriteString("\t\tct state established,related accept\n")
			if s.Hub.IsValid() {
				hf := family(s.Hub)
				if s.ControlPort > 0 {
					fmt.Fprintf(&b, "\t\t%s daddr %s tcp dport %d accept\n", hf, s.Hub, s.ControlPort)
				}
				if s.Hub.Is4() {
					fmt.Fprintf(&b, "\t\tip daddr %s icmp type echo-request accept\n", s.Hub)
				} else {
					fmt.Fprintf(&b, "\t\tip6 daddr %s icmpv6 type echo-request accept\n", s.Hub)
				}
			}
			for _, r := range c.Rules {
				for _, line := range ruleLines(r) {
					fmt.Fprintf(&b, "\t\t%s accept\n", line)
				}
			}
			b.WriteString("\t\tcounter drop\n\t}\n")
		}
	}
	if len(s.NAT) > 0 && s.Mesh.IsValid() {
		b.WriteString("\tchain nat_routes {\n")
		b.WriteString("\t\ttype nat hook postrouting priority 100; policy accept;\n")
		mf := family(s.Mesh.Addr())
		for _, p := range s.NAT {
			if family(p.Addr()) != mf {
				continue
			}
			fmt.Fprintf(&b, "\t\toifname != %q %s saddr %s %s daddr %s masquerade\n", s.Interface, mf, s.Mesh, mf, p)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// ruleLines renders one rule as nft match expressions, one line per port
// range (or one line with no port match when the rule allows everything).
func ruleLines(r acl.Rule) []string {
	dst := fmt.Sprintf("%s daddr %s", family(r.Prefix.Addr()), r.Prefix)
	if len(r.Ports) == 0 {
		return []string{dst}
	}
	out := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		switch {
		case p.Whole():
			out = append(out, fmt.Sprintf("%s meta l4proto %s", dst, p.Proto))
		case p.From == p.To:
			out = append(out, fmt.Sprintf("%s %s dport %d", dst, p.Proto, p.From))
		default:
			out = append(out, fmt.Sprintf("%s %s dport %d-%d", dst, p.Proto, p.From, p.To))
		}
	}
	return out
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

// comment keeps a client name safe inside an nft string literal.
func comment(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' || r == ' ' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

// ErrUnsupported means the coordinator cannot enforce grants on this host.
var ErrUnsupported = errors.New("hub-only clients need a Linux coordinator with nftables (`nft`)")

// Available reports whether the table can be applied here.
func Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("nft")
	return err == nil
}

// runNft feeds a script to `nft -f -`; replaced in tests.
var runNft = func(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply installs s, or removes the table when s is empty.
func Apply(s Spec) error {
	if !Available() {
		return ErrUnsupported
	}
	if s.Empty() {
		return Remove()
	}
	return runNft(Render(s))
}

// Remove deletes the wgcoord table if it exists.
func Remove() error {
	if !Available() {
		return nil
	}
	return runNft(fmt.Sprintf("table inet %s\ndelete table inet %s\n", Table, Table))
}

// procSys is where forwarding sysctls live; replaced in tests.
var procSys = "/proc/sys"

// EnableForwarding turns on IPv4 (and optionally IPv6) forwarding, which the
// hub needs to pass hub-only and NAT traffic on. It reports whether anything
// had to change. It never turns forwarding off: other software on the host
// (Kubernetes, Docker) may rely on it.
func EnableForwarding(v6 bool) (bool, error) {
	paths := []string{procSys + "/net/ipv4/ip_forward"}
	if v6 {
		paths = append(paths, procSys+"/net/ipv6/conf/all/forwarding")
	}
	changed := false
	for _, p := range paths {
		cur, err := os.ReadFile(p)
		if err != nil {
			return changed, err
		}
		if strings.TrimSpace(string(cur)) == "1" {
			continue
		}
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			return changed, fmt.Errorf("enable forwarding (%s): %w", p, err)
		}
		changed = true
	}
	return changed, nil
}
