package coordinator

import (
	"net/netip"
	"strings"

	"wgcoord/internal/acl"
	"wgcoord/internal/config"
)

// GrantAll is the grant target meaning the mesh range plus every route,
// tracked as routes come and go.
const GrantAll = "all"

// isCIDRRef reports whether a stored route/grant reference is a literal CIDR
// rather than a group name. Group names can never parse as a prefix.
func isCIDRRef(ref string) bool {
	_, err := netip.ParsePrefix(ref)
	return err == nil
}

func findGroup(cc *config.CoordinatorConfig, name string) *config.Group {
	for _, g := range cc.Groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// resolveRoutes expands route references (CIDRs and group names) into the
// CIDRs they stand for, deduplicated in order. A group that no longer exists
// contributes nothing.
func resolveRoutes(cc *config.CoordinatorConfig, refs []string) []string {
	if len(refs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(refs))
	var out []string
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, ref := range refs {
		if isCIDRRef(ref) {
			add(ref)
			continue
		}
		if g := findGroup(cc, ref); g != nil {
			for _, e := range g.Entries {
				add(e.CIDR)
			}
		}
	}
	return out
}

// meshPrefix is the mesh address pool as a prefix.
func meshPrefix(cc *config.CoordinatorConfig) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(cc.IPRange)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// routable is everything a packet forwarded by the hub can reach: the mesh
// range and every route carried by the hub or a live mesh client.
func routable(cc *config.CoordinatorConfig) []netip.Prefix {
	var out []netip.Prefix
	if m, ok := meshPrefix(cc); ok {
		out = append(out, m)
	}
	addAll := func(refs []string) {
		for _, r := range resolveRoutes(cc, refs) {
			if p, err := netip.ParsePrefix(r); err == nil {
				out = append(out, p)
			}
		}
	}
	addAll(cc.Routes)
	for _, c := range cc.Clients {
		if c.Blacklisted || c.HubOnly {
			continue
		}
		addAll(c.Routes)
	}
	return out
}

// grantRules expands one grant into raw rules, before cutting them down to
// what is routable. Port constraints from the grant and from group entries
// are intersected; an entry whose ports don't overlap the grant's drops out.
func grantRules(cc *config.CoordinatorConfig, g config.Grant, rt []netip.Prefix) []acl.Rule {
	ports, err := acl.ParsePorts(g.Ports)
	if err != nil {
		return nil // stored canonical; unreachable unless the file was hand-edited badly
	}
	switch {
	case g.Target == GrantAll:
		out := make([]acl.Rule, 0, len(rt))
		for _, p := range rt {
			out = append(out, acl.Rule{Prefix: p, Ports: ports})
		}
		return out
	case isCIDRRef(g.Target):
		return []acl.Rule{{Prefix: netip.MustParsePrefix(g.Target).Masked(), Ports: ports}}
	}
	grp := findGroup(cc, g.Target)
	if grp == nil {
		return nil
	}
	var out []acl.Rule
	for _, e := range grp.Entries {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		ep, err := acl.ParsePorts(e.Ports)
		if err != nil {
			continue
		}
		both, ok := acl.IntersectPorts(ep, ports)
		if !ok {
			continue
		}
		out = append(out, acl.Rule{Prefix: p.Masked(), Ports: both})
	}
	return out
}

// effectiveRules is what a hub-only client may actually reach: its grants
// resolved and cut down to routable prefixes, deduplicated.
func effectiveRules(cc *config.CoordinatorConfig, c *config.Client) []acl.Rule {
	rt := routable(cc)
	seen := map[string]bool{}
	var out []acl.Rule
	for _, g := range c.Grants {
		for _, r := range grantRules(cc, g, rt) {
			pieces, _ := acl.Cover(r.Prefix, rt)
			for _, p := range pieces {
				rule := acl.Rule{Prefix: p, Ports: r.Ports}
				if k := ruleKey(rule); !seen[k] {
					seen[k] = true
					out = append(out, rule)
				}
			}
		}
	}
	return out
}

func ruleKey(r acl.Rule) string {
	var b strings.Builder
	b.WriteString(r.Prefix.String())
	for _, p := range r.Ports {
		b.WriteByte(' ')
		b.WriteString(p.String())
	}
	return b.String()
}

// hubPeerAllowed is the AllowedIPs of the coordinator peer as advertised to
// forClient (nil means a mesh client).
//
// A hub-only client sends the whole mesh range to the hub, so replies to any
// mesh member find their way back, plus each granted prefix outside the mesh.
// What it may open is decided by the hub's firewall, not by this list.
//
// A mesh client sends the hub its own address and routes, plus the address of
// every hub-only client, since the hub forwards their traffic and must also
// receive the replies.
func hubPeerAllowed(cc *config.CoordinatorConfig, forClient *config.Client) []string {
	if forClient != nil && forClient.HubOnly {
		mesh, ok := meshPrefix(cc)
		var ps []netip.Prefix
		if ok {
			ps = append(ps, mesh)
		}
		for _, r := range effectiveRules(cc, forClient) {
			if ok && mesh.Bits() <= r.Prefix.Bits() && mesh.Contains(r.Prefix.Addr()) {
				continue // already inside the mesh range
			}
			ps = append(ps, r.Prefix)
		}
		ps = acl.Minimal(ps)
		out := make([]string, 0, len(ps))
		for _, p := range ps {
			out = append(out, p.String())
		}
		return out
	}
	out := allowedIPs(cc.Address, resolveRoutes(cc, cc.Routes))
	for _, c := range cc.Clients {
		if c.HubOnly && !c.Blacklisted && c.Address != "" {
			out = append(out, c.Address+"/32")
		}
	}
	return out
}

// hubOnlyClients returns the non-blacklisted hub-only clients.
func hubOnlyClients(cc *config.CoordinatorConfig) []*config.Client {
	var out []*config.Client
	for _, c := range cc.Clients {
		if c.HubOnly && !c.Blacklisted {
			out = append(out, c)
		}
	}
	return out
}
