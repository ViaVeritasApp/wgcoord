package coordinator

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"wgcoord/internal/acl"
	"wgcoord/internal/config"
)

// ErrGrantNeedsHubOnly is returned when grants are given to a mesh client.
var ErrGrantNeedsHubOnly = errors.New("--grant needs --hub-only; mesh clients reach every node directly, so grants can't be enforced")

// GrantAdd gives a hub-only client access to targets (CIDRs, group names or
// "all"), optionally limited to ports. It returns the grants added and
// warnings for targets the mesh only partly routes.
func (s *Store) GrantAdd(client string, targets, ports []string) ([]config.Grant, []string, error) {
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("at least one CIDR or group is required")
	}
	canonPorts, err := acl.CanonPorts(ports)
	if err != nil {
		return nil, nil, err
	}
	var added []config.Grant
	var warnings []string
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		c := findByName(cc, client)
		if c == nil {
			return notFound(client)
		}
		if !c.HubOnly {
			return fmt.Errorf("%q is a mesh client and reaches every node directly, so grants can't be enforced; switch it first with `wgcoord coordinator client mode %s hub-only`", c.Name, c.Name)
		}
		added, warnings, err = addGrants(cc, c, targets, canonPorts)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return added, warnings, nil
}

// addGrants validates and appends grants to c inside a mutation.
func addGrants(cc *config.CoordinatorConfig, c *config.Client, targets, canonPorts []string) ([]config.Grant, []string, error) {
	rt := routable(cc)
	var added []config.Grant
	var warnings []string
	for _, t := range targets {
		target, err := grantTarget(cc, t)
		if err != nil {
			return nil, nil, err
		}
		g := config.Grant{Target: target, Ports: canonPorts}
		if hasGrant(c, g) {
			continue
		}
		warn, err := checkGrant(cc, g, rt)
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, warn...)
		c.Grants = append(c.Grants, g)
		added = append(added, g)
	}
	if len(added) > 0 {
		c.UpdatedAt = nowRFC3339()
	}
	return added, warnings, nil
}

func grantTarget(cc *config.CoordinatorConfig, t string) (string, error) {
	if strings.TrimSpace(t) == GrantAll {
		return GrantAll, nil
	}
	return canonRef(cc, t)
}

func hasGrant(c *config.Client, g config.Grant) bool {
	for _, x := range c.Grants {
		if x.Target == g.Target && strings.Join(x.Ports, ",") == strings.Join(g.Ports, ",") {
			return true
		}
	}
	return false
}

// checkGrant rejects a grant that reaches nothing the mesh routes and warns
// about the parts of it that are not routed.
func checkGrant(cc *config.CoordinatorConfig, g config.Grant, rt []netip.Prefix) ([]string, error) {
	rules := grantRules(cc, g, rt)
	if len(rules) == 0 {
		if grp := findGroup(cc, g.Target); grp != nil && len(grp.Entries) > 0 {
			return nil, fmt.Errorf("grant %s allows no traffic: its ports don't overlap the ports of group %q", grantLabel(g), g.Target)
		}
		return nil, fmt.Errorf("grant %s is empty; add entries to the group first", grantLabel(g))
	}
	var warnings []string
	reaches := false
	for _, r := range rules {
		pieces, full := acl.Cover(r.Prefix, rt)
		if len(pieces) > 0 {
			reaches = true
		}
		if !full && len(pieces) > 0 {
			warnings = append(warnings, fmt.Sprintf("only part of %s is routed by the mesh; %s reaches %s", r.Prefix, grantLabel(g), prefixList(pieces)))
		} else if len(pieces) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s (from %s) is not routed by any node and is ignored", r.Prefix, grantLabel(g)))
		}
	}
	if !reaches {
		return nil, fmt.Errorf("grant %s reaches nothing the mesh routes; add a route for it first (for a network next to the coordinator: wgcoord coordinator route add coordinator <cidr> --nat)", grantLabel(g))
	}
	return warnings, nil
}

// GrantRemove revokes every grant of client whose target matches one of
// targets, whatever its ports. It returns the labels of the grants removed.
func (s *Store) GrantRemove(client string, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one CIDR or group is required")
	}
	var removed []string
	err := s.Mutate(func(cc *config.CoordinatorConfig) error {
		c := findByName(cc, client)
		if c == nil {
			return notFound(client)
		}
		drop := map[string]bool{}
		for _, t := range targets {
			t = strings.TrimSpace(t)
			if p, err := netip.ParsePrefix(t); err == nil {
				t = p.Masked().String()
			}
			drop[t] = true
		}
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if drop[g.Target] {
				removed = append(removed, grantLabel(g))
				continue
			}
			kept = append(kept, g)
		}
		c.Grants = kept
		if len(c.Grants) == 0 {
			c.Grants = nil
		}
		if len(removed) > 0 {
			c.UpdatedAt = nowRFC3339()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// SetMode switches a client between mesh and hub-only. Leaving hub-only while
// grants exist needs clearGrants, so widening access is always deliberate.
// changed is false when the client was already in that mode.
func (s *Store) SetMode(name string, hubOnly, clearGrants bool) (changed bool, err error) {
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		c := findByName(cc, name)
		if c == nil {
			return notFound(name)
		}
		if c.HubOnly == hubOnly {
			return nil
		}
		if hubOnly && len(c.Routes) > 0 {
			return fmt.Errorf("%q carries routes (%s); hub-only clients can't, so remove them first with `wgcoord coordinator route remove %s ...`", c.Name, strings.Join(c.Routes, ", "), c.Name)
		}
		if !hubOnly && len(c.Grants) > 0 {
			if !clearGrants {
				return fmt.Errorf("%q has grants; as a mesh client it would reach every node. Pass --clear-grants to switch anyway", c.Name)
			}
			c.Grants = nil
		}
		c.HubOnly = hubOnly
		c.SentHub = ""
		now := nowRFC3339()
		c.UpdatedAt = now
		cc.UpdatedAt = now // the hub's AllowedIPs gain or lose this client's /32
		changed = true
		return nil
	})
	return changed, err
}

func grantLabel(g config.Grant) string {
	if len(g.Ports) == 0 {
		return g.Target
	}
	return g.Target + " (" + strings.Join(g.Ports, ", ") + ")"
}

func prefixList(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ", ")
}

// GrantView is one grant as shown to the operator, with what it resolves to.
type GrantView struct {
	Label   string
	Reaches []string // "10.42.1.0/24 tcp/8080"
}

// DescribeGrants resolves each of c's grants for display.
func DescribeGrants(cc *config.CoordinatorConfig, c *config.Client) []GrantView {
	rt := routable(cc)
	out := make([]GrantView, 0, len(c.Grants))
	for _, g := range c.Grants {
		v := GrantView{Label: grantLabel(g)}
		seen := map[string]bool{}
		for _, r := range grantRules(cc, g, rt) {
			pieces, _ := acl.Cover(r.Prefix, rt)
			for _, p := range pieces {
				k := ruleKey(acl.Rule{Prefix: p, Ports: r.Ports})
				if !seen[k] {
					seen[k] = true
					v.Reaches = append(v.Reaches, k)
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// ResolveRoutes exposes route resolution for display.
func ResolveRoutes(cc *config.CoordinatorConfig, refs []string) []string {
	return resolveRoutes(cc, refs)
}
