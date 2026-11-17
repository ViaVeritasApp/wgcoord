package coordinator

import (
	"fmt"
	"net/netip"
	"strings"

	"wgcoord/internal/acl"
	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/valid"
)

// validGroupName enforces names that can never be mistaken for an address:
// a leading letter, then letters, digits, '-' or '_', at most 63 characters,
// and none of the reserved words.
func validGroupName(name string) error {
	if name == "" || len(name) > 63 {
		return fmt.Errorf("group name must be 1-63 characters")
	}
	for i, r := range name {
		letter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if i == 0 && !letter {
			return fmt.Errorf("invalid group name %q: must start with a letter", name)
		}
		if !letter && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return fmt.Errorf("invalid group name %q: use letters, digits, '-' and '_'", name)
		}
	}
	switch strings.ToLower(name) {
	case GrantAll, api.CoordinatorPeerID, "hub":
		return fmt.Errorf("%q is reserved and can't be a group name", name)
	}
	return nil
}

// groupEntries validates CIDRs and ports into canonical entries, one per CIDR,
// each carrying the same ports.
func groupEntries(cidrs, ports []string) ([]config.GroupEntry, error) {
	canonPorts, err := acl.CanonPorts(ports)
	if err != nil {
		return nil, err
	}
	if len(cidrs) == 0 && len(canonPorts) > 0 {
		return nil, fmt.Errorf("--port needs at least one CIDR to apply to")
	}
	out := make([]config.GroupEntry, 0, len(cidrs))
	for _, c := range cidrs {
		canon, err := valid.CIDR(c)
		if err != nil {
			return nil, err
		}
		out = append(out, config.GroupEntry{CIDR: canon, Ports: canonPorts})
	}
	return out, nil
}

func entryKey(e config.GroupEntry) string {
	return e.CIDR + " " + strings.Join(e.Ports, ",")
}

// GroupCreate creates a named group, optionally with initial entries.
func (s *Store) GroupCreate(name string, cidrs, ports []string) (*config.Group, error) {
	name = strings.TrimSpace(name)
	if err := validGroupName(name); err != nil {
		return nil, err
	}
	entries, err := groupEntries(cidrs, ports)
	if err != nil {
		return nil, err
	}
	var created *config.Group
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		if findGroup(cc, name) != nil {
			return fmt.Errorf("a group named %q already exists", name)
		}
		g := &config.Group{Name: name, UpdatedAt: nowRFC3339()}
		for _, e := range entries {
			if !hasEntry(g, e) {
				g.Entries = append(g.Entries, e)
			}
		}
		cc.Groups = append(cc.Groups, g)
		created = g
		return nil
	})
	return created, err
}

func hasEntry(g *config.Group, e config.GroupEntry) bool {
	for _, x := range g.Entries {
		if entryKey(x) == entryKey(e) {
			return true
		}
	}
	return false
}

// GroupAdd appends entries to a group. A group used as a route must stay
// port-free and must not start routing a prefix another node already routes.
func (s *Store) GroupAdd(name string, cidrs, ports []string) ([]config.GroupEntry, error) {
	entries, err := groupEntries(cidrs, ports)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	var added []config.GroupEntry
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		g := findGroup(cc, name)
		if g == nil {
			return groupNotFound(name)
		}
		for _, e := range entries {
			if !hasEntry(g, e) {
				g.Entries = append(g.Entries, e)
				added = append(added, e)
			}
		}
		if len(added) == 0 {
			return nil
		}
		if err := checkAllRoutes(cc); err != nil {
			return err
		}
		touchGroup(cc, g)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}

// GroupRemove drops every entry for the given CIDRs, whatever their ports.
func (s *Store) GroupRemove(name string, cidrs []string) ([]string, error) {
	drop := map[string]bool{}
	for _, c := range cidrs {
		canon, err := valid.CIDR(c)
		if err != nil {
			return nil, err
		}
		drop[canon] = true
	}
	if len(drop) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	var removed []string
	err := s.Mutate(func(cc *config.CoordinatorConfig) error {
		g := findGroup(cc, name)
		if g == nil {
			return groupNotFound(name)
		}
		kept := g.Entries[:0]
		for _, e := range g.Entries {
			if drop[e.CIDR] {
				removed = append(removed, entryLabel(e))
				continue
			}
			kept = append(kept, e)
		}
		g.Entries = kept
		if len(removed) > 0 {
			touchGroup(cc, g)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// GroupDelete deletes a group that nothing uses any more.
func (s *Store) GroupDelete(name string) error {
	return s.Mutate(func(cc *config.CoordinatorConfig) error {
		if findGroup(cc, name) == nil {
			return groupNotFound(name)
		}
		if users := GroupUsers(cc, name); len(users) > 0 {
			return fmt.Errorf("group %q is still used by %s; remove those first", name, strings.Join(users, ", "))
		}
		for i, g := range cc.Groups {
			if g.Name == name {
				cc.Groups = append(cc.Groups[:i], cc.Groups[i+1:]...)
				break
			}
		}
		return nil
	})
}

// GroupUsers describes everything referencing a group, e.g. "route of node1"
// or "grant of alice".
func GroupUsers(cc *config.CoordinatorConfig, name string) []string {
	var out []string
	for _, r := range cc.Routes {
		if r == name {
			out = append(out, "route of coordinator")
		}
	}
	for _, c := range cc.Clients {
		for _, r := range c.Routes {
			if r == name {
				out = append(out, "route of "+c.Name)
			}
		}
		for _, g := range c.Grants {
			if g.Target == name {
				out = append(out, "grant of "+c.Name)
				break
			}
		}
	}
	return out
}

// touchGroup bumps the group and every node routing it, so mesh peers are
// re-sent the changed AllowedIPs. Hub-only clients compare their whole view
// on each heartbeat and need no bump.
func touchGroup(cc *config.CoordinatorConfig, g *config.Group) {
	g.UpdatedAt = nowRFC3339()
	for _, r := range cc.Routes {
		if r == g.Name {
			cc.UpdatedAt = g.UpdatedAt
		}
	}
	for _, c := range cc.Clients {
		for _, r := range c.Routes {
			if r == g.Name {
				c.UpdatedAt = g.UpdatedAt
			}
		}
	}
}

func entryLabel(e config.GroupEntry) string {
	if len(e.Ports) == 0 {
		return e.CIDR
	}
	return e.CIDR + " (" + strings.Join(e.Ports, ", ") + ")"
}

func groupNotFound(name string) error { return fmt.Errorf("no group named %q", name) }

// canonRef turns a typed route/grant target into its stored form: a canonical
// CIDR, or the name of a group that exists. Anything that is neither gets an
// error naming both possibilities, so a mistyped CIDR is not silently taken
// for a group name.
func canonRef(cc *config.CoordinatorConfig, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if p, err := netip.ParsePrefix(ref); err == nil {
		return p.Masked().String(), nil
	}
	if findGroup(cc, ref) != nil {
		return ref, nil
	}
	if validGroupName(ref) == nil {
		return "", groupNotFound(ref)
	}
	return "", fmt.Errorf("%q is not a valid CIDR or group name", ref)
}
