// Package coordinator is the control-plane: the named-client registry, the HTTP
// peer-exchange endpoints, and the loop reconciling the hub's live interface.
package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/ipalloc"
	"wgcoord/internal/token"
	"wgcoord/internal/valid"
)

// ErrUnauthorized is returned when a presented token matches no client.
var ErrUnauthorized = errors.New("unauthorized")

// Store serializes reads/writes of the coordinator config. Each mutation is a
// read-modify-write under an in-process mutex and an inter-process file lock,
// so the daemon and a CLI edit (blacklist, token) can't clobber each other.
type Store struct {
	mu sync.Mutex
}

func NewStore() *Store { return &Store{} }

// Load returns a fresh snapshot of the coordinator section from disk.
func Load() (*config.CoordinatorConfig, error) {
	_, cc, err := config.LoadCoordinator()
	return cc, err
}

// Mutate applies fn to a freshly-loaded config and saves it, under both locks.
func (s *Store) Mutate(fn func(cc *config.CoordinatorConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	release, err := flock(config.Path() + ".lock")
	if err != nil {
		return err
	}
	defer release()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Mode != config.ModeCoordinator || cfg.Coordinator == nil {
		return fmt.Errorf("this machine is not a coordinator")
	}
	if err := fn(cfg.Coordinator); err != nil {
		return err
	}
	return config.Save(cfg)
}

// ClientOptions configures a new client. Routes and Grants take CIDRs or
// group names; Grants also take "all". Grants need HubOnly, and a hub-only
// client can't carry Routes.
type ClientOptions struct {
	Address string
	Routes  []string
	HubOnly bool
	Grants  []string
}

// AddedClient is a freshly created client, its one-time plaintext token, and
// any warnings about grants the mesh only partly routes.
type AddedClient struct {
	Client   *config.Client
	Token    string
	Warnings []string
}

// AddClient creates a named client with a fresh token. A non-empty address is
// reserved; otherwise the lowest free one is auto-allocated. The returned
// plaintext token is shown once and never stored.
func (s *Store) AddClient(name string, o ClientOptions) (*AddedClient, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("client name is required")
	}
	if o.HubOnly && len(o.Routes) > 0 {
		return nil, fmt.Errorf("hub-only clients can't carry routes; drop --route or --hub-only")
	}
	if !o.HubOnly && len(o.Grants) > 0 {
		return nil, ErrGrantNeedsHubOnly
	}
	tok, err := token.Generate()
	if err != nil {
		return nil, err
	}
	out := &AddedClient{Token: tok}
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		if findByName(cc, name) != nil {
			return fmt.Errorf("a client named %q already exists", name)
		}
		addr := strings.TrimSpace(o.Address)
		if addr == "" {
			a, err := ipalloc.NextFree(cc.IPRange, usedAddrs(cc))
			if err != nil {
				return err
			}
			addr = a
		} else if err := checkAddrFree(cc, addr, ""); err != nil {
			return err
		}
		routes, err := canonRefs(cc, o.Routes)
		if err != nil {
			return err
		}
		now := nowRFC3339()
		c := &config.Client{
			ID:        newID(),
			Name:      name,
			TokenHash: token.Hash(tok),
			Address:   addr,
			Routes:    routes,
			HubOnly:   o.HubOnly,
			CreatedAt: now,
		}
		cc.Clients = append(cc.Clients, c)
		if err := checkAllRoutes(cc); err != nil {
			return err
		}
		if len(o.Grants) > 0 {
			if _, out.Warnings, err = addGrants(cc, c, o.Grants, nil); err != nil {
				return err
			}
		}
		if c.HubOnly {
			cc.UpdatedAt = now // mesh clients route this address via the hub
		}
		out.Client = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// canonRefs canonicalizes route references, dropping duplicates in order.
func canonRefs(cc *config.CoordinatorConfig, refs []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, r := range refs {
		c, err := canonRef(cc, r)
		if err != nil {
			return nil, err
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// AddRoutes appends extra CIDRs or groups a node carries (its Kubernetes pod
// subnet, a LAN behind it) to the AllowedIPs advertised for it, so peers route
// those subnets through its tunnel instead of WireGuard dropping them. node is
// a client name or "coordinator" (the hub itself). nat, valid only on the
// coordinator, marks the routes as networks next to the hub that mesh traffic
// is masqueraded into. Duplicates are ignored; the refs actually added (or
// newly marked NAT) are returned, and peers pick them up on their next
// heartbeat.
func (s *Store) AddRoutes(node string, refs []string, nat bool) ([]string, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("at least one CIDR or group is required")
	}
	if nat && !isHub(node) {
		return nil, fmt.Errorf("--nat is only valid on the coordinator's own routes (wgcoord coordinator route add coordinator <cidr> --nat)")
	}
	var added []string
	err := s.Mutate(func(cc *config.CoordinatorConfig) error {
		target, _, err := routesTarget(cc, node)
		if err != nil {
			return err
		}
		if c := findByName(cc, node); c != nil && c.HubOnly && !isHub(node) {
			return fmt.Errorf("%q is a hub-only client and can't carry routes", c.Name)
		}
		canon, err := canonRefs(cc, refs)
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(*target))
		for _, r := range *target {
			have[r] = true
		}
		for _, r := range canon {
			newNAT := nat && !contains(cc.NATRoutes, r)
			if newNAT {
				cc.NATRoutes = append(cc.NATRoutes, r)
			}
			if have[r] {
				if newNAT {
					added = append(added, r)
				}
				continue
			}
			have[r] = true
			*target = append(*target, r)
			added = append(added, r)
		}
		if len(added) == 0 {
			return nil
		}
		if err := checkAllRoutes(cc); err != nil {
			return err
		}
		touchNode(cc, node)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}

// RemoveRoutes drops route refs (CIDRs or group names) from a node. node is a
// client name or "coordinator". Returns the refs actually removed; the change
// reaches peers on their next heartbeat.
func (s *Store) RemoveRoutes(node string, refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("at least one CIDR or group is required")
	}
	drop := make(map[string]bool, len(refs))
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if isCIDRRef(r) {
			canon, err := valid.CIDR(r)
			if err != nil {
				return nil, err
			}
			r = canon
		}
		drop[r] = true
	}
	var removed []string
	err := s.Mutate(func(cc *config.CoordinatorConfig) error {
		target, _, err := routesTarget(cc, node)
		if err != nil {
			return err
		}
		kept := (*target)[:0]
		for _, r := range *target {
			if drop[r] {
				removed = append(removed, r)
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			*target = nil
		} else {
			*target = kept
		}
		if isHub(node) {
			cc.NATRoutes = without(cc.NATRoutes, drop)
		}
		if len(removed) > 0 {
			touchNode(cc, node)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// checkAllRoutes validates every node's routes together: groups used as routes
// exist and carry no ports, no route sits inside the mesh range, hub-only
// clients carry none, and no prefix is routed by two nodes (WireGuard would
// hand it to whichever peer was configured last).
func checkAllRoutes(cc *config.CoordinatorConfig) error {
	mesh, haveMesh := meshPrefix(cc)
	owner := map[netip.Prefix]string{}
	check := func(node string, refs []string) error {
		for _, ref := range refs {
			if !isCIDRRef(ref) {
				g := findGroup(cc, ref)
				if g == nil {
					return fmt.Errorf("%s routes group %q, which doesn't exist", node, ref)
				}
				for _, e := range g.Entries {
					if len(e.Ports) > 0 {
						return fmt.Errorf("group %q limits %s to %s, so it can't be used as a route; routes carry whole ranges", g.Name, e.CIDR, strings.Join(e.Ports, ", "))
					}
				}
			}
		}
		for _, r := range resolveRoutes(cc, refs) {
			p, err := netip.ParsePrefix(r)
			if err != nil {
				return err
			}
			if haveMesh && p.Bits() >= mesh.Bits() && mesh.Contains(p.Addr()) {
				return fmt.Errorf("route %s is inside the mesh range %s; mesh addresses are already routed", p, mesh)
			}
			if prev, ok := owner[p]; ok && prev != node {
				return fmt.Errorf("%s would be routed by both %s and %s; each prefix must belong to exactly one node", p, prev, node)
			}
			owner[p] = node
		}
		return nil
	}
	if err := check(api.CoordinatorPeerID, cc.Routes); err != nil {
		return err
	}
	for _, c := range cc.Clients {
		if c.HubOnly && len(c.Routes) > 0 {
			return fmt.Errorf("%q is a hub-only client and can't carry routes", c.Name)
		}
		if err := check(c.Name, c.Routes); err != nil {
			return err
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func without(list []string, drop map[string]bool) []string {
	var out []string
	for _, x := range list {
		if !drop[x] {
			out = append(out, x)
		}
	}
	return out
}

// Routes returns the routes configured for node (a client name or
// "coordinator") alongside its canonical display name.
func (s *Store) Routes(node string) ([]string, string, error) {
	cc, err := Load()
	if err != nil {
		return nil, "", err
	}
	target, name, err := routesTarget(cc, node)
	if err != nil {
		return nil, "", err
	}
	return *target, name, nil
}

// RemoveClient deletes a client; the next reconcile drops it from the interface.
func (s *Store) RemoveClient(name string) error {
	return s.Mutate(func(cc *config.CoordinatorConfig) error {
		for i, c := range cc.Clients {
			if c.Name == name {
				if c.HubOnly {
					cc.UpdatedAt = nowRFC3339() // its /32 leaves the hub's AllowedIPs
				}
				cc.Clients = append(cc.Clients[:i], cc.Clients[i+1:]...)
				return nil
			}
		}
		return notFound(name)
	})
}

// RenameClient changes a client's display name.
func (s *Store) RenameClient(oldName, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return fmt.Errorf("new name is required")
	}
	return s.Mutate(func(cc *config.CoordinatorConfig) error {
		if findByName(cc, newName) != nil {
			return fmt.Errorf("a client named %q already exists", newName)
		}
		c := findByName(cc, oldName)
		if c == nil {
			return notFound(oldName)
		}
		c.Name = newName
		c.UpdatedAt = nowRFC3339()
		return nil
	})
}

// RegenToken rotates a client's token and returns the new plaintext.
func (s *Store) RegenToken(name string) (string, error) {
	tok, err := token.Generate()
	if err != nil {
		return "", err
	}
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		c := findByName(cc, name)
		if c == nil {
			return notFound(name)
		}
		c.TokenHash = token.Hash(tok)
		c.UpdatedAt = nowRFC3339()
		return nil
	})
	if err != nil {
		return "", err
	}
	return tok, nil
}

// SetBlacklist toggles a client's blacklist flag; blacklisted clients are
// refused at the control plane and dropped on the next reconcile/heartbeat.
func (s *Store) SetBlacklist(name string, blacklisted bool) error {
	return s.Mutate(func(cc *config.CoordinatorConfig) error {
		c := findByName(cc, name)
		if c == nil {
			return notFound(name)
		}
		c.Blacklisted = blacklisted
		c.UpdatedAt = nowRFC3339()
		if c.HubOnly {
			cc.UpdatedAt = c.UpdatedAt // its /32 leaves or rejoins the hub's AllowedIPs
		}
		return nil
	})
}

// Authenticate resolves a bearer token to its client. Callers still check the
// returned client's Blacklisted flag.
func Authenticate(tok string) (*config.Client, error) {
	if strings.TrimSpace(tok) == "" {
		return nil, ErrUnauthorized
	}
	cc, err := Load()
	if err != nil {
		return nil, err
	}
	for _, c := range cc.Clients {
		if token.Equal(tok, c.TokenHash) {
			return c, nil
		}
	}
	return nil, ErrUnauthorized
}

// --- helpers ---

func findByName(cc *config.CoordinatorConfig, name string) *config.Client {
	for _, c := range cc.Clients {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func findByID(cc *config.CoordinatorConfig, id string) *config.Client {
	for _, c := range cc.Clients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// usedAddrs is every mesh address currently spoken for (hub + clients).
func usedAddrs(cc *config.CoordinatorConfig) []string {
	used := make([]string, 0, len(cc.Clients)+1)
	if cc.Address != "" {
		used = append(used, cc.Address)
	}
	for _, c := range cc.Clients {
		if c.Address != "" {
			used = append(used, c.Address)
		}
	}
	return used
}

// checkAddrFree validates addr is a usable host in range and unclaimed by the
// hub or another client (exceptID is skipped, so a client can keep its own).
func checkAddrFree(cc *config.CoordinatorConfig, addr, exceptID string) error {
	ok, err := ipalloc.Usable(cc.IPRange, addr)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not a usable host address in %s", addr, cc.IPRange)
	}
	if addr == cc.Address {
		return fmt.Errorf("%s is the coordinator's own address", addr)
	}
	for _, c := range cc.Clients {
		if c.ID != exceptID && c.Address == addr {
			return fmt.Errorf("%s is already assigned to client %q", addr, c.Name)
		}
	}
	return nil
}

// isHub reports whether node names the coordinator itself rather than a client.
// "coordinator" mirrors the peer id the hub advertises under; "hub" is a
// friendlier alias.
func isHub(node string) bool {
	return node == api.CoordinatorPeerID || node == "hub"
}

// routesTarget resolves node (the hub, or a client by name) to the routes slice
// to mutate and a canonical display name.
func routesTarget(cc *config.CoordinatorConfig, node string) (*[]string, string, error) {
	if isHub(node) {
		return &cc.Routes, api.CoordinatorPeerID, nil
	}
	c := findByName(cc, node)
	if c == nil {
		return nil, "", notFound(node)
	}
	return &c.Routes, c.Name, nil
}

// touchNode bumps the UpdatedAt that drives heartbeat re-advertisement for node:
// the hub's own timestamp, or the client record's.
func touchNode(cc *config.CoordinatorConfig, node string) {
	if isHub(node) {
		cc.UpdatedAt = nowRFC3339()
		return
	}
	if c := findByName(cc, node); c != nil {
		c.UpdatedAt = nowRFC3339()
	}
}

func notFound(name string) error { return fmt.Errorf("no client named %q", name) }

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "id-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

// flock takes an exclusive advisory lock on path and returns a release func,
// serializing config writes across the daemon and any CLI edit.
func flock(path string) (func(), error) {
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
