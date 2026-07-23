// Package coordinator is the control-plane: the named-client registry, the HTTP
// peer-exchange endpoints, and the loop reconciling the hub's live interface.
package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// AddClient creates a named client with a fresh token. A non-empty address is
// reserved; otherwise the lowest free one is auto-allocated. routes are extra
// CIDRs the client carries (see AddRoutes). The returned plaintext token is
// shown once and never stored.
func (s *Store) AddClient(name, address string, routes []string) (*config.Client, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("client name is required")
	}
	canonRoutes, err := canonRoutes(routes)
	if err != nil {
		return nil, "", err
	}
	tok, err := token.Generate()
	if err != nil {
		return nil, "", err
	}
	var created *config.Client
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		if findByName(cc, name) != nil {
			return fmt.Errorf("a client named %q already exists", name)
		}
		addr := strings.TrimSpace(address)
		if addr == "" {
			a, err := ipalloc.NextFree(cc.IPRange, usedAddrs(cc))
			if err != nil {
				return err
			}
			addr = a
		} else if err := checkAddrFree(cc, addr, ""); err != nil {
			return err
		}
		c := &config.Client{
			ID:        newID(),
			Name:      name,
			TokenHash: token.Hash(tok),
			Address:   addr,
			Routes:    canonRoutes,
			CreatedAt: nowRFC3339(),
		}
		cc.Clients = append(cc.Clients, c)
		created = c
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return created, tok, nil
}

// AddRoutes appends extra CIDRs a node carries — its Kubernetes pod subnet, a
// LAN behind it — to the AllowedIPs advertised for it, so peers route those
// subnets through its tunnel instead of WireGuard dropping them. node is a
// client name or "coordinator" (the hub itself). Duplicates are ignored; the
// routes actually added are returned, and the change reaches peers on their
// next heartbeat.
func (s *Store) AddRoutes(node string, cidrs []string) ([]string, error) {
	canon, err := canonRoutes(cidrs)
	if err != nil {
		return nil, err
	}
	if len(canon) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	var added []string
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
		target, _, err := routesTarget(cc, node)
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(*target))
		for _, r := range *target {
			have[r] = true
		}
		for _, r := range canon {
			if have[r] {
				continue
			}
			have[r] = true
			*target = append(*target, r)
			added = append(added, r)
		}
		if len(added) > 0 {
			touchNode(cc, node)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}

// RemoveRoutes drops CIDRs from a node's advertised routes. node is a client
// name or "coordinator". Returns the routes actually removed; the change
// reaches peers on their next heartbeat.
func (s *Store) RemoveRoutes(node string, cidrs []string) ([]string, error) {
	canon, err := canonRoutes(cidrs)
	if err != nil {
		return nil, err
	}
	if len(canon) == 0 {
		return nil, fmt.Errorf("at least one CIDR is required")
	}
	drop := make(map[string]bool, len(canon))
	for _, r := range canon {
		drop[r] = true
	}
	var removed []string
	err = s.Mutate(func(cc *config.CoordinatorConfig) error {
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

// canonRoutes validates and canonicalizes route CIDRs, dropping duplicates
// while preserving order.
func canonRoutes(cidrs []string) ([]string, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(cidrs))
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		canon, err := valid.CIDR(c)
		if err != nil {
			return nil, err
		}
		if seen[canon] {
			continue
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out, nil
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
