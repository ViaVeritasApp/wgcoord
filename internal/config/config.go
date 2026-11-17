// Package config is the on-disk state for wgcoord: a single 0600 config.json
// holding either a coordinator section or a set of client profiles,
// discriminated by Mode.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wgcoord/internal/valid"
)

// Mode values.
const (
	ModeCoordinator = "coordinator"
	ModeClient      = "client"
)

// DefaultKeepalive keeps NAT mappings open toward peers (WireGuard-recommended).
const DefaultKeepalive = 25

// DefaultHeartbeatSeconds is the client's default beat interval.
const DefaultHeartbeatSeconds = 25

// Coordinator init defaults. The operator can override every one of these.
const (
	DefaultControlPort  = 51821         // HTTP control-plane (peer exchange)
	DefaultWGPort       = 51820         // hub WireGuard UDP port
	DefaultClientWGPort = 51820         // WireGuard UDP port advertised for clients
	DefaultIPRange      = "10.8.0.0/24" // mesh pool; hub takes the first host (10.8.0.1)
)

type Config struct {
	Mode        string             `json:"mode"`
	Coordinator *CoordinatorConfig `json:"coordinator,omitempty"`
	// Client is the single-client layout from before profiles. Load moves it
	// into Profiles under DefaultProfile, and Save never writes it.
	Client *ClientConfig `json:"client,omitempty"`
	// Profiles are the coordinators this client has joined, by profile name.
	// At most one is connected at a time: ActiveProfile.
	Profiles      map[string]*ClientConfig `json:"profiles,omitempty"`
	ActiveProfile string                   `json:"active_profile,omitempty"`
}

// CoordinatorConfig is the control-plane + hub state. The coordinator is
// peer-0 of the mesh, so it holds its own keypair alongside the client registry.
type CoordinatorConfig struct {
	ControlPort    int    `json:"control_port"`    // HTTP control-plane port (peer exchange)
	Interface      string `json:"interface"`       // WireGuard interface name, e.g. wg0
	ListenPort     int    `json:"listen_port"`     // WireGuard UDP port of the hub
	PublicEndpoint string `json:"public_endpoint"` // public IP/host clients dial; port is ListenPort
	IPRange        string `json:"ip_range"`        // mesh address pool, e.g. 10.55.0.0/24
	Address        string `json:"address"`         // hub's own mesh IP (host, no mask)
	ClientWGPort   int    `json:"client_wg_port"`  // default WireGuard port advertised for clients
	PrivateKey     string `json:"private_key"`     // hub WireGuard private key (base64)
	PublicKey      string `json:"public_key"`      // derived hub public key (base64)
	Keepalive      int    `json:"persistent_keepalive,omitempty"`
	// TLS for the control plane. When both are set the server runs HTTPS, so
	// bearer tokens and keys aren't exposed on-path during bootstrap.
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
	// Routes are extra CIDRs the hub carries beyond its own mesh /32, appended
	// to the AllowedIPs it advertises to clients (e.g. its Kubernetes pod
	// subnet). See [Client.Routes].
	Routes []string `json:"routes,omitempty"`
	// UpdatedAt is bumped when the hub's own peer-facing identity changes
	// (currently its routes), so heartbeats re-advertise the coordinator peer
	// to clients that already hold it.
	UpdatedAt string    `json:"updated_at,omitempty"`
	Clients   []*Client `json:"clients"`
	// Groups are named sets of CIDRs (optionally limited to ports), usable as
	// grants for hub-only clients and, when they carry no ports, as routes.
	Groups []*Group `json:"groups,omitempty"`
	// NATRoutes are the hub's route refs (a CIDR or group name, as stored in
	// Routes) that live outside the mesh, in the coordinator's own network.
	// Mesh traffic leaving for them is masqueraded so replies find their way back.
	NATRoutes []string `json:"nat_routes,omitempty"`
}

// Group is a named set of address entries. An entry's Ports narrow it to
// specific protocols/ports; none means every port and protocol.
type Group struct {
	Name      string       `json:"name"`
	Entries   []GroupEntry `json:"entries"`
	UpdatedAt string       `json:"updated_at,omitempty"`
}

// GroupEntry is one CIDR in a group, in canonical form, with canonical port
// specs ("tcp/5432", "udp/53", "tcp/8000-8100", "tcp").
type GroupEntry struct {
	CIDR  string   `json:"cidr"`
	Ports []string `json:"ports,omitempty"`
}

// Grant is one destination a hub-only client may reach. Target is a
// canonical CIDR, a group name, or "all" (the mesh range plus every route).
// Ports narrow it further; when a group entry also has ports, both must match.
type Grant struct {
	Target string   `json:"target"`
	Ports  []string `json:"ports,omitempty"`
}

// Client is one named node as the coordinator sees it. Only the token's
// SHA-256 hash is stored, never the plaintext.
type Client struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TokenHash   string `json:"token_hash"`
	Address     string `json:"address"`               // assigned mesh IP (host, no mask)
	PublicKey   string `json:"public_key,omitempty"`  // set on first register
	Endpoint    string `json:"endpoint,omitempty"`    // host:port peers dial (empty until known)
	ListenPort  int    `json:"listen_port,omitempty"` // client's own WireGuard port
	Blacklisted bool   `json:"blacklisted"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"` // bumped when key/endpoint/address/routes change
	// Routes are extra CIDRs this client carries beyond its own mesh /32,
	// appended to the AllowedIPs advertised for it so peers route those subnets
	// through its tunnel (e.g. a Kubernetes pod CIDR, or a LAN behind the node).
	// Each entry is a CIDR or a group name, resolved when peers are built.
	Routes []string `json:"routes,omitempty"`
	Have   []string `json:"have,omitempty"` // peer ids this client last reported holding
	// HubOnly clients peer with the coordinator alone. The hub forwards their
	// traffic and its firewall limits it to Grants; other nodes never see them.
	HubOnly bool    `json:"hub_only,omitempty"`
	Grants  []Grant `json:"grants,omitempty"`
	// SentHub is the coordinator AllowedIPs last sent to this hub-only client,
	// so a heartbeat re-sends the coordinator peer only when it changed.
	SentHub string `json:"sent_hub,omitempty"`
}

// ClientConfig is a client machine's state: how to reach the coordinator, its
// own WireGuard identity, and the last peer set it was handed.
type ClientConfig struct {
	CoordinatorURL string `json:"coordinator_url"`
	// InternalURL is the coordinator's control plane as reached through the
	// mesh, advertised by the hub on register/heartbeat. Preferred once the
	// tunnel is up; CoordinatorURL stays the fallback.
	InternalURL       string            `json:"internal_url,omitempty"`
	Token             string            `json:"token"` // plaintext auth token; the file is 0600
	ID                string            `json:"id,omitempty"`
	Name              string            `json:"name,omitempty"`
	Interface         string            `json:"interface"`
	ListenPort        int               `json:"listen_port"`
	PublicEndpoint    string            `json:"public_endpoint,omitempty"` // this node's public IP/host, shared to peers
	PrivateKey        string            `json:"private_key"`
	PublicKey         string            `json:"public_key"`
	Address           string            `json:"address,omitempty"`  // assigned mesh IP (host, no mask)
	IPRange           string            `json:"ip_range,omitempty"` // mesh CIDR, for the interface netmask
	Keepalive         int               `json:"persistent_keepalive,omitempty"`
	HeartbeatSeconds  int               `json:"heartbeat_seconds,omitempty"`
	EndpointOverrides map[string]string `json:"endpoint_overrides,omitempty"`
	Peers             []Peer            `json:"peers"`
	// HubOnly mirrors the coordinator's setting for this client: it peers with
	// the coordinator alone, which forwards its traffic.
	HubOnly bool `json:"hub_only,omitempty"`
	// ManagedRoutes are the kernel routes wgcoord installed for a hub-only
	// client's granted ranges (macOS only; Linux tags its routes instead).
	ManagedRoutes []string `json:"managed_routes,omitempty"`
}

// Peer is one other mesh member as cached on a client.
type Peer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint,omitempty"`
	AllowedIPs string `json:"allowed_ips"`
}

// EndpointOverrideFor returns the override configured for p, matched on its id
// first and then its name.
func (c *ClientConfig) EndpointOverrideFor(p Peer) (string, bool) {
	if len(c.EndpointOverrides) == 0 {
		return "", false
	}
	if v, ok := c.EndpointOverrides[p.ID]; ok {
		return v, true
	}
	v, ok := c.EndpointOverrides[p.Name]
	return v, ok
}

// ResolveEndpoint is the endpoint to program for p: the local override when one
// is set, otherwise what the coordinator advertised. A bare-host override keeps
// the advertised port, so pinning a peer to a LAN address doesn't silently move
// it off the port it actually listens on.
func (c *ClientConfig) ResolveEndpoint(p Peer) string {
	ov, ok := c.EndpointOverrideFor(p)
	if !ok {
		return p.Endpoint
	}
	if ov == valid.EndpointNone {
		return ""
	}
	if _, _, err := net.SplitHostPort(ov); err == nil {
		return ov // already host:port
	}
	return net.JoinHostPort(ov, strconv.Itoa(advertisedPort(p.Endpoint)))
}

// KnownPeer reports whether key names a peer this client currently holds, by id
// or name — used to warn about an override that matches nothing.
func (c *ClientConfig) KnownPeer(key string) bool {
	for _, p := range c.Peers {
		if p.ID == key || p.Name == key {
			return true
		}
	}
	return false
}

// advertisedPort extracts the port from a coordinator-advertised endpoint,
// falling back to the default when the peer advertised none (roaming/NAT).
func advertisedPort(endpoint string) int {
	if _, p, err := net.SplitHostPort(endpoint); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			return n
		}
	}
	return DefaultClientWGPort
}

// TLSEnabled reports whether the control plane serves HTTPS itself, as opposed
// to plaintext behind a TLS-terminating proxy.
func (c *CoordinatorConfig) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// InternalControlURL is the control plane as reached from inside the mesh: the
// hub's own mesh address on the control port. Clients with a live tunnel prefer
// it over the public URL, so register/heartbeat travel inside WireGuard.
func (c *CoordinatorConfig) InternalControlURL() string {
	if c.Address == "" || c.ControlPort <= 0 {
		return ""
	}
	scheme := "http"
	if c.TLSEnabled() {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(c.Address, strconv.Itoa(c.ControlPort))
}

// EffectiveKeepalive resolves the configured keepalive or the default.
func (c *CoordinatorConfig) EffectiveKeepalive() int {
	if c.Keepalive > 0 {
		return c.Keepalive
	}
	return DefaultKeepalive
}

func (c *ClientConfig) EffectiveKeepalive() int {
	if c.Keepalive > 0 {
		return c.Keepalive
	}
	return DefaultKeepalive
}

// HeartbeatInterval resolves the configured beat interval or the default.
func (c *ClientConfig) HeartbeatInterval() time.Duration {
	s := c.HeartbeatSeconds
	if s <= 0 {
		s = DefaultHeartbeatSeconds
	}
	return time.Duration(s) * time.Second
}

// customPath overrides the default config location (set from --config).
var customPath string

// SetPath overrides the config file path for this invocation.
func SetPath(p string) { customPath = p }

// Path resolves the config location: --config, then $WGCOORD_CONFIG, then
// /etc/wgcoord/config.json as root, else ~/.config/wgcoord/config.json.
func Path() string {
	if customPath != "" {
		return customPath
	}
	if env := os.Getenv("WGCOORD_CONFIG"); env != "" {
		return env
	}
	if os.Geteuid() == 0 {
		return "/etc/wgcoord/config.json"
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		} else {
			base = "."
		}
	}
	return filepath.Join(base, "wgcoord", "config.json")
}

// Dir is the directory containing the config file.
func Dir() string { return filepath.Dir(Path()) }

// Exists reports whether a config file is already present.
func Exists() bool {
	_, err := os.Stat(Path())
	return err == nil
}

// Load reads and parses the config, with a friendly error when it is missing.
func Load() (*Config, error) {
	return LoadFile(Path())
}

// LoadFile reads and parses the config at path. A client config in the
// pre-profiles layout comes back as one profile named DefaultProfile.
func LoadFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no config at %s — run `wgcoord coordinator init` or `wgcoord client join` first", path)
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	c.migrate()
	return &c, nil
}

// migrate moves a pre-profiles client section into Profiles.
func (c *Config) migrate() {
	if c.Mode != ModeClient || c.Client == nil {
		return
	}
	if len(c.Profiles) == 0 {
		c.Profiles = map[string]*ClientConfig{DefaultProfile: c.Client}
		c.ActiveProfile = DefaultProfile
	}
	c.Client = nil
}

// LoadCoordinator loads the config and asserts coordinator mode.
func LoadCoordinator() (*Config, *CoordinatorConfig, error) {
	c, err := Load()
	if err != nil {
		return nil, nil, err
	}
	if c.Mode != ModeCoordinator || c.Coordinator == nil {
		return nil, nil, fmt.Errorf("this machine is not a coordinator (mode=%q) — run `wgcoord coordinator init`", c.Mode)
	}
	return c, c.Coordinator, nil
}

// LoadClient loads the config and asserts client mode with at least one
// profile.
func LoadClient() (*Config, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	if err := c.AssertClient(); err != nil {
		return nil, err
	}
	return c, nil
}

// AssertClient reports an error unless c is a client config with a profile.
func (c *Config) AssertClient() error {
	if c.Mode != ModeClient || len(c.Profiles) == 0 {
		return fmt.Errorf("this machine is not a client (mode=%q) — run `wgcoord client join`", c.Mode)
	}
	return nil
}

// LoadProfile loads the config and returns the named profile, or the active
// one when name is empty.
func LoadProfile(name string) (*Config, string, *ClientConfig, error) {
	c, err := LoadClient()
	if err != nil {
		return nil, "", nil, err
	}
	name, cc, err := c.Profile(name)
	if err != nil {
		return nil, "", nil, err
	}
	return c, name, cc, nil
}

// Profile returns the named profile, or the active one when name is empty.
func (c *Config) Profile(name string) (string, *ClientConfig, error) {
	if name == "" {
		name = c.ActiveProfile
		if name == "" {
			return "", nil, fmt.Errorf("no active profile — pick one with `wgcoord client use <profile>` (have: %s)", strings.Join(c.ProfileNames(), ", "))
		}
	}
	cc, ok := c.Profiles[name]
	if !ok || cc == nil {
		return "", nil, fmt.Errorf("no profile named %q (have: %s)", name, orNone(c.ProfileNames()))
	}
	return name, cc, nil
}

// ProfileNames lists the profiles in name order.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func orNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// DefaultProfile names the first profile when `client join` is given none,
// and a client config migrated from before profiles.
const DefaultProfile = "default"

// ValidProfileName checks a profile name: 1-32 letters, digits, '.', '_' or
// '-', not starting with '.' or '-'.
func ValidProfileName(n string) error {
	if n == "" || len(n) > 32 {
		return fmt.Errorf("profile name %q must be 1-32 characters", n)
	}
	for i, r := range n {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || (i > 0 && (r == '.' || r == '-'))
		if !ok {
			return fmt.Errorf("profile name %q may use only letters, digits, '.', '_' and '-' (not first)", n)
		}
	}
	return nil
}

// lockMu serializes Lock within this process; the file lock alone would not,
// since each call opens its own descriptor.
var lockMu sync.Mutex

// Lock takes an exclusive lock on the config, shared with every other wgcoord
// process, and returns its release func. It is not reentrant.
func Lock() (func(), error) {
	lockMu.Lock()
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		lockMu.Unlock()
		return nil, err
	}
	f, err := os.OpenFile(Path()+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		lockMu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		lockMu.Unlock()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		lockMu.Unlock()
	}, nil
}

// Mutate loads the config under Lock, runs fn on it, and saves it when fn
// returns nil.
func Mutate(fn func(c *Config) error) error {
	release, err := Lock()
	if err != nil {
		return err
	}
	defer release()
	c, err := Load()
	if err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	return Save(c)
}

// TryLockDaemon takes a non-blocking lock held for the life of `client run`,
// so a second daemon on the same config can tell one is already running. ok
// is false when another process holds it.
func TryLockDaemon() (release func(), ok bool, err error) {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(Path()+".run.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, true, nil
}

// Save writes the config atomically (temp file + rename) at 0600.
func Save(c *Config) error {
	c.migrate()
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config.json.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, Path())
}
