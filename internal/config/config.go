// Package config is the on-disk state for wgcoord: a single 0600 config.json
// holding either a coordinator or a client section, discriminated by Mode.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	Client      *ClientConfig      `json:"client,omitempty"`
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
	Routes []string `json:"routes,omitempty"`
	Have   []string `json:"have,omitempty"` // peer ids this client last reported holding
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
	b, err := os.ReadFile(Path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no config at %s — run `wgcoord coordinator init` or `wgcoord client join` first", Path())
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", Path(), err)
	}
	return &c, nil
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

// LoadClient loads the config and asserts client mode.
func LoadClient() (*Config, *ClientConfig, error) {
	c, err := Load()
	if err != nil {
		return nil, nil, err
	}
	if c.Mode != ModeClient || c.Client == nil {
		return nil, nil, fmt.Errorf("this machine is not a client (mode=%q) — run `wgcoord client join`", c.Mode)
	}
	return c, c.Client, nil
}

// Save writes the config atomically (temp file + rename) at 0600.
func Save(c *Config) error {
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
