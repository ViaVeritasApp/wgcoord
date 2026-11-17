// Package client is the client mode: join a coordinator, heartbeat to exchange
// peers, and apply the resulting WireGuard state locally.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/ipalloc"
	"wgcoord/internal/valid"
	"wgcoord/internal/wgctl"
	"wgcoord/internal/wgkey"
)

const (
	// requestTimeout bounds a control-plane call over the public URL.
	requestTimeout = 15 * time.Second
	// internalTimeout bounds the over-mesh attempt. A live tunnel answers in
	// milliseconds, so a short deadline keeps a dead one from stalling the beat
	// before the public fallback runs.
	internalTimeout = 5 * time.Second
	// internalCooldown is how long the client sticks to the public URL after an
	// over-mesh attempt fails, so a broken tunnel costs one stall, not every beat.
	internalCooldown = 5 * time.Minute
)

var httpClient = &http.Client{Timeout: requestTimeout}

// internalUntil is when over-mesh attempts may resume after a failure; it is
// process-local, so a one-shot `client sync` always gives the mesh one try.
var (
	internalMu    sync.Mutex
	internalUntil time.Time
)

// meshAvailable reports whether this host can hold a live tunnel at all;
// indirected for tests.
var meshAvailable = wgctl.Available

// Seams for the live interface, replaced in tests.
var (
	wgApply      = wgctl.Apply
	wgDown       = wgctl.Down
	wgSyncRoutes = wgctl.SyncRoutes
	wgTagsRoutes = wgctl.TagsRoutes
)

// profilePoll is how often `client run` checks whether the active profile
// changed, so a switch takes effect within seconds, not a heartbeat interval.
var profilePoll = 2 * time.Second

// Applied is the outcome of bringing a profile's interface in line: the .conf
// written and the apply error, which may be wgctl.ErrUnsupported. Skipped means
// the profile is not the active one, so nothing was touched.
type Applied struct {
	ConfPath string
	Err      error
	Skipped  bool
}

// JoinOptions configures a first-time join.
type JoinOptions struct {
	// Profile names the new profile. Empty means DefaultProfile, and is only
	// allowed while the machine has no profile yet.
	Profile           string
	CoordinatorURL    string
	Token             string
	Name              string
	Interface         string
	ListenPort        int
	PublicEndpoint    string
	RequestedAddress  string
	Keepalive         int
	HeartbeatSeconds  int
	EndpointOverrides map[string]string
}

// Joined is a new profile. Active is set when it became the active profile
// (no other was active), in which case Applied reports bringing it up.
type Joined struct {
	Profile string
	Client  *config.ClientConfig
	Active  bool
	Applied Applied
}

// Join generates a keypair, registers, and saves the result as a new profile.
// It becomes the active profile only when none is active, so joining a second
// coordinator never drops the connection to the first.
func Join(o JoinOptions) (*Joined, error) {
	if strings.TrimSpace(o.CoordinatorURL) == "" {
		return nil, fmt.Errorf("--server (coordinator URL) is required")
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, fmt.Errorf("--token is required")
	}
	name := strings.TrimSpace(o.Profile)
	if err := checkJoinable(name); err != nil {
		return nil, err
	}
	if name == "" {
		name = config.DefaultProfile
	}
	kp, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	cc := &config.ClientConfig{
		CoordinatorURL:    strings.TrimRight(o.CoordinatorURL, "/"),
		Token:             o.Token,
		Interface:         orStr(o.Interface, "wg0"),
		ListenPort:        orInt(o.ListenPort, config.DefaultClientWGPort),
		PublicEndpoint:    o.PublicEndpoint,
		PrivateKey:        kp.PrivateKey,
		PublicKey:         kp.PublicKey,
		Keepalive:         o.Keepalive,
		HeartbeatSeconds:  o.HeartbeatSeconds,
		EndpointOverrides: o.EndpointOverrides,
	}
	resp, err := register(cc, o.RequestedAddress)
	if err != nil {
		return nil, err
	}
	cc.ID = resp.ID
	cc.Name = resp.Name
	cc.Address = resp.Address
	cc.IPRange = resp.IPRange
	cc.InternalURL = resp.ControlURL
	cc.Peers = toPeers(resp.Peers)
	cc.HubOnly = resp.HubOnly

	out := &Joined{Profile: name, Client: cc, Applied: Applied{Skipped: true}}
	err = mutate(true, func(c *config.Config) error {
		if _, ok := c.Profiles[name]; ok {
			return fmt.Errorf("profile %q already exists", name)
		}
		if c.Profiles == nil {
			c.Profiles = map[string]*config.ClientConfig{}
		}
		c.Profiles[name] = cc
		if c.ActiveProfile == "" {
			c.ActiveProfile = name
			out.Active = true
			out.Applied = apply(cc)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// checkJoinable refuses a join before it registers, since registering spends
// the token's first use: a taken profile name, a coordinator host, or a second
// unnamed profile.
func checkJoinable(name string) error {
	if name != "" {
		if err := config.ValidProfileName(name); err != nil {
			return err
		}
	}
	if !config.Exists() {
		return nil
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	if c.Mode != config.ModeClient {
		return fmt.Errorf("%s is a %s config — a host is either a coordinator or a client", config.Path(), c.Mode)
	}
	if name == "" && len(c.Profiles) > 0 {
		return fmt.Errorf("already joined (profiles: %s) — name the new one with --profile <name>", strings.Join(c.ProfileNames(), ", "))
	}
	if name == "" {
		name = config.DefaultProfile
	}
	if _, ok := c.Profiles[name]; ok {
		return fmt.Errorf("profile %q already exists — pick another --profile, or remove it first with `wgcoord client profile remove %s`", name, name)
	}
	return nil
}

// SyncResult is one heartbeat folded into a profile.
type SyncResult struct {
	Profile string
	Client  *config.ClientConfig
	Resp    *api.HeartbeatResponse
	Applied Applied
}

// Sync sends one heartbeat for the named profile (the active one when empty),
// folds the returned delta into its cached peers, and re-applies the
// interface when the profile is active.
func Sync(profile string) (*SyncResult, error) {
	_, name, cc, err := config.LoadProfile(profile)
	if err != nil {
		return nil, err
	}
	req := api.HeartbeatRequest{
		Have:           peerIDs(cc.Peers),
		PublicKey:      cc.PublicKey,
		PublicEndpoint: cc.PublicEndpoint,
		ListenPort:     cc.ListenPort,
	}
	var resp api.HeartbeatResponse
	if err := post(cc, "/heartbeat", req, &resp); err != nil {
		return nil, err
	}
	res := &SyncResult{Profile: name, Resp: &resp}
	// The heartbeat ran unlocked, so fold it into a fresh copy: a CLI edit made
	// meanwhile (an endpoint override, a switch) must survive.
	err = mutate(false, func(c *config.Config) error {
		fresh, ok := c.Profiles[name]
		if !ok {
			return fmt.Errorf("profile %q was removed during the heartbeat", name)
		}
		applyHeartbeat(fresh, &resp)
		res.Client = fresh
		if c.ActiveProfile == name {
			res.Applied = apply(fresh)
		} else {
			res.Applied = Applied{Skipped: true}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// applyHeartbeat folds a heartbeat response into cc.
func applyHeartbeat(cc *config.ClientConfig, resp *api.HeartbeatResponse) {
	applyDelta(cc, resp)
	if resp.Address != "" {
		cc.Address = resp.Address
	}
	if resp.IPRange != "" {
		cc.IPRange = resp.IPRange
	}
	// Tracked verbatim: an empty value means the hub no longer offers an in-mesh
	// control plane, and the client should stop preferring the old one.
	cc.InternalURL = resp.ControlURL
	cc.HubOnly = resp.HubOnly
}

// Run beats the active profile's coordinator until ctx is cancelled. It
// follows the active profile: after `client use <other>`, it stops beating the
// old coordinator and starts on the new one within profilePoll.
func Run(ctx context.Context, logger *log.Logger) error {
	if _, err := config.LoadClient(); err != nil {
		return err
	}
	var (
		cur       string
		started   bool
		ticker    *time.Ticker
		tick      <-chan time.Time
		lastApply string
		lastLoad  string
	)
	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker, tick = nil, nil
		}
	}
	defer stopTicker()

	check := func() {
		c, err := config.LoadClient()
		if err != nil {
			if err.Error() != lastLoad {
				logger.Printf("config: %v", err)
				lastLoad = err.Error()
			}
			return
		}
		lastLoad = ""
		name := c.ActiveProfile
		if _, ok := c.Profiles[name]; !ok {
			name = ""
		}
		if started && name == cur {
			return
		}
		started = true
		stopTicker()
		if cur != "" && name != cur {
			logger.Printf("profile %q is no longer active; stopped beating its coordinator", cur)
		}
		cur, lastApply = name, ""
		resetInternal() // a cooldown earned by another coordinator says nothing about this one
		if name == "" {
			logger.Print("no active profile; idle until `wgcoord client use <profile>`")
			return
		}
		cc := c.Profiles[name]
		interval := cc.HeartbeatInterval()
		target := cc.CoordinatorURL
		if cc.InternalURL != "" {
			target = fmt.Sprintf("%s (over the mesh, falling back to %s)", cc.InternalURL, cc.CoordinatorURL)
		}
		logger.Printf("profile %q: client %q up; beating %s every %s", name, cc.Name, target, interval)
		ticker = time.NewTicker(interval)
		tick = ticker.C
		beat(logger, name, &lastApply)
	}

	check()
	poll := time.NewTicker(profilePoll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
			check()
		case <-tick:
			beat(logger, cur, &lastApply)
		}
	}
}

// Activated is a profile brought up by Use or Up. Previous is the profile
// that was active before; it equals Profile when nothing was switched.
type Activated struct {
	Profile  string
	Previous string
	Client   *config.ClientConfig
	Applied  Applied
}

// Use makes name the active profile: it closes every profile's interface,
// then brings name's up from its cached peers. A running `client run` follows
// within profilePoll.
func Use(name string) (*Activated, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("a profile name is required")
	}
	out := &Activated{Profile: name}
	err := mutate(false, func(c *config.Config) error {
		_, cc, err := c.Profile(name)
		if err != nil {
			return err
		}
		out.Previous = c.ActiveProfile
		// Close every profile, the target included: macOS installs a tunnel's
		// routes only when it comes up, so even a profile sharing the target's
		// interface name has to go down before the target comes up.
		if err := downAll(c); err != nil {
			return err
		}
		c.ActiveProfile = name
		out.Client = cc
		out.Applied = apply(cc)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// downAll takes down every profile's interface, once per interface name.
func downAll(c *config.Config) error {
	done := map[string]bool{}
	for _, n := range c.ProfileNames() {
		p := c.Profiles[n]
		if p == nil || done[p.Interface] {
			continue
		}
		done[p.Interface] = true
		if err := downProfile(p); err != nil && !errors.Is(err, wgctl.ErrUnsupported) {
			return fmt.Errorf("close profile %q (%s): %w", n, p.Interface, err)
		}
		// Routes die with the interface.
		p.ManagedRoutes = nil
	}
	return nil
}

// Up applies a profile's cached peer set without contacting its coordinator.
// An empty profile means the active one; naming another switches to it, as
// Use does.
func Up(profile string) (*Activated, error) {
	c, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	name, _, err := c.Profile(profile)
	if err != nil {
		return nil, err
	}
	if name != c.ActiveProfile {
		return Use(name)
	}
	out := &Activated{Profile: name, Previous: name}
	err = mutate(false, func(c *config.Config) error {
		_, cc, err := c.Profile(name)
		if err != nil {
			return err
		}
		out.Client = cc
		out.Applied = apply(cc)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Down removes a profile's WireGuard interface (the active profile's when
// empty) and returns the profile's name. The profile stays active, so a
// running `client run` brings it back on its next beat.
func Down(profile string) (string, error) {
	c, name, cc, err := config.LoadProfile(profile)
	if err != nil {
		return "", err
	}
	if active, ok := c.Profiles[c.ActiveProfile]; ok && name != c.ActiveProfile && active.Interface == cc.Interface {
		return "", fmt.Errorf("profile %q is not connected; %s belongs to the active profile %q", name, cc.Interface, c.ActiveProfile)
	}
	return name, downProfile(cc)
}

// downProfile takes cc's interface down. The .conf is written first: macOS
// wg-quick reads it on the way down, and a profile imported from another
// config directory has none here yet.
func downProfile(cc *config.ClientConfig) error {
	if err := wgctl.WriteConfigFile(confPath(cc), renderInterface(cc)); err != nil {
		return err
	}
	return wgDown(cc.Interface)
}

// Edited is a profile changed in place, re-applied when it is active.
type Edited struct {
	Profile string
	Client  *config.ClientConfig
	Applied Applied
}

// SetEndpointOverride pins the endpoint this node dials for a peer and persists
// it. The coordinator is never told: an override describes how *this* node
// reaches the peer from where it sits, which is what a peer behind the same NAT
// needs when the router won't hairpin its own public address.
func SetEndpointOverride(profile, peer, endpoint string) (*Edited, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return nil, fmt.Errorf("a peer name or id is required")
	}
	if err := valid.EndpointOverride(endpoint); err != nil {
		return nil, err
	}
	return editProfile(profile, func(cc *config.ClientConfig) error {
		if cc.EndpointOverrides == nil {
			cc.EndpointOverrides = make(map[string]string, 1)
		}
		cc.EndpointOverrides[peer] = endpoint
		return nil
	})
}

// ClearEndpointOverride drops an override, restoring the coordinator-advertised
// endpoint on the next apply.
func ClearEndpointOverride(profile, peer string) (*Edited, error) {
	return editProfile(profile, func(cc *config.ClientConfig) error {
		if _, ok := cc.EndpointOverrides[peer]; !ok {
			return fmt.Errorf("no endpoint override set for %q", peer)
		}
		delete(cc.EndpointOverrides, peer)
		if len(cc.EndpointOverrides) == 0 {
			cc.EndpointOverrides = nil
		}
		return nil
	})
}

// editProfile runs fn on a profile under the config lock, saves it, and
// re-applies it when it is the active profile.
func editProfile(profile string, fn func(cc *config.ClientConfig) error) (*Edited, error) {
	out := &Edited{}
	err := mutate(false, func(c *config.Config) error {
		name, cc, err := c.Profile(profile)
		if err != nil {
			return err
		}
		if err := fn(cc); err != nil {
			return err
		}
		out.Profile, out.Client = name, cc
		if name == c.ActiveProfile {
			out.Applied = apply(cc)
		} else {
			out.Applied = Applied{Skipped: true}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// apply renders the interface (self + cached peers), writes the .conf, and
// applies it live. The .conf is always written; Err may be
// wgctl.ErrUnsupported. It updates cc.ManagedRoutes and never saves: callers
// hold the config lock and save once.
func apply(cc *config.ClientConfig) Applied {
	path := confPath(cc)
	iface := renderInterface(cc)
	if err := wgctl.WriteConfigFile(path, iface); err != nil {
		return Applied{ConfPath: path, Err: err}
	}
	if err := wgApply(iface); err != nil {
		return Applied{ConfPath: path, Err: err}
	}
	return Applied{ConfPath: path, Err: syncRoutes(cc)}
}

func confPath(cc *config.ClientConfig) string {
	return filepath.Join(config.Dir(), cc.Interface+".conf")
}

func renderInterface(cc *config.ClientConfig) wgctl.Interface {
	bits := 32
	if cc.IPRange != "" {
		if b, err := ipalloc.PrefixBits(cc.IPRange); err == nil {
			bits = b
		}
	}
	iface := wgctl.Interface{
		Name:       cc.Interface,
		PrivateKey: cc.PrivateKey,
		ListenPort: cc.ListenPort,
		Address:    fmt.Sprintf("%s/%d", cc.Address, bits),
	}
	for _, p := range cc.Peers {
		// Resolved at render time, not stored on the peer: a heartbeat delta
		// overwrites cached peers wholesale, and the override must survive that.
		iface.Peers = append(iface.Peers, wgctl.Peer{
			PublicKey:  p.PublicKey,
			Endpoint:   cc.ResolveEndpoint(p),
			AllowedIPs: []string{p.AllowedIPs},
			Keepalive:  cc.EffectiveKeepalive(),
		})
	}
	return iface
}

// syncRoutes routes a hub-only client's granted ranges into the tunnel. Mesh
// addresses are already routed by the interface address; anything else the
// coordinator allows (pod ranges, networks next to the coordinator) needs a
// kernel route. Mesh clients get none: there a CNI or the operator owns
// routing, and any routes left from an earlier hub-only stint are removed.
// The routes installed are recorded in cc.ManagedRoutes for the caller to save.
func syncRoutes(cc *config.ClientConfig) error {
	var want []string
	if cc.HubOnly {
		want = hubRoutes(cc)
	}
	if len(want) == 0 && len(cc.ManagedRoutes) == 0 && !cc.HubOnly && !wgTagsRoutes() {
		return nil
	}
	managed, err := wgSyncRoutes(cc.Interface, want, cc.ManagedRoutes)
	if errors.Is(err, wgctl.ErrUnsupported) {
		return nil
	}
	cc.ManagedRoutes = managed
	return err
}

// mutate loads the config under the config lock, runs fn, and saves it. With
// create, a missing config starts out as an empty client config.
func mutate(create bool, fn func(c *config.Config) error) error {
	release, err := config.Lock()
	if err != nil {
		return err
	}
	defer release()
	var c *config.Config
	if create && !config.Exists() {
		c = &config.Config{Mode: config.ModeClient}
	} else if c, err = config.Load(); err != nil {
		return err
	}
	if create {
		if c.Mode != config.ModeClient {
			return fmt.Errorf("%s is a %s config — a host is either a coordinator or a client", config.Path(), c.Mode)
		}
	} else if err := c.AssertClient(); err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	return config.Save(c)
}

// hubRoutes lists the coordinator peer's AllowedIPs that fall outside the mesh
// range.
func hubRoutes(cc *config.ClientConfig) []string {
	mesh, err := netip.ParsePrefix(cc.IPRange)
	if err != nil {
		return nil
	}
	mesh = mesh.Masked()
	var out []string
	for _, p := range cc.Peers {
		if p.ID != api.CoordinatorPeerID {
			continue
		}
		for _, raw := range strings.Split(p.AllowedIPs, ",") {
			q, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			if q.Bits() >= mesh.Bits() && mesh.Contains(q.Addr()) {
				continue
			}
			out = append(out, q.Masked().String())
		}
	}
	return out
}

// --- internals ---

func register(cc *config.ClientConfig, requestedAddr string) (*api.RegisterResponse, error) {
	req := api.RegisterRequest{
		PublicKey:        cc.PublicKey,
		PublicEndpoint:   cc.PublicEndpoint,
		ListenPort:       cc.ListenPort,
		RequestedAddress: requestedAddr,
	}
	var resp api.RegisterResponse
	if err := post(cc, "/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// beat runs one Sync (which re-applies), logging transient errors rather
// than failing. An apply fault persists across beats, so lastApply carries it
// and only a change is logged — otherwise one broken interface fills the log
// every interval.
func beat(logger *log.Logger, profile string, lastApply *string) {
	res, err := Sync(profile)
	if err != nil {
		logger.Printf("heartbeat (%s): %v", profile, err)
		return
	}
	if len(res.Resp.Add) > 0 || len(res.Resp.Remove) > 0 {
		logger.Printf("peers changed (%s): +%d -%d", profile, len(res.Resp.Add), len(res.Resp.Remove))
	}
	if res.Applied.Skipped {
		return // switched away mid-beat; the next poll picks up the new profile
	}
	err = res.Applied.Err
	if errors.Is(err, wgctl.ErrUnsupported) {
		err = nil // Control plane only on this host, not a fault.
	}
	switch {
	case err == nil && *lastApply != "":
		logger.Print("apply: recovered")
		*lastApply = ""
	case err != nil && err.Error() != *lastApply:
		logger.Printf("apply (%s): %v", profile, err)
		*lastApply = err.Error()
	}
}

// applyDelta upserts added peers and drops removed ones from cc.Peers.
func applyDelta(cc *config.ClientConfig, resp *api.HeartbeatResponse) {
	byID := make(map[string]int, len(cc.Peers))
	for i, p := range cc.Peers {
		byID[p.ID] = i
	}
	for _, p := range resp.Add {
		np := config.Peer{ID: p.ID, Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs}
		if i, ok := byID[p.ID]; ok {
			cc.Peers[i] = np
		} else {
			cc.Peers = append(cc.Peers, np)
			byID[p.ID] = len(cc.Peers) - 1
		}
	}
	if len(resp.Remove) > 0 {
		drop := make(map[string]bool, len(resp.Remove))
		for _, id := range resp.Remove {
			drop[id] = true
		}
		kept := cc.Peers[:0]
		for _, p := range cc.Peers {
			if !drop[p.ID] {
				kept = append(kept, p)
			}
		}
		cc.Peers = kept
	}
}

func toPeers(in []api.Peer) []config.Peer {
	out := make([]config.Peer, 0, len(in))
	for _, p := range in {
		out = append(out, config.Peer{ID: p.ID, Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs})
	}
	return out
}

func peerIDs(peers []config.Peer) []string {
	ids := make([]string, 0, len(peers))
	for _, p := range peers {
		ids = append(ids, p.ID)
	}
	return ids
}

// post sends a control-plane request, preferring the coordinator's in-mesh
// address once this node has a tunnel — the token then never leaves WireGuard —
// and falling back to the public URL it joined with when that path fails.
func post(cc *config.ClientConfig, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if base := internalBase(cc); base != "" {
		retry, err := do(cc, base+path, buf, out, internalTimeout)
		if err == nil {
			return nil
		}
		if !retry {
			return err // the coordinator answered, so the mesh path itself works
		}
		coolDownInternal()
		log.Printf("control plane: %s over the mesh failed (%v) — using %s for the next %s",
			path, err, cc.CoordinatorURL, internalCooldown)
	}
	_, err = do(cc, cc.CoordinatorURL+path, buf, out, requestTimeout)
	return err
}

// do posts one request. retry reports whether the failure was a transport-level
// one (dial, timeout, 5xx) — worth trying over another path — as opposed to a
// definitive answer from the coordinator, which would be the same either way.
func do(cc *config.ClientConfig, endpoint string, body []byte, out any, timeout time.Duration) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cc.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return true, fmt.Errorf("contact coordinator: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := fmt.Sprintf("coordinator returned %d", resp.StatusCode)
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = fmt.Sprintf("coordinator %d: %s", resp.StatusCode, e.Error)
		}
		return resp.StatusCode/100 == 5, errors.New(msg)
	}
	if out == nil {
		return false, nil
	}
	// A decode failure is never retried: out may already be half-written, and
	// re-decoding the other path's body into it would merge two responses.
	return false, json.Unmarshal(data, out)
}

// internalBase returns the coordinator's in-mesh control URL when it is worth
// trying: advertised by the hub, inside the mesh range, reachable through an
// interface this host can actually bring up, and not cooling down from a
// recent failure.
func internalBase(cc *config.ClientConfig) string {
	if cc.InternalURL == "" || cc.InternalURL == cc.CoordinatorURL || cc.Address == "" {
		return ""
	}
	if !inMesh(cc, cc.InternalURL) || !hasCoordinatorPeer(cc) {
		return "" // no tunnel carries this address
	}
	if !meshAvailable() {
		return "" // live apply is impossible here, so the mesh routes nowhere
	}
	internalMu.Lock()
	defer internalMu.Unlock()
	if time.Now().Before(internalUntil) {
		return ""
	}
	return cc.InternalURL
}

// resetInternal lifts the cooldown, e.g. when switching to another
// coordinator.
func resetInternal() {
	internalMu.Lock()
	defer internalMu.Unlock()
	internalUntil = time.Time{}
}

func coolDownInternal() {
	internalMu.Lock()
	defer internalMu.Unlock()
	internalUntil = time.Now().Add(internalCooldown)
}

// inMesh checks that raw points at an address inside the mesh pool: the
// coordinator is trusted, but only the tunnel makes this path worth preferring.
func inMesh(cc *config.ClientConfig, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || cc.IPRange == "" {
		return false
	}
	ok, err := ipalloc.Usable(cc.IPRange, u.Hostname())
	return err == nil && ok
}

func hasCoordinatorPeer(cc *config.ClientConfig) bool {
	for _, p := range cc.Peers {
		if p.ID == api.CoordinatorPeerID {
			return true
		}
	}
	return false
}

func orStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func orInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
