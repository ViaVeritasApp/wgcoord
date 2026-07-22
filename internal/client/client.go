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

// JoinOptions configures a first-time join.
type JoinOptions struct {
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

// Join generates a keypair, registers, and persists the client config with the
// returned address and peer set.
func Join(o JoinOptions) (*config.ClientConfig, error) {
	if strings.TrimSpace(o.CoordinatorURL) == "" {
		return nil, fmt.Errorf("--server (coordinator URL) is required")
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, fmt.Errorf("--token is required")
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
	if err := save(cc); err != nil {
		return nil, err
	}
	return cc, nil
}

// Sync sends one heartbeat and folds the returned delta into the cached peers.
func Sync() (*config.ClientConfig, *api.HeartbeatResponse, error) {
	_, cc, err := config.LoadClient()
	if err != nil {
		return nil, nil, err
	}
	req := api.HeartbeatRequest{
		Have:           peerIDs(cc.Peers),
		PublicKey:      cc.PublicKey,
		PublicEndpoint: cc.PublicEndpoint,
		ListenPort:     cc.ListenPort,
	}
	var resp api.HeartbeatResponse
	if err := post(cc, "/heartbeat", req, &resp); err != nil {
		return nil, nil, err
	}
	applyDelta(cc, &resp)
	if resp.Address != "" {
		cc.Address = resp.Address
	}
	if resp.IPRange != "" {
		cc.IPRange = resp.IPRange
	}
	// Tracked verbatim: an empty value means the hub no longer offers an in-mesh
	// control plane, and the client should stop preferring the old one.
	cc.InternalURL = resp.ControlURL
	if err := save(cc); err != nil {
		return nil, nil, err
	}
	return cc, &resp, nil
}

// Run beats the coordinator on the configured interval until ctx is cancelled.
func Run(ctx context.Context, logger *log.Logger) error {
	_, cc, err := config.LoadClient()
	if err != nil {
		return err
	}
	interval := cc.HeartbeatInterval()
	target := cc.CoordinatorURL
	if cc.InternalURL != "" {
		target = fmt.Sprintf("%s (over the mesh, falling back to %s)", cc.InternalURL, cc.CoordinatorURL)
	}
	logger.Printf("client %q up; beating %s every %s", cc.Name, target, interval)
	beat(logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			beat(logger)
		}
	}
}

// Up applies the cached peer set to the interface without contacting the
// coordinator.
func Up() (string, error) {
	_, cc, err := config.LoadClient()
	if err != nil {
		return "", err
	}
	return Apply(cc)
}

// Down removes the WireGuard interface.
func Down() error {
	_, cc, err := config.LoadClient()
	if err != nil {
		return err
	}
	return wgctl.Down(cc.Interface)
}

// SetEndpointOverride pins the endpoint this node dials for a peer and persists
// it. The coordinator is never told: an override describes how *this* node
// reaches the peer from where it sits, which is what a peer behind the same NAT
// needs when the router won't hairpin its own public address.
func SetEndpointOverride(peer, endpoint string) (*config.ClientConfig, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return nil, fmt.Errorf("a peer name or id is required")
	}
	if err := valid.EndpointOverride(endpoint); err != nil {
		return nil, err
	}
	_, cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	if cc.EndpointOverrides == nil {
		cc.EndpointOverrides = make(map[string]string, 1)
	}
	cc.EndpointOverrides[peer] = endpoint
	if err := save(cc); err != nil {
		return nil, err
	}
	return cc, nil
}

// ClearEndpointOverride drops an override, restoring the coordinator-advertised
// endpoint on the next apply.
func ClearEndpointOverride(peer string) (*config.ClientConfig, error) {
	_, cc, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	if _, ok := cc.EndpointOverrides[peer]; !ok {
		return nil, fmt.Errorf("no endpoint override set for %q", peer)
	}
	delete(cc.EndpointOverrides, peer)
	if len(cc.EndpointOverrides) == 0 {
		cc.EndpointOverrides = nil
	}
	if err := save(cc); err != nil {
		return nil, err
	}
	return cc, nil
}

// Apply renders the interface (self + cached peers), writes the .conf, and
// applies it live. The path is always written; err may be wgctl.ErrUnsupported.
func Apply(cc *config.ClientConfig) (string, error) {
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
	confPath := filepath.Join(config.Dir(), cc.Interface+".conf")
	if err := wgctl.WriteConfigFile(confPath, iface); err != nil {
		return confPath, err
	}
	return confPath, wgctl.Apply(iface)
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

// beat runs one Sync + Apply, logging transient errors rather than failing.
func beat(logger *log.Logger) {
	cc, resp, err := Sync()
	if err != nil {
		logger.Printf("heartbeat: %v", err)
		return
	}
	if len(resp.Add) > 0 || len(resp.Remove) > 0 {
		logger.Printf("peers changed: +%d -%d", len(resp.Add), len(resp.Remove))
	}
	if _, err := Apply(cc); err != nil && !errors.Is(err, wgctl.ErrUnsupported) {
		logger.Printf("apply: %v", err)
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

func save(cc *config.ClientConfig) error {
	return config.Save(&config.Config{Mode: config.ModeClient, Client: cc})
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
