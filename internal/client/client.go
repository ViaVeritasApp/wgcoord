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
	"path/filepath"
	"strings"
	"time"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/ipalloc"
	"wgcoord/internal/wgctl"
	"wgcoord/internal/wgkey"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// JoinOptions configures a first-time join.
type JoinOptions struct {
	CoordinatorURL   string
	Token            string
	Name             string
	Interface        string
	ListenPort       int
	PublicEndpoint   string
	RequestedAddress string
	Keepalive        int
	HeartbeatSeconds int
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
		CoordinatorURL:   strings.TrimRight(o.CoordinatorURL, "/"),
		Token:            o.Token,
		Interface:        orStr(o.Interface, "wg0"),
		ListenPort:       orInt(o.ListenPort, config.DefaultClientWGPort),
		PublicEndpoint:   o.PublicEndpoint,
		PrivateKey:       kp.PrivateKey,
		PublicKey:        kp.PublicKey,
		Keepalive:        o.Keepalive,
		HeartbeatSeconds: o.HeartbeatSeconds,
	}
	resp, err := register(cc, o.RequestedAddress)
	if err != nil {
		return nil, err
	}
	cc.ID = resp.ID
	cc.Name = resp.Name
	cc.Address = resp.Address
	cc.IPRange = resp.IPRange
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
	logger.Printf("client %q up; beating %s every %s", cc.Name, cc.CoordinatorURL, interval)
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
		iface.Peers = append(iface.Peers, wgctl.Peer{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
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

func post(cc *config.ClientConfig, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cc.CoordinatorURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cc.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("contact coordinator: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("coordinator %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("coordinator returned %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
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
