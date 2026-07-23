package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/token"
	"wgcoord/internal/wgkey"
)

func TestAllowedIPs(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		routes []string
		want   []string
	}{
		{"address only", "10.8.0.2", nil, []string{"10.8.0.2/32"}},
		{"address plus pod cidr", "10.8.0.2", []string{"10.12.1.0/24"}, []string{"10.8.0.2/32", "10.12.1.0/24"}},
		{"multiple routes", "10.8.0.1", []string{"10.12.0.0/24", "10.43.0.0/16"}, []string{"10.8.0.1/32", "10.12.0.0/24", "10.43.0.0/16"}},
		{"no address", "", []string{"10.12.1.0/24"}, []string{"10.12.1.0/24"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := allowedIPs(c.addr, c.routes)
			if len(got) != len(c.want) {
				t.Fatalf("allowedIPs(%q,%v) = %v; want %v", c.addr, c.routes, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("allowedIPs(%q,%v) = %v; want %v", c.addr, c.routes, got, c.want)
				}
			}
		})
	}
}

func TestBuildPeersIncludesRoutes(t *testing.T) {
	cc := &config.CoordinatorConfig{
		PublicKey: "hubpub",
		Address:   "10.8.0.1",
		Routes:    []string{"10.12.0.0/24"},
		Clients: []*config.Client{
			{ID: "a", Name: "node1", PublicKey: "apub", Address: "10.8.0.2", Routes: []string{"10.12.1.0/24"}},
			{ID: "b", Name: "node2", PublicKey: "bpub", Address: "10.8.0.3"},
		},
	}
	peers := buildPeers(cc, "b") // node2 asks; it should see the hub and node1

	byID := map[string]api.Peer{}
	for _, p := range peers {
		byID[p.ID] = p
	}
	if got := byID[api.CoordinatorPeerID].AllowedIPs; got != "10.8.0.1/32, 10.12.0.0/24" {
		t.Errorf("hub AllowedIPs = %q; want %q", got, "10.8.0.1/32, 10.12.0.0/24")
	}
	if got := byID["a"].AllowedIPs; got != "10.8.0.2/32, 10.12.1.0/24" {
		t.Errorf("node1 AllowedIPs = %q; want %q", got, "10.8.0.2/32, 10.12.1.0/24")
	}
	if _, ok := byID["b"]; ok {
		t.Errorf("node2 should not be advertised to itself")
	}
}

func TestDesiredInterfaceIncludesRoutes(t *testing.T) {
	cc := &config.CoordinatorConfig{
		Interface:  "wg0",
		PrivateKey: "hubpriv",
		ListenPort: 51820,
		IPRange:    "10.8.0.0/24",
		Address:    "10.8.0.1",
		Clients: []*config.Client{
			{ID: "a", Name: "node1", PublicKey: "apub", Address: "10.8.0.2", Routes: []string{"10.12.1.0/24", "10.13.0.0/16"}},
		},
	}
	iface, err := desiredInterface(cc)
	if err != nil {
		t.Fatalf("desiredInterface: %v", err)
	}
	if len(iface.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(iface.Peers))
	}
	want := []string{"10.8.0.2/32", "10.12.1.0/24", "10.13.0.0/16"}
	got := iface.Peers[0].AllowedIPs
	if len(got) != len(want) {
		t.Fatalf("peer AllowedIPs = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("peer AllowedIPs = %v; want %v", got, want)
		}
	}
}

// newCoordConfig writes a minimal coordinator config to a temp path and returns
// a store bound to it.
func newCoordConfig(t *testing.T) *Store {
	t.Helper()
	config.SetPath(filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { config.SetPath("") })
	cc := &config.CoordinatorConfig{
		ControlPort: 51821,
		Interface:   "wg0",
		ListenPort:  51820,
		IPRange:     "10.8.0.0/24",
		Address:     "10.8.0.1",
		PublicKey:   "hubpub",
		Clients:     []*config.Client{},
	}
	if err := config.Save(&config.Config{Mode: config.ModeCoordinator, Coordinator: cc}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return NewStore()
}

func loadCC(t *testing.T) *config.CoordinatorConfig {
	t.Helper()
	cc, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cc
}

func TestAddRoutesClient(t *testing.T) {
	s := newCoordConfig(t)
	if _, _, err := s.AddClient("node1", "10.8.0.2", nil); err != nil {
		t.Fatalf("add client: %v", err)
	}

	// Host bits get masked; a duplicate and a repeat are ignored.
	added, err := s.AddRoutes("node1", []string{"10.12.1.5/24", "10.12.1.9/24", "10.13.0.0/16"})
	if err != nil {
		t.Fatalf("add routes: %v", err)
	}
	if len(added) != 2 || added[0] != "10.12.1.0/24" || added[1] != "10.13.0.0/16" {
		t.Fatalf("added = %v; want [10.12.1.0/24 10.13.0.0/16]", added)
	}

	// A second add of the same route reports nothing new and bumps nothing.
	added, err = s.AddRoutes("node1", []string{"10.12.1.0/24"})
	if err != nil {
		t.Fatalf("add routes again: %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("re-adding should add nothing, got %v", added)
	}

	cc := loadCC(t)
	c := findByName(cc, "node1")
	if c == nil || len(c.Routes) != 2 {
		t.Fatalf("client routes = %v; want 2 entries", c.Routes)
	}
	if c.UpdatedAt == "" {
		t.Errorf("adding a route should bump the client's UpdatedAt so peers re-sync")
	}
}

func TestRoutesHub(t *testing.T) {
	s := newCoordConfig(t)
	if _, err := s.AddRoutes("coordinator", []string{"10.12.0.0/24"}); err != nil {
		t.Fatalf("add hub route: %v", err)
	}
	cc := loadCC(t)
	if len(cc.Routes) != 1 || cc.Routes[0] != "10.12.0.0/24" {
		t.Fatalf("hub routes = %v; want [10.12.0.0/24]", cc.Routes)
	}
	if cc.UpdatedAt == "" {
		t.Errorf("changing hub routes should bump the hub UpdatedAt")
	}

	removed, err := s.RemoveRoutes("hub", []string{"10.12.0.0/24"})
	if err != nil {
		t.Fatalf("remove hub route: %v", err)
	}
	if len(removed) != 1 || removed[0] != "10.12.0.0/24" {
		t.Fatalf("removed = %v; want [10.12.0.0/24]", removed)
	}
	if got := loadCC(t).Routes; len(got) != 0 {
		t.Fatalf("hub routes after remove = %v; want empty", got)
	}
}

func TestRoutesUnknownNode(t *testing.T) {
	s := newCoordConfig(t)
	if _, err := s.AddRoutes("ghost", []string{"10.12.1.0/24"}); err == nil {
		t.Fatal("adding routes to an unknown node should error")
	}
}

func TestAddRoutesRejectsBadCIDR(t *testing.T) {
	s := newCoordConfig(t)
	if _, _, err := s.AddClient("node1", "10.8.0.2", nil); err != nil {
		t.Fatalf("add client: %v", err)
	}
	if _, err := s.AddRoutes("node1", []string{"not-a-cidr"}); err == nil {
		t.Fatal("a bad CIDR should be rejected")
	}
	if got := loadCC(t).Clients[0].Routes; len(got) != 0 {
		t.Fatalf("nothing should have been stored, got %v", got)
	}
}

// TestHeartbeatReAdvertisesHubOnRouteChange verifies that after the hub's routes
// change, a client that already holds the coordinator peer is re-sent it (with
// the new AllowedIPs) on its next heartbeat — the delta logic keyed on the hub's
// own UpdatedAt.
func TestHeartbeatReAdvertisesHubOnRouteChange(t *testing.T) {
	config.SetPath(filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { config.SetPath("") })

	hub, _ := wgkey.Generate()
	a, _ := wgkey.Generate()
	tokA, _ := token.Generate()

	cc := &config.CoordinatorConfig{
		ControlPort: 51821,
		Interface:   "wg0",
		ListenPort:  51820,
		IPRange:     "10.8.0.0/24",
		Address:     "10.8.0.1",
		PublicKey:   hub.PublicKey,
		Routes:      []string{"10.12.0.0/24"},
		UpdatedAt:   "2020-01-02T00:00:00Z", // hub routes changed after A last synced
		Clients: []*config.Client{
			{ID: "a", Name: "node1", TokenHash: token.Hash(tokA), Address: "10.8.0.2",
				PublicKey: a.PublicKey, LastSeenAt: "2020-01-01T00:00:00Z", Have: []string{api.CoordinatorPeerID}},
		},
	}
	if err := config.Save(&config.Config{Mode: config.ModeCoordinator, Coordinator: cc}); err != nil {
		t.Fatalf("save: %v", err)
	}

	srv := httptest.NewServer(NewServer(NewStore()).Handler())
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(api.HeartbeatRequest{Have: []string{api.CoordinatorPeerID}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokA)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	var hb api.HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var hubPeer *api.Peer
	for i := range hb.Add {
		if hb.Add[i].ID == api.CoordinatorPeerID {
			hubPeer = &hb.Add[i]
		}
	}
	if hubPeer == nil {
		t.Fatalf("hub peer not re-advertised after a route change; Add=%+v", hb.Add)
	}
	if hubPeer.AllowedIPs != "10.8.0.1/32, 10.12.0.0/24" {
		t.Errorf("hub AllowedIPs = %q; want %q", hubPeer.AllowedIPs, "10.8.0.1/32, 10.12.0.0/24")
	}
}
