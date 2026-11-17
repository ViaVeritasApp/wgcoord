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

// accessFixture is a k3s-like mesh: hub + node1 + node2 carrying pod ranges,
// a "development" group on the node mesh IPs with two ports, and two hub-only
// clients.
func accessFixture() *config.CoordinatorConfig {
	return &config.CoordinatorConfig{
		PublicKey: "hubpub",
		IPRange:   "10.8.0.0/24",
		Address:   "10.8.0.1",
		Routes:    []string{"10.42.0.0/24"},
		Groups: []*config.Group{
			{Name: "development", Entries: []config.GroupEntry{{CIDR: "10.8.0.0/28", Ports: []string{"tcp/15432", "tcp/16379"}}}},
			{Name: "pods-1", Entries: []config.GroupEntry{{CIDR: "10.42.1.0/24"}}},
		},
		Clients: []*config.Client{
			{ID: "n1", Name: "node1", PublicKey: "n1pub", Address: "10.8.0.11", Routes: []string{"pods-1"}},
			{ID: "n2", Name: "node2", PublicKey: "n2pub", Address: "10.8.0.12", Routes: []string{"10.42.2.0/24"}},
			{ID: "al", Name: "alice", PublicKey: "alpub", Address: "10.8.0.101", HubOnly: true,
				Grants: []config.Grant{{Target: "development"}, {Target: "10.42.0.0/16", Ports: []string{"tcp/8080"}}}},
			{ID: "bo", Name: "bob", PublicKey: "bopub", Address: "10.8.0.102", HubOnly: true,
				Grants: []config.Grant{{Target: GrantAll}}},
		},
	}
}

func peersByID(ps []api.Peer) map[string]api.Peer {
	m := map[string]api.Peer{}
	for _, p := range ps {
		m[p.ID] = p
	}
	return m
}

func TestResolveRoutesExpandsGroups(t *testing.T) {
	cc := accessFixture()
	got := resolveRoutes(cc, []string{"pods-1", "10.42.9.0/24", "missing-group", "pods-1"})
	if len(got) != 2 || got[0] != "10.42.1.0/24" || got[1] != "10.42.9.0/24" {
		t.Fatalf("resolveRoutes = %v", got)
	}
}

func TestBuildPeersHubOnlyGetsOnlyHub(t *testing.T) {
	cc := accessFixture()
	peers := buildPeers(cc, "al")
	if len(peers) != 1 || peers[0].ID != api.CoordinatorPeerID {
		t.Fatalf("hub-only client should see only the hub, got %+v", peers)
	}
	// Mesh range + the pod ranges, cut to what is routed (10.42.0.0/16 is not
	// itself a route; its three routed /24s are).
	want := "10.8.0.0/24, 10.42.0.0/24, 10.42.1.0/24, 10.42.2.0/24"
	if peers[0].AllowedIPs != want {
		t.Fatalf("alice hub AllowedIPs = %q; want %q", peers[0].AllowedIPs, want)
	}
}

func TestBuildPeersMeshNeverSeesHubOnly(t *testing.T) {
	cc := accessFixture()
	byID := peersByID(buildPeers(cc, "n1"))
	if _, ok := byID["al"]; ok {
		t.Fatal("mesh client must not receive hub-only peers")
	}
	if got := byID["n2"].AllowedIPs; got != "10.8.0.12/32, 10.42.2.0/24" {
		t.Errorf("node2 AllowedIPs = %q", got)
	}
	// Replies to hub-only clients must route via the hub.
	want := "10.8.0.1/32, 10.42.0.0/24, 10.8.0.101/32, 10.8.0.102/32"
	if got := byID[api.CoordinatorPeerID].AllowedIPs; got != want {
		t.Fatalf("hub AllowedIPs (mesh view) = %q; want %q", got, want)
	}
	// node2 sees node1's group route expanded.
	if got := peersByID(buildPeers(cc, "n2"))["n1"].AllowedIPs; got != "10.8.0.11/32, 10.42.1.0/24" {
		t.Errorf("node1 AllowedIPs = %q", got)
	}
}

func TestBlacklistedHubOnlyLeavesHubAllowedIPs(t *testing.T) {
	cc := accessFixture()
	findByID(cc, "bo").Blacklisted = true
	got := peersByID(buildPeers(cc, "n1"))[api.CoordinatorPeerID].AllowedIPs
	if got != "10.8.0.1/32, 10.42.0.0/24, 10.8.0.101/32" {
		t.Fatalf("hub AllowedIPs = %q", got)
	}
}

func TestEffectiveRules(t *testing.T) {
	cc := accessFixture()
	var got []string
	for _, r := range effectiveRules(cc, findByID(cc, "al")) {
		got = append(got, ruleKey(r))
	}
	want := []string{
		"10.8.0.0/28 tcp/15432 tcp/16379",
		"10.42.0.0/24 tcp/8080",
		"10.42.1.0/24 tcp/8080",
		"10.42.2.0/24 tcp/8080",
	}
	if len(got) != len(want) {
		t.Fatalf("rules = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rules = %v; want %v", got, want)
		}
	}
}

func TestEffectiveRulesPortIntersection(t *testing.T) {
	cc := accessFixture()
	c := findByID(cc, "al")
	c.Grants = []config.Grant{{Target: "development", Ports: []string{"tcp/15432", "udp/53"}}}
	rules := effectiveRules(cc, c)
	if len(rules) != 1 || ruleKey(rules[0]) != "10.8.0.0/28 tcp/15432" {
		t.Fatalf("rules = %+v", rules)
	}
	c.Grants = []config.Grant{{Target: "development", Ports: []string{"udp/53"}}}
	if rules := effectiveRules(cc, c); len(rules) != 0 {
		t.Fatalf("disjoint ports should grant nothing, got %+v", rules)
	}
}

func TestAllGrantFollowsRoutes(t *testing.T) {
	cc := accessFixture()
	bob := findByID(cc, "bo")
	before := hubPeerAllowed(cc, bob)
	findByID(cc, "n2").Routes = append(findByID(cc, "n2").Routes, "192.168.50.0/24")
	after := hubPeerAllowed(cc, bob)
	if len(after) != len(before)+1 || after[len(after)-1] != "192.168.50.0/24" {
		t.Fatalf("all grant did not follow a new route: before %v after %v", before, after)
	}
}

func TestDesiredInterfaceHubOnly(t *testing.T) {
	cc := accessFixture()
	cc.Interface, cc.PrivateKey = "wg0", "priv"
	iface, err := desiredInterface(cc, true)
	if err != nil {
		t.Fatal(err)
	}
	var alice []string
	for _, p := range iface.Peers {
		if p.PublicKey == "alpub" {
			alice = p.AllowedIPs
		}
	}
	if len(alice) != 1 || alice[0] != "10.8.0.101/32" {
		t.Fatalf("alice on hub = %v; want only her /32", alice)
	}
	iface, _ = desiredInterface(cc, false)
	for _, p := range iface.Peers {
		if p.PublicKey == "alpub" || p.PublicKey == "bopub" {
			t.Fatal("hub-only peers must be left out when the firewall is not in place")
		}
	}
	if len(iface.Peers) != 2 {
		t.Fatalf("mesh peers should remain, got %d", len(iface.Peers))
	}
}

// TestHeartbeatResendsHubToHubOnlyOnlyWhenChanged checks the content-based
// change detection for a hub-only client's view of the coordinator.
func TestHeartbeatResendsHubToHubOnlyOnlyWhenChanged(t *testing.T) {
	config.SetPath(filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { config.SetPath("") })
	hub, _ := wgkey.Generate()
	al, _ := wgkey.Generate()
	tok, _ := token.Generate()
	cc := accessFixture()
	cc.PublicKey = hub.PublicKey
	alice := findByID(cc, "al")
	alice.PublicKey, alice.TokenHash = al.PublicKey, token.Hash(tok)
	if err := config.Save(&config.Config{Mode: config.ModeCoordinator, Coordinator: cc}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(NewStore()).Handler())
	t.Cleanup(srv.Close)

	beat := func() api.HeartbeatResponse {
		t.Helper()
		body, _ := json.Marshal(api.HeartbeatRequest{Have: []string{api.CoordinatorPeerID}})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/heartbeat", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var hb api.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hb); err != nil {
			t.Fatal(err)
		}
		return hb
	}

	first := beat() // SentHub empty: the hub is sent once
	if len(first.Add) != 1 || !first.HubOnly {
		t.Fatalf("first beat: add=%+v hubOnly=%v", first.Add, first.HubOnly)
	}
	if second := beat(); len(second.Add) != 0 {
		t.Fatalf("unchanged view should not be re-sent, got %+v", second.Add)
	}
	// Dropping the pod grant shrinks the view: the hub peer comes back.
	if err := NewStore().Mutate(func(cc *config.CoordinatorConfig) error {
		findByID(cc, "al").Grants = []config.Grant{{Target: "development"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	third := beat()
	if len(third.Add) != 1 || third.Add[0].AllowedIPs != "10.8.0.0/24" {
		t.Fatalf("after grant change: %+v", third.Add)
	}
}
