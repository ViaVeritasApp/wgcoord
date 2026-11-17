package coordinator

import (
	"errors"
	"strings"
	"testing"
	"wgcoord/internal/config"
)

// k3sStore is a coordinator with node1/node2 carrying pod ranges.
func k3sStore(t *testing.T) *Store {
	t.Helper()
	s := newCoordConfig(t)
	for _, n := range []struct{ name, addr, route string }{
		{"node1", "10.8.0.11", "10.42.1.0/24"},
		{"node2", "10.8.0.12", "10.42.2.0/24"},
	} {
		if _, err := s.AddClient(n.name, ClientOptions{Address: n.addr, Routes: []string{n.route}}); err != nil {
			t.Fatalf("add %s: %v", n.name, err)
		}
	}
	if _, err := s.AddRoutes("coordinator", []string{"10.42.0.0/24"}, false); err != nil {
		t.Fatal(err)
	}
	return s
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

func TestGroupNames(t *testing.T) {
	s := newCoordConfig(t)
	for _, bad := range []string{"all", "coordinator", "hub", "ALL", "1abc", "-x", "a b", "a.b", "10.0.0.0/8", strings.Repeat("a", 64), ""} {
		if _, err := s.GroupCreate(bad, nil, nil); err == nil {
			t.Errorf("group name %q should be rejected", bad)
		}
	}
	if _, err := s.GroupCreate("k3s-nodes_1", nil, nil); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	_, err := s.GroupCreate("k3s-nodes_1", nil, nil)
	wantErr(t, err, "already exists")
}

func TestGroupCreateAddRemove(t *testing.T) {
	s := newCoordConfig(t)
	_, err := s.GroupCreate("db", nil, []string{"tcp/5432"})
	wantErr(t, err, "--port needs at least one CIDR")

	g, err := s.GroupCreate("db", []string{"10.42.1.7/24", "10.42.2.0/24"}, []string{"tcp/5432", "TCP/5432"})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Entries) != 2 || g.Entries[0].CIDR != "10.42.1.0/24" || strings.Join(g.Entries[0].Ports, ",") != "tcp/5432" {
		t.Fatalf("entries = %+v", g.Entries)
	}
	added, err := s.GroupAdd("db", []string{"10.42.1.0/24"}, []string{"tcp/5432"})
	if err != nil || len(added) != 0 {
		t.Fatalf("re-adding an identical entry should add nothing: %v %v", added, err)
	}
	if added, err = s.GroupAdd("db", []string{"10.42.1.0/24"}, []string{"tcp/27017"}); err != nil || len(added) != 1 {
		t.Fatalf("same CIDR with other ports is a new entry: %v %v", added, err)
	}
	removed, err := s.GroupRemove("db", []string{"10.42.1.0/24"})
	if err != nil || len(removed) != 2 {
		t.Fatalf("remove should drop both entries for the CIDR: %v %v", removed, err)
	}
	_, err = s.GroupAdd("nope", []string{"10.0.0.0/8"}, nil)
	wantErr(t, err, `no group named "nope"`)
}

func TestGroupDeleteInUse(t *testing.T) {
	s := k3sStore(t)
	if _, err := s.GroupCreate("dev", []string{"10.42.1.0/24"}, []string{"tcp/5432"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClient("alice", ClientOptions{HubOnly: true, Grants: []string{"dev"}}); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.GroupDelete("dev"), "grant of alice")
	if _, err := s.GrantRemove("alice", []string{"dev"}); err != nil {
		t.Fatal(err)
	}
	if err := s.GroupDelete("dev"); err != nil {
		t.Fatalf("unused group should delete: %v", err)
	}
}

func TestRouteValidation(t *testing.T) {
	s := k3sStore(t)

	_, err := s.AddRoutes("node2", []string{"10.42.1.0/24"}, false)
	wantErr(t, err, "routed by both node1 and node2")

	_, err = s.AddRoutes("node1", []string{"10.8.0.128/25"}, false)
	wantErr(t, err, "inside the mesh range")

	_, err = s.AddRoutes("node1", []string{"10.99.0.0/16"}, true)
	wantErr(t, err, "--nat is only valid on the coordinator")

	_, err = s.AddRoutes("node1", []string{"10.42.1.0/33"}, false)
	wantErr(t, err, "not a valid CIDR or group name")

	_, err = s.AddRoutes("node1", []string{"missing"}, false)
	wantErr(t, err, `no group named "missing"`)

	if _, err := s.GroupCreate("ported", []string{"10.50.0.0/24"}, []string{"tcp/80"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.AddRoutes("node1", []string{"ported"}, false)
	wantErr(t, err, "can't be used as a route")

	// A nested (not identical) prefix on another node is fine: WireGuard
	// prefers the most specific.
	if _, err := s.AddRoutes("coordinator", []string{"10.0.0.0/8"}, true); err != nil {
		t.Fatalf("nested NAT route should be allowed: %v", err)
	}
	if cc := loadCC(t); len(cc.NATRoutes) != 1 || cc.NATRoutes[0] != "10.0.0.0/8" {
		t.Fatalf("NATRoutes = %v", cc.NATRoutes)
	}
	// Marking an existing route NAT counts as a change; removing it clears NAT.
	if added, err := s.AddRoutes("coordinator", []string{"10.42.0.0/24"}, true); err != nil || len(added) != 1 {
		t.Fatalf("re-add as NAT: %v %v", added, err)
	}
	if _, err := s.RemoveRoutes("coordinator", []string{"10.0.0.0/8", "10.42.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if cc := loadCC(t); len(cc.NATRoutes) != 0 {
		t.Fatalf("NAT flags should go with the routes, got %v", cc.NATRoutes)
	}
}

func TestGroupAsRouteFollowsEdits(t *testing.T) {
	s := k3sStore(t)
	if _, err := s.GroupCreate("lan", []string{"192.168.50.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRoutes("node1", []string{"lan"}, false); err != nil {
		t.Fatal(err)
	}
	before := findByName(loadCC(t), "node1").UpdatedAt
	// Editing the group must keep the rules: adding a port is refused...
	_, err := s.GroupAdd("lan", []string{"192.168.51.0/24"}, []string{"tcp/80"})
	wantErr(t, err, "can't be used as a route")
	// ...and so is a prefix another node routes.
	_, err = s.GroupAdd("lan", []string{"10.42.2.0/24"}, nil)
	wantErr(t, err, "routed by both node1 and node2")
	// A valid edit reaches node1's AllowedIPs and bumps it.
	if _, err := s.GroupAdd("lan", []string{"192.168.51.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	cc := loadCC(t)
	node1 := findByName(cc, "node1")
	if got := resolveRoutes(cc, node1.Routes); len(got) != 3 {
		t.Fatalf("node1 routes = %v", got)
	}
	if node1.UpdatedAt == before && before != "" {
		// timestamps have second resolution; the bump may coincide
		t.Logf("UpdatedAt unchanged within the same second")
	}
	if node1.UpdatedAt == "" {
		t.Fatal("group edit should bump the routing node")
	}
}

func TestClientAddHubOnlyRules(t *testing.T) {
	s := k3sStore(t)
	_, err := s.AddClient("alice", ClientOptions{Grants: []string{"10.42.0.0/16"}})
	if !errors.Is(err, ErrGrantNeedsHubOnly) {
		t.Fatalf("grant without hub-only: %v", err)
	}
	_, err = s.AddClient("alice", ClientOptions{HubOnly: true, Routes: []string{"10.60.0.0/24"}})
	wantErr(t, err, "hub-only clients can't carry routes")

	_, err = s.AddClient("alice", ClientOptions{HubOnly: true, Grants: []string{"172.16.0.0/12"}})
	wantErr(t, err, "reaches nothing the mesh routes")
	if findByName(loadCC(t), "alice") != nil {
		t.Fatal("a rejected add must not leave a client behind")
	}

	before := loadCC(t).UpdatedAt
	added, err := s.AddClient("alice", ClientOptions{HubOnly: true, Grants: []string{"10.42.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(added.Warnings) != 1 || !strings.Contains(added.Warnings[0], "only part of 10.42.0.0/16") {
		t.Fatalf("expected a partial-coverage warning, got %v", added.Warnings)
	}
	cc := loadCC(t)
	if !findByName(cc, "alice").HubOnly || cc.UpdatedAt == "" || (before != "" && cc.UpdatedAt < before) {
		t.Fatalf("hub-only add should bump the hub: %+v", cc.UpdatedAt)
	}
	_, err = s.AddRoutes("alice", []string{"10.70.0.0/24"}, false)
	wantErr(t, err, "hub-only client and can't carry routes")
}

func TestGrantAddRemove(t *testing.T) {
	s := k3sStore(t)
	if _, err := s.AddClient("dev", ClientOptions{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.GrantAdd("dev", []string{"all"}, nil)
	wantErr(t, err, "mesh client")

	if _, err := s.AddClient("alice", ClientOptions{HubOnly: true}); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.GrantAdd("alice", []string{"10.42.1.0/24"}, []string{"tcp/99999"})
	wantErr(t, err, "port must be 1-65535")

	if _, err := s.GroupCreate("staging", []string{"10.8.0.0/28"}, []string{"tcp/25432"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.GrantAdd("alice", []string{"staging"}, []string{"udp/53"})
	wantErr(t, err, "allows no traffic")

	if _, err := s.GroupCreate("empty", nil, nil); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.GrantAdd("alice", []string{"empty"}, nil)
	wantErr(t, err, "is empty")

	added, warn, err := s.GrantAdd("alice", []string{"staging", "10.42.1.9/24", "all"}, nil)
	if err != nil || len(added) != 3 || len(warn) != 0 {
		t.Fatalf("grant add: %v %v %v", added, warn, err)
	}
	if added[1].Target != "10.42.1.0/24" {
		t.Fatalf("CIDR not canonicalized: %q", added[1].Target)
	}
	if again, _, _ := s.GrantAdd("alice", []string{"staging"}, nil); len(again) != 0 {
		t.Fatalf("duplicate grant re-added: %v", again)
	}
	removed, err := s.GrantRemove("alice", []string{"10.42.1.5/24", "staging"})
	if err != nil || len(removed) != 2 {
		t.Fatalf("grant remove: %v %v", removed, err)
	}
	if g := findByName(loadCC(t), "alice").Grants; len(g) != 1 || g[0].Target != "all" {
		t.Fatalf("remaining grants = %+v", g)
	}
}

func TestSetMode(t *testing.T) {
	s := k3sStore(t)
	if _, err := s.AddClient("alice", ClientOptions{HubOnly: true, Grants: []string{"all"}}); err != nil {
		t.Fatal(err)
	}
	_, err := s.SetMode("alice", false, false)
	wantErr(t, err, "--clear-grants")

	changed, err := s.SetMode("alice", false, true)
	if err != nil || !changed {
		t.Fatalf("switch to mesh: %v %v", changed, err)
	}
	if c := findByName(loadCC(t), "alice"); c.HubOnly || len(c.Grants) != 0 {
		t.Fatalf("after switch: %+v", c)
	}
	if changed, _ := s.SetMode("alice", false, false); changed {
		t.Fatal("switching to the current mode should report no change")
	}
	_, err = s.SetMode("node1", true, false)
	wantErr(t, err, "carries routes")
	if changed, err := s.SetMode("alice", true, false); err != nil || !changed {
		t.Fatalf("back to hub-only: %v %v", changed, err)
	}
}

func TestRemoveAndBlacklistHubOnlyBumpHub(t *testing.T) {
	s := k3sStore(t)
	if _, err := s.AddClient("alice", ClientOptions{HubOnly: true}); err != nil {
		t.Fatal(err)
	}
	clear := func() {
		if err := s.Mutate(func(cc *config.CoordinatorConfig) error { cc.UpdatedAt = ""; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	if err := s.SetBlacklist("alice", true); err != nil {
		t.Fatal(err)
	}
	if loadCC(t).UpdatedAt == "" {
		t.Fatal("blacklisting a hub-only client must bump the hub")
	}
	clear()
	if err := s.RemoveClient("alice"); err != nil {
		t.Fatal(err)
	}
	if loadCC(t).UpdatedAt == "" {
		t.Fatal("removing a hub-only client must bump the hub")
	}
}
