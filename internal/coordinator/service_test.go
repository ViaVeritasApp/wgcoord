package coordinator

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"wgcoord/internal/config"
	"wgcoord/internal/firewall"
)

// fakeHost records what reconcile asked of the host.
type fakeHost struct {
	avail    bool
	applyErr error
	applied  []firewall.Spec
	forwards int
}

func (f *fakeHost) enforcer() enforcer {
	return enforcer{
		available: func() bool { return f.avail },
		apply:     func(s firewall.Spec) error { f.applied = append(f.applied, s); return f.applyErr },
		forward:   func(bool) (bool, error) { f.forwards++; return f.forwards == 1, nil },
		routes:    func(string, []string) error { return nil },
	}
}

func newTestService(f *fakeHost) (*Service, *bytes.Buffer) {
	var buf bytes.Buffer
	s := NewService(log.New(&buf, "", 0))
	s.fw = f.enforcer()
	return s, &buf
}

func TestEnforceFailsClosed(t *testing.T) {
	spec := firewallSpec(accessFixture())
	if len(spec.Clients) != 2 {
		t.Fatalf("spec clients = %d; want 2", len(spec.Clients))
	}

	// No nft: hub-only clients are left off, and it is said once.
	f := &fakeHost{avail: false}
	s, logs := newTestService(f)
	if s.enforce(spec) || s.enforce(spec) {
		t.Fatal("without a firewall hub-only clients must be excluded")
	}
	if n := strings.Count(logs.String(), "left off"); n != 1 {
		t.Fatalf("unsupported warning logged %d times; want 1:\n%s", n, logs)
	}

	// nft fails: same, fail closed.
	f = &fakeHost{avail: true, applyErr: errors.New("boom")}
	s, logs = newTestService(f)
	if s.enforce(spec) {
		t.Fatal("a failed firewall apply must exclude hub-only clients")
	}
	if !strings.Contains(logs.String(), "boom") {
		t.Fatalf("apply error not logged:\n%s", logs)
	}
	// ...and recovers when it applies again.
	f.applyErr = nil
	if !s.enforce(spec) {
		t.Fatal("a working firewall should include hub-only clients")
	}
	if !strings.Contains(logs.String(), "firewall: recovered") {
		t.Fatalf("recovery not logged:\n%s", logs)
	}
	if f.forwards == 0 {
		t.Fatal("forwarding should be enabled when there is something to forward")
	}
}

func TestEnforceEmptySpecRemovesTableOnce(t *testing.T) {
	cc := accessFixture()
	cc.Clients = cc.Clients[:2] // mesh only
	spec := firewallSpec(cc)
	f := &fakeHost{avail: true}
	s, _ := newTestService(f)
	for i := 0; i < 3; i++ {
		if !s.enforce(spec) {
			t.Fatal("mesh-only coordinator must keep its peers")
		}
	}
	if len(f.applied) != 1 || !f.applied[0].Empty() {
		t.Fatalf("empty spec should be applied (table removed) exactly once, got %d", len(f.applied))
	}
	if f.forwards != 0 {
		t.Fatal("forwarding must not be touched when nothing needs it")
	}
	// Mesh-only hosts without nft are unaffected.
	f2 := &fakeHost{avail: false}
	s2, logs := newTestService(f2)
	if !s2.enforce(spec) || logs.Len() != 0 {
		t.Fatalf("mesh-only host without nft should be silent and keep peers: %q", logs)
	}
}

func TestFirewallSpecNAT(t *testing.T) {
	cc := accessFixture()
	cc.Groups = append(cc.Groups, &config.Group{Name: "cloud", Entries: []config.GroupEntry{{CIDR: "172.30.0.0/24"}}})
	cc.Routes = append(cc.Routes, "cloud")
	cc.NATRoutes = []string{"cloud"}
	spec := firewallSpec(cc)
	if len(spec.NAT) != 1 || spec.NAT[0].String() != "172.30.0.0/24" {
		t.Fatalf("NAT = %v", spec.NAT)
	}
	if spec.Hub.String() != "10.8.0.1" || spec.Mesh.String() != "10.8.0.0/24" {
		t.Fatalf("hub/mesh = %v %v", spec.Hub, spec.Mesh)
	}
}
