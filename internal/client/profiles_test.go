package client

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/wgctl"
)

// fakeWG records interface calls instead of touching the host.
type fakeWG struct {
	mu     sync.Mutex
	events []string
}

func (f *fakeWG) log(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeWG) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.events
	f.events = nil
	return out
}

// withProfiles points the config at a temp dir holding profiles, with the
// interface calls faked. Profile names map to interface names.
func withProfiles(t *testing.T, active string, profiles map[string]string) *fakeWG {
	t.Helper()
	config.SetPath(filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { config.SetPath("") })
	f := &fakeWG{}
	wgApply = func(i wgctl.Interface) error { f.log("up " + i.Name + " " + i.PrivateKey); return nil }
	wgDown = func(name string) error { f.log("down " + name); return nil }
	wgSyncRoutes = func(_ string, _, managed []string) ([]string, error) { return managed, nil }
	wgTagsRoutes = func() bool { return false }
	t.Cleanup(func() {
		wgApply, wgDown, wgSyncRoutes, wgTagsRoutes = wgctl.Apply, wgctl.Down, wgctl.SyncRoutes, wgctl.TagsRoutes
	})
	c := &config.Config{Mode: config.ModeClient, ActiveProfile: active, Profiles: map[string]*config.ClientConfig{}}
	for name, iface := range profiles {
		c.Profiles[name] = &config.ClientConfig{
			Name: name + "-node", Interface: iface, PrivateKey: "key-" + name,
			Address: "10.8.0.2", IPRange: "10.8.0.0/24", CoordinatorURL: "http://" + name + ".invalid",
		}
	}
	if len(profiles) > 0 {
		if err := config.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func load(t *testing.T) *config.Config {
	t.Helper()
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUseClosesEveryProfileThenBringsUpTarget(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg0", "lab": "wg1"})

	a, err := Use("nx")
	if err != nil {
		t.Fatal(err)
	}
	if a.Previous != "vv" || a.Profile != "nx" {
		t.Fatalf("got %+v", a)
	}
	// wg0 once (shared by two profiles), wg1, then nx's own key comes up.
	got := strings.Join(f.take(), "; ")
	if got != "down wg1; down wg0; up wg0 key-nx" {
		t.Fatalf("interface calls = %q", got)
	}
	if c := load(t); c.ActiveProfile != "nx" {
		t.Fatalf("active = %q", c.ActiveProfile)
	}
}

func TestUseUnknownProfileKeepsActive(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0"})
	if _, err := Use("nope"); err == nil || !strings.Contains(err.Error(), `no profile named "nope"`) {
		t.Fatalf("want unknown-profile error, got %v", err)
	}
	if ev := f.take(); len(ev) != 0 {
		t.Fatalf("interface touched: %v", ev)
	}
	if c := load(t); c.ActiveProfile != "vv" {
		t.Fatalf("active = %q", c.ActiveProfile)
	}
}

func TestUpOtherProfileSwitches(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg1"})
	if _, err := Up("nx"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.take(), "; "); got != "down wg1; down wg0; up wg1 key-nx" {
		t.Fatalf("interface calls = %q", got)
	}
	// Up on the active profile only re-applies.
	if _, err := Up(""); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.take(), "; "); got != "up wg1 key-nx" {
		t.Fatalf("interface calls = %q", got)
	}
}

func TestDownRefusesInterfaceOfActiveProfile(t *testing.T) {
	withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg0"})
	if _, err := Down("nx"); err == nil || !strings.Contains(err.Error(), "belongs to the active profile") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestEndpointOverrideOnInactiveProfileIsNotApplied(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg1"})
	e, err := SetEndpointOverride("nx", "peer", "192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Applied.Skipped || len(f.take()) != 0 {
		t.Fatal("inactive profile was applied")
	}
	if got := load(t).Profiles["nx"].EndpointOverrides["peer"]; got != "192.168.1.5" {
		t.Fatalf("override not saved: %q", got)
	}
}

// heartbeatServer answers heartbeats with one peer added.
func heartbeatServer(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(api.HeartbeatResponse{
			Address: "10.8.0.2", IPRange: "10.8.0.0/24",
			Add: []api.Peer{{ID: "p1", Name: "peer1", PublicKey: "pk1", AllowedIPs: "10.8.0.3/32"}},
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func setURL(t *testing.T, profile, url string) {
	t.Helper()
	if err := mutate(false, func(c *config.Config) error {
		c.Profiles[profile].CoordinatorURL = url
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSyncInactiveProfileSavesButDoesNotApply(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg1"})
	var hits atomic.Int64
	setURL(t, "nx", heartbeatServer(t, &hits).URL)

	res, err := Sync("nx")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied.Skipped || len(f.take()) != 0 {
		t.Fatal("inactive profile was applied")
	}
	if n := len(load(t).Profiles["nx"].Peers); n != 1 {
		t.Fatalf("peers saved = %d", n)
	}
}

func TestRunFollowsActiveProfile(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg1"})
	var vvHits, nxHits atomic.Int64
	setURL(t, "vv", heartbeatServer(t, &vvHits).URL)
	setURL(t, "nx", heartbeatServer(t, &nxHits).URL)
	profilePoll = 20 * time.Millisecond
	t.Cleanup(func() { profilePoll = 2 * time.Second })

	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- Run(ctx, log.New(&logs, "", 0)) }()

	waitFor(t, func() bool { return hasEvent(f, "up wg0 key-vv") })
	if _, err := Use("nx"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return nxHits.Load() > 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `profile "vv" is no longer active`) {
		t.Fatalf("switch not logged:\n%s", logs.String())
	}
	// After the switch, nothing may bring vv's key back up.
	ev := f.take()
	last := -1
	for i, e := range ev {
		if e == "up wg1 key-nx" && last < 0 {
			last = i
		}
	}
	for _, e := range ev[last+1:] {
		if strings.HasSuffix(e, "key-vv") {
			t.Fatalf("vv re-applied after switch: %v", ev)
		}
	}
}

// hasEvent reports whether f recorded e, keeping the events for later checks.
func hasEvent(f *fakeWG, e string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.events {
		if x == e {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 5s")
}

func TestJoinSecondProfile(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0"})
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{ID: "id2", Name: "laptop", Address: "10.9.0.2", IPRange: "10.9.0.0/24"})
	}))
	t.Cleanup(reg.Close)

	if _, err := Join(JoinOptions{CoordinatorURL: reg.URL, Token: "t"}); err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Fatalf("unnamed second join: want --profile error, got %v", err)
	}
	if _, err := Join(JoinOptions{Profile: "vv", CoordinatorURL: reg.URL, Token: "t"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("taken name: want error, got %v", err)
	}
	j, err := Join(JoinOptions{Profile: "nx", CoordinatorURL: reg.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if j.Active || !j.Applied.Skipped || len(f.take()) != 0 {
		t.Fatalf("second profile must not take over: %+v", j)
	}
	c := load(t)
	if c.ActiveProfile != "vv" || c.Profiles["nx"].Address != "10.9.0.2" {
		t.Fatalf("got active %q, nx %+v", c.ActiveProfile, c.Profiles["nx"])
	}
}

func TestJoinFirstProfileIsActive(t *testing.T) {
	f := withProfiles(t, "", nil)
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.RegisterResponse{ID: "id1", Name: "laptop", Address: "10.8.0.2", IPRange: "10.8.0.0/24"})
	}))
	t.Cleanup(reg.Close)
	j, err := Join(JoinOptions{CoordinatorURL: reg.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if j.Profile != config.DefaultProfile || !j.Active {
		t.Fatalf("got %+v", j)
	}
	if ev := f.take(); len(ev) != 1 || !strings.HasPrefix(ev[0], "up wg0 ") {
		t.Fatalf("interface calls = %v", ev)
	}
}

func TestImportLegacyConfig(t *testing.T) {
	withProfiles(t, "vv", map[string]string{"vv": "wg0"})
	legacy := filepath.Join(t.TempDir(), "config.json")
	raw := `{"mode":"client","client":{"name":"mac","coordinator_url":"http://nx.invalid","interface":"wg0","public_key":"pk-nx","private_key":"k"}}`
	if err := os.WriteFile(legacy, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cc, err := ImportProfile("nx", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Name != "mac" {
		t.Fatalf("imported %+v", cc)
	}
	c := load(t)
	if c.ActiveProfile != "vv" || c.Profiles["nx"].CoordinatorURL != "http://nx.invalid" {
		t.Fatalf("got active %q, nx %+v", c.ActiveProfile, c.Profiles["nx"])
	}
	if _, err := ImportProfile("nx2", legacy); err == nil || !strings.Contains(err.Error(), "already imported") {
		t.Fatalf("second import: want error, got %v", err)
	}
}

func TestRemoveActiveProfile(t *testing.T) {
	f := withProfiles(t, "vv", map[string]string{"vv": "wg0", "nx": "wg1"})
	wasActive, err := RemoveProfile("vv")
	if err != nil || !wasActive {
		t.Fatalf("wasActive=%v err=%v", wasActive, err)
	}
	if got := strings.Join(f.take(), "; "); got != "down wg0" {
		t.Fatalf("interface calls = %q", got)
	}
	c := load(t)
	if c.ActiveProfile != "" || c.Profiles["vv"] != nil || c.Profiles["nx"] == nil {
		t.Fatalf("got %+v", c)
	}
}

func TestRenameActiveProfile(t *testing.T) {
	withProfiles(t, "default", map[string]string{"default": "wg0"})
	if err := RenameProfile("default", "vv"); err != nil {
		t.Fatal(err)
	}
	if c := load(t); c.ActiveProfile != "vv" || c.Profiles["vv"] == nil {
		t.Fatalf("got %+v", c)
	}
}
