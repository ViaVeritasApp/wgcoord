package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/wgctl"
)

// meshConfig is a joined client whose "mesh" is loopback, so httptest servers
// count as in-range in-mesh addresses.
func meshConfig(t *testing.T, internalURL, publicURL string) *config.ClientConfig {
	t.Helper()
	internalUntil = time.Time{} // package state: no cooldown carried between tests
	meshAvailable = func() bool { return true }
	t.Cleanup(func() { meshAvailable = wgctl.Available })
	return &config.ClientConfig{
		CoordinatorURL: publicURL,
		InternalURL:    internalURL,
		Token:          "tok",
		Address:        "127.0.0.2",
		IPRange:        "127.0.0.0/8",
		Peers:          []config.Peer{{ID: api.CoordinatorPeerID, Name: "coordinator"}},
	}
}

// countingServer answers heartbeats with the given status, tallying hits.
func countingServer(t *testing.T, status int, hits *int) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*hits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"address":"127.0.0.2"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestPostPrefersMesh(t *testing.T) {
	var meshHits, publicHits int
	mesh := countingServer(t, http.StatusOK, &meshHits)
	public := countingServer(t, http.StatusOK, &publicHits)

	var resp api.HeartbeatResponse
	if err := post(meshConfig(t, mesh.URL, public.URL), "/heartbeat", api.HeartbeatRequest{}, &resp); err != nil {
		t.Fatalf("post: %v", err)
	}
	if meshHits != 1 || publicHits != 0 {
		t.Fatalf("want mesh 1 / public 0, got mesh %d / public %d", meshHits, publicHits)
	}
	if resp.Address != "127.0.0.2" {
		t.Fatalf("response not decoded: %+v", resp)
	}
}

func TestPostFallsBackWhenMeshUnreachable(t *testing.T) {
	var publicHits int
	public := countingServer(t, http.StatusOK, &publicHits)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // nothing listens: dialing it fails at transport level

	cc := meshConfig(t, dead.URL, public.URL)
	var resp api.HeartbeatResponse
	if err := post(cc, "/heartbeat", api.HeartbeatRequest{}, &resp); err != nil {
		t.Fatalf("post: %v", err)
	}
	if publicHits != 1 {
		t.Fatalf("want 1 public hit after fallback, got %d", publicHits)
	}
	// The failure must arm the cooldown, so the next beat skips the dead path.
	if base := internalBase(cc); base != "" {
		t.Fatalf("mesh path still preferred after failure: %q", base)
	}
	if err := post(cc, "/heartbeat", api.HeartbeatRequest{}, &resp); err != nil {
		t.Fatalf("post during cooldown: %v", err)
	}
	if publicHits != 2 {
		t.Fatalf("want 2 public hits, got %d", publicHits)
	}
}

func TestPostFallsBackOnServerError(t *testing.T) {
	var meshHits, publicHits int
	mesh := countingServer(t, http.StatusBadGateway, &meshHits)
	public := countingServer(t, http.StatusOK, &publicHits)

	var resp api.HeartbeatResponse
	if err := post(meshConfig(t, mesh.URL, public.URL), "/heartbeat", api.HeartbeatRequest{}, &resp); err != nil {
		t.Fatalf("post: %v", err)
	}
	if meshHits != 1 || publicHits != 1 {
		t.Fatalf("want mesh 1 / public 1, got mesh %d / public %d", meshHits, publicHits)
	}
}

// A 4xx is the coordinator's own answer — the mesh path worked, so retrying it
// over the public URL would only repeat the same refusal.
func TestPostDoesNotRetryClientError(t *testing.T) {
	var meshHits, publicHits int
	mesh := countingServer(t, http.StatusForbidden, &meshHits)
	public := countingServer(t, http.StatusOK, &publicHits)

	var resp api.HeartbeatResponse
	err := post(meshConfig(t, mesh.URL, public.URL), "/heartbeat", api.HeartbeatRequest{}, &resp)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want the 403 surfaced, got %v", err)
	}
	if publicHits != 0 {
		t.Fatalf("want no public fallback on 4xx, got %d hits", publicHits)
	}
}

// A heartbeat replaces cached peers wholesale, so the override — which lives on
// the config, not the peer — must still be the address that gets programmed.
func TestEndpointOverrideSurvivesHeartbeatDelta(t *testing.T) {
	cc := &config.ClientConfig{
		EndpointOverrides: map[string]string{"server-a": "192.168.1.50"},
		Peers:             []config.Peer{{ID: "abc123", Name: "server-a", Endpoint: "203.0.113.20:51820"}},
	}
	applyDelta(cc, &api.HeartbeatResponse{
		Add: []api.Peer{{ID: "abc123", Name: "server-a", Endpoint: "198.51.100.9:51820"}},
	})
	if got := cc.Peers[0].Endpoint; got != "198.51.100.9:51820" {
		t.Fatalf("cached endpoint not refreshed from the hub: %q", got)
	}
	if got := cc.ResolveEndpoint(cc.Peers[0]); got != "192.168.1.50:51820" {
		t.Fatalf("override lost after delta: got %q", got)
	}
}

func TestInternalBaseGating(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(cc *config.ClientConfig)
	}{
		{"no advertised url", func(cc *config.ClientConfig) { cc.InternalURL = "" }},
		{"no mesh address yet", func(cc *config.ClientConfig) { cc.Address = "" }},
		{"url outside the mesh range", func(cc *config.ClientConfig) { cc.InternalURL = "http://203.0.113.1:51821" }},
		{"coordinator peer missing", func(cc *config.ClientConfig) { cc.Peers = nil }},
		{"host cannot apply a tunnel", func(_ *config.ClientConfig) { meshAvailable = func() bool { return false } }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := meshConfig(t, "http://127.0.0.1:51821", "http://203.0.113.1:51821")
			tt.mutate(cc)
			if base := internalBase(cc); base != "" {
				t.Fatalf("want the public URL, got %q", base)
			}
		})
	}
}
