package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEndpoint(t *testing.T) {
	peer := Peer{ID: "abc123", Name: "server-a", Endpoint: "203.0.113.20:51999"}
	cases := []struct {
		name      string
		overrides map[string]string
		peer      Peer
		want      string
	}{
		{"no overrides keeps the advertised endpoint", nil, peer, "203.0.113.20:51999"},
		{"unrelated override is ignored", map[string]string{"other": "10.0.0.5"}, peer, "203.0.113.20:51999"},
		{"bare host keeps the advertised port", map[string]string{"server-a": "192.168.1.50"}, peer, "192.168.1.50:51999"},
		{"host:port is taken verbatim", map[string]string{"server-a": "192.168.1.50:51820"}, peer, "192.168.1.50:51820"},
		{"match by id", map[string]string{"abc123": "192.168.1.50"}, peer, "192.168.1.50:51999"},
		{"id wins over name", map[string]string{"abc123": "10.0.0.1", "server-a": "10.0.0.2"}, peer, "10.0.0.1:51999"},
		{"dash suppresses the endpoint", map[string]string{"server-a": "-"}, peer, ""},
		{"bare ipv6 gets bracketed", map[string]string{"server-a": "2001:db8::1"}, peer, "[2001:db8::1]:51999"},
		{"bracketed ipv6 with port is verbatim", map[string]string{"server-a": "[2001:db8::1]:51820"}, peer, "[2001:db8::1]:51820"},
		{
			"peer with no advertised endpoint falls back to the default port",
			map[string]string{"coordinator": "192.168.1.10"},
			Peer{ID: "coordinator", Name: "coordinator"},
			"192.168.1.10:51820",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cc := &ClientConfig{EndpointOverrides: c.overrides}
			if got := cc.ResolveEndpoint(c.peer); got != c.want {
				t.Errorf("ResolveEndpoint() = %q; want %q", got, c.want)
			}
		})
	}
}

func TestKnownPeer(t *testing.T) {
	cc := &ClientConfig{Peers: []Peer{{ID: "abc123", Name: "server-a"}}}
	for _, key := range []string{"abc123", "server-a"} {
		if !cc.KnownPeer(key) {
			t.Errorf("KnownPeer(%q) = false; want true", key)
		}
	}
	if cc.KnownPeer("server-b") {
		t.Error(`KnownPeer("server-b") = true; want false`)
	}
}

func TestLegacyClientMigratesToDefaultProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"mode":"client","client":{"name":"mac","interface":"wg0","token":"tok"}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Client != nil || c.ActiveProfile != DefaultProfile || c.Profiles[DefaultProfile].Token != "tok" {
		t.Fatalf("not migrated: %+v", c)
	}
	SetPath(path)
	t.Cleanup(func() { SetPath("") })
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), `"client":`) || !strings.Contains(string(b), `"active_profile": "default"`) {
		t.Fatalf("saved in the old layout:\n%s", b)
	}
}

func TestProfileResolution(t *testing.T) {
	c := &Config{Mode: ModeClient, ActiveProfile: "vv", Profiles: map[string]*ClientConfig{
		"vv": {Name: "a"}, "nx": {Name: "b"},
	}}
	if n, cc, err := c.Profile(""); err != nil || n != "vv" || cc.Name != "a" {
		t.Fatalf("active: %q %v %v", n, cc, err)
	}
	if n, _, err := c.Profile("nx"); err != nil || n != "nx" {
		t.Fatalf("named: %q %v", n, err)
	}
	if _, _, err := c.Profile("zz"); err == nil || !strings.Contains(err.Error(), "nx, vv") {
		t.Fatalf("unknown: %v", err)
	}
	c.ActiveProfile = ""
	if _, _, err := c.Profile(""); err == nil || !strings.Contains(err.Error(), "no active profile") {
		t.Fatalf("none active: %v", err)
	}
}

func TestValidProfileName(t *testing.T) {
	for _, ok := range []string{"vv", "nx-prod", "a.b_c", "0"} {
		if err := ValidProfileName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "a/b", "a b", strings.Repeat("x", 33)} {
		if ValidProfileName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
