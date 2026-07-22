package config

import "testing"

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
