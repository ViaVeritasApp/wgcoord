// Package api is the JSON wire contract for the control-plane HTTP port.
// Requests authenticate with `Authorization: Bearer <token>`.
package api

// CoordinatorPeerID is the fixed peer id the hub advertises itself under.
const CoordinatorPeerID = "coordinator"

// Peer is one mesh member as advertised to a client.
type Peer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint,omitempty"`
	AllowedIPs string `json:"allowed_ips"`
}

// RegisterRequest is posted to POST /register. The coordinator joins
// PublicEndpoint with ListenPort into the endpoint shared with peers.
type RegisterRequest struct {
	PublicKey      string `json:"public_key"`
	PublicEndpoint string `json:"public_endpoint,omitempty"`
	ListenPort     int    `json:"listen_port,omitempty"`
	// RequestedAddress asks for a specific mesh IP, granted when free; empty
	// keeps the address assigned at `client add` time.
	RequestedAddress string `json:"requested_address,omitempty"`
}

// RegisterResponse returns the assigned address and the full current peer set.
type RegisterResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	IPRange    string `json:"ip_range"`
	ControlURL string `json:"control_url,omitempty"` // see HeartbeatResponse.ControlURL
	Peers      []Peer `json:"peers"`
}

// HeartbeatRequest is posted to POST /heartbeat. Have lists the peer ids the
// client holds; the coordinator answers with the difference.
type HeartbeatRequest struct {
	Have           []string `json:"have"`
	PublicKey      string   `json:"public_key,omitempty"`
	PublicEndpoint string   `json:"public_endpoint,omitempty"`
	ListenPort     int      `json:"listen_port,omitempty"`
}

// HeartbeatResponse is the peer delta: Add for missing/changed peers, Remove
// for ids to drop (blacklisted or deleted).
type HeartbeatResponse struct {
	Address string `json:"address"`
	IPRange string `json:"ip_range"`
	// ControlURL is the coordinator's control plane as reached *through* the
	// mesh (e.g. http://10.8.0.1:51821). A client whose tunnel is up should
	// prefer it — the request then travels encrypted — and fall back to the
	// public URL it joined with whenever that path fails.
	ControlURL string   `json:"control_url,omitempty"`
	Add        []Peer   `json:"add"`
	Remove     []string `json:"remove"`
}

// ErrorResponse is the body returned for any non-2xx control-plane response.
type ErrorResponse struct {
	Error string `json:"error"`
}
