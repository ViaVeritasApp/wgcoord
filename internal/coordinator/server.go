package coordinator

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"wgcoord/internal/api"
	"wgcoord/internal/config"
	"wgcoord/internal/valid"
	"wgcoord/internal/wgkey"
)

// errClientGone: the authenticated client was removed between auth and write.
var errClientGone = errors.New("client no longer exists")

// Server is the control-plane HTTP handler set.
type Server struct {
	store *Store
}

func NewServer(store *Store) *Server { return &Server{store: store} }

// Handler builds the control-plane routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /register", s.auth(s.handleRegister))
	mux.HandleFunc("POST /heartbeat", s.auth(s.handleHeartbeat))
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type clientHandler func(w http.ResponseWriter, r *http.Request, clientID string)

// auth resolves the bearer token to a non-blacklisted client.
func (s *Server) auth(next clientHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := Authenticate(bearer(r))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid or missing auth token")
			return
		}
		if c.Blacklisted {
			writeErr(w, http.StatusForbidden, "client is blacklisted")
			return
		}
		next(w, r, c.ID)
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, clientID string) {
	var req api.RegisterRequest
	if !decode(w, r, &req) {
		return
	}
	if !wgkey.Valid(req.PublicKey) {
		writeErr(w, http.StatusBadRequest, "public_key must be a 32-byte base64 WireGuard key")
		return
	}
	if req.PublicEndpoint != "" {
		if err := valid.EndpointHost(req.PublicEndpoint); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var resp api.RegisterResponse
	err := s.store.Mutate(func(cc *config.CoordinatorConfig) error {
		self := findByID(cc, clientID)
		if self == nil {
			return errClientGone
		}
		if req.RequestedAddress != "" && req.RequestedAddress != self.Address {
			if err := checkAddrFree(cc, req.RequestedAddress, self.ID); err != nil {
				return err
			}
			self.Address = req.RequestedAddress
			if self.HubOnly {
				cc.UpdatedAt = nowRFC3339() // mesh clients route this address via the hub
			}
		}
		self.PublicKey = req.PublicKey
		self.ListenPort = pickPort(req.ListenPort, cc.ClientWGPort)
		self.Endpoint = endpointFrom(req.PublicEndpoint, self.ListenPort)
		self.UpdatedAt = nowRFC3339()
		self.LastSeenAt = self.UpdatedAt
		resp = api.RegisterResponse{
			ID:         self.ID,
			Name:       self.Name,
			Address:    self.Address,
			IPRange:    cc.IPRange,
			ControlURL: cc.InternalControlURL(),
			Peers:      buildPeers(cc, self.ID),
			HubOnly:    self.HubOnly,
		}
		self.SentHub = hubAllowedIn(resp.Peers)
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, clientID string) {
	var req api.HeartbeatRequest
	if !decode(w, r, &req) {
		return
	}
	if req.PublicEndpoint != "" {
		if err := valid.EndpointHost(req.PublicEndpoint); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	have := make(map[string]bool, len(req.Have))
	for _, id := range req.Have {
		have[id] = true
	}
	var resp api.HeartbeatResponse
	err := s.store.Mutate(func(cc *config.CoordinatorConfig) error {
		self := findByID(cc, clientID)
		if self == nil {
			return errClientGone
		}
		prevSeen := self.LastSeenAt

		// Identity may change on any beat (e.g. public IP); bumping UpdatedAt
		// propagates it to peers.
		if req.PublicKey != "" && wgkey.Valid(req.PublicKey) {
			self.PublicKey = req.PublicKey
		}
		self.ListenPort = pickPort(pickPort(req.ListenPort, self.ListenPort), cc.ClientWGPort)
		if req.PublicEndpoint != "" {
			if ep := endpointFrom(req.PublicEndpoint, self.ListenPort); ep != self.Endpoint {
				self.Endpoint = ep
				self.UpdatedAt = nowRFC3339()
			}
		}
		self.Have = req.Have
		self.LastSeenAt = nowRFC3339()

		peers := buildPeers(cc, self.ID)
		present := map[string]bool{api.CoordinatorPeerID: true}
		var add []api.Peer
		for _, p := range peers {
			present[p.ID] = true
			// A peer already held by the client is only re-sent when it changed
			// since the client last synced. The hub tracks its own UpdatedAt
			// (bumped when its routes change); other peers track theirs on the
			// client record.
			updatedAt := ""
			if p.ID == api.CoordinatorPeerID {
				updatedAt = cc.UpdatedAt
			} else if c := findByID(cc, p.ID); c != nil {
				updatedAt = c.UpdatedAt
			}
			// >=, not >: timestamps have one-second resolution, so a change
			// made in the same second as the previous beat would otherwise be
			// skipped for good. The cost is one redundant re-send.
			changed := updatedAt != "" && prevSeen != "" && updatedAt >= prevSeen
			if self.HubOnly && p.ID == api.CoordinatorPeerID {
				// A hub-only client's view of the hub depends on its grants,
				// groups and every route, so compare what it last received.
				changed = p.AllowedIPs != self.SentHub
			}
			if !have[p.ID] || changed {
				add = append(add, p)
				if p.ID == api.CoordinatorPeerID {
					self.SentHub = p.AllowedIPs
				}
			}
		}
		var remove []string
		for _, id := range req.Have {
			if id != api.CoordinatorPeerID && !present[id] {
				remove = append(remove, id) // gone or blacklisted
			}
		}
		resp = api.HeartbeatResponse{
			Address:    self.Address,
			IPRange:    cc.IPRange,
			ControlURL: cc.InternalControlURL(),
			Add:        add,
			Remove:     remove,
			HubOnly:    self.HubOnly,
		}
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// buildPeers is the peer set advertised to selfID. A mesh client gets the hub
// plus every other registered, non-blacklisted mesh client. A hub-only client
// gets the hub alone, and is never advertised to anyone else.
func buildPeers(cc *config.CoordinatorConfig, selfID string) []api.Peer {
	self := findByID(cc, selfID)
	peers := make([]api.Peer, 0, len(cc.Clients)+1)
	if cc.PublicKey != "" {
		hub := api.Peer{
			ID:         api.CoordinatorPeerID,
			Name:       "coordinator",
			PublicKey:  cc.PublicKey,
			AllowedIPs: strings.Join(hubPeerAllowed(cc, self), ", "),
		}
		if cc.PublicEndpoint != "" {
			hub.Endpoint = net.JoinHostPort(cc.PublicEndpoint, strconv.Itoa(cc.ListenPort))
		}
		peers = append(peers, hub)
	}
	if self != nil && self.HubOnly {
		return peers
	}
	for _, c := range cc.Clients {
		if c.ID == selfID || c.Blacklisted || c.PublicKey == "" || c.HubOnly {
			continue
		}
		peers = append(peers, api.Peer{
			ID:         c.ID,
			Name:       c.Name,
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: strings.Join(allowedIPs(c.Address, resolveRoutes(cc, c.Routes)), ", "),
		})
	}
	return peers
}

// hubAllowedIn returns the coordinator peer's AllowedIPs from a peer set.
func hubAllowedIn(peers []api.Peer) string {
	for _, p := range peers {
		if p.ID == api.CoordinatorPeerID {
			return p.AllowedIPs
		}
	}
	return ""
}

// allowedIPs is the AllowedIPs set for a mesh member: its own address as a /32
// host route, followed by any extra routes it carries (pod CIDRs, LANs). The
// /32 keeps each node individually addressable; the routes are what let pod and
// subnet traffic cross the tunnel instead of being dropped by cryptokey routing.
func allowedIPs(addr string, routes []string) []string {
	ips := make([]string, 0, len(routes)+1)
	if addr != "" {
		ips = append(ips, addr+"/32")
	}
	return append(ips, routes...)
}

// --- small HTTP helpers ---

func pickPort(preferred, fallback int) int {
	if preferred > 0 {
		return preferred
	}
	return fallback
}

// endpointFrom joins host:port, or "" for a roaming/NAT client with no host.
func endpointFrom(host string, port int) string {
	if strings.TrimSpace(host) == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, errClientGone):
		return http.StatusNotFound
	default:
		// Register/heartbeat write errors are almost always address conflicts.
		return http.StatusConflict
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
