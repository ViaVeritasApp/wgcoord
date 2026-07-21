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
		}
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
			changed := false
			if c := findByID(cc, p.ID); c != nil && c.UpdatedAt != "" && prevSeen != "" && c.UpdatedAt > prevSeen {
				changed = true // updated since this client last synced
			}
			if !have[p.ID] || changed {
				add = append(add, p)
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
		}
		return nil
	})
	if err != nil {
		writeErr(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// buildPeers is the peer set advertised to selfID: the hub plus every other
// registered, non-blacklisted client.
func buildPeers(cc *config.CoordinatorConfig, selfID string) []api.Peer {
	peers := make([]api.Peer, 0, len(cc.Clients)+1)
	if cc.PublicKey != "" {
		hub := api.Peer{
			ID:         api.CoordinatorPeerID,
			Name:       "coordinator",
			PublicKey:  cc.PublicKey,
			AllowedIPs: cc.Address + "/32",
		}
		if cc.PublicEndpoint != "" {
			hub.Endpoint = net.JoinHostPort(cc.PublicEndpoint, strconv.Itoa(cc.ListenPort))
		}
		peers = append(peers, hub)
	}
	for _, c := range cc.Clients {
		if c.ID == selfID || c.Blacklisted || c.PublicKey == "" {
			continue
		}
		peers = append(peers, api.Peer{
			ID:         c.ID,
			Name:       c.Name,
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: c.Address + "/32",
		})
	}
	return peers
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
