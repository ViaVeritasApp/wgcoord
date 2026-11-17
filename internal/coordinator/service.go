package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"wgcoord/internal/config"
	"wgcoord/internal/firewall"
	"wgcoord/internal/ipalloc"
	"wgcoord/internal/wgctl"
)

const reconcileInterval = 15 * time.Second

// Service runs the control-plane HTTP server and periodically reconciles the
// hub's interface from the registry.
type Service struct {
	store           *Store
	log             *log.Logger
	warnUnsupported sync.Once
	fw              enforcer
	// fwClean is set once an empty spec has been applied (the table removed),
	// so hosts that never use the feature don't run nft on every reconcile.
	fwClean bool
	// last holds the most recent message per topic, so a fault that persists
	// across reconciles is logged once, and its recovery once.
	last map[string]string
}

// enforcer is the host side of hub-only enforcement, swappable in tests.
type enforcer struct {
	available func() bool
	apply     func(firewall.Spec) error
	forward   func(v6 bool) (bool, error)
	routes    func(iface string, want []string) error
}

var hostEnforcer = enforcer{
	available: firewall.Available,
	apply:     firewall.Apply,
	forward:   firewall.EnableForwarding,
	routes: func(iface string, want []string) error {
		_, err := wgctl.SyncRoutes(iface, want, nil)
		return err
	},
}

func NewService(logger *log.Logger) *Service {
	return &Service{store: NewStore(), log: logger, fw: hostEnforcer, last: map[string]string{}}
}

// Serve blocks until ctx is cancelled.
func (s *Service) Serve(ctx context.Context) error {
	cc, err := Load()
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(cc.ControlPort))
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewServer(s.store).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	tlsOn := cc.TLSEnabled()

	s.reconcile() // apply current state before accepting clients

	go func() {
		scheme := "http"
		if tlsOn {
			scheme = "https"
		}
		s.log.Printf("control plane listening on %s://%s (wg %s udp/%d, range %s)", scheme, addr, cc.Interface, cc.ListenPort, cc.IPRange)
		if !tlsOn {
			s.log.Printf("WARNING: control plane is plaintext HTTP — bearer tokens and keys are exposed on-path. Set tls_cert_file/tls_key_file (coordinator init --tls-cert/--tls-key) or front it with TLS.")
		}
		var err error
		if tlsOn {
			err = srv.ListenAndServeTLS(cc.TLSCertFile, cc.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Printf("control server error: %v", err)
		}
	}()

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutCtx)
		case <-ticker.C:
			s.reconcile() // pick up registrations + CLI edits (blacklist, etc.)
		}
	}
}

// reconcile brings the host in line with the registry: the firewall first,
// then the interface (written as an inspectable .conf and applied live), then
// the kernel routes the hub needs to forward hub-only traffic.
func (s *Service) reconcile() {
	cc, err := Load()
	if err != nil {
		s.log.Printf("reconcile: load config: %v", err)
		return
	}
	spec := firewallSpec(cc)
	includeHubOnly := s.enforce(spec)
	iface, err := desiredInterface(cc, includeHubOnly)
	if err != nil {
		s.log.Printf("reconcile: %v", err)
		return
	}
	confPath := filepath.Join(config.Dir(), cc.Interface+".conf")
	if err := wgctl.WriteConfigFile(confPath, iface); err != nil {
		s.log.Printf("reconcile: write %s: %v", confPath, err)
	}
	if err := wgctl.Apply(iface); err != nil {
		if errors.Is(err, wgctl.ErrUnsupported) {
			s.warnUnsupported.Do(func() {
				s.log.Printf("live apply unavailable on this host; wrote %s — bring it up manually with `wg-quick up %s`", confPath, confPath)
			})
			return
		}
		s.log.Printf("reconcile: apply %s: %v", cc.Interface, err)
		return
	}
	s.syncHubRoutes(cc, includeHubOnly && len(spec.Clients) > 0)
}

// enforce applies the firewall for spec and reports whether hub-only clients
// may be put on the interface. It fails closed: when their grants can't be
// enforced, they are left off, since forwarding may already be on (Kubernetes
// turns it on) and their traffic would otherwise pass unfiltered.
func (s *Service) enforce(spec firewall.Spec) bool {
	if !s.fw.available() {
		if len(spec.Clients) > 0 {
			s.note("firewall", fmt.Sprintf("%v; %d hub-only client(s) are left off %s until it is", firewall.ErrUnsupported, len(spec.Clients), spec.Interface))
			return false
		}
		s.note("firewall", "")
		return true
	}
	if !spec.Empty() {
		if changed, err := s.fw.forward(spec.NeedsIPv6()); err != nil {
			s.note("forward", fmt.Sprintf("hub-only/NAT traffic can't be forwarded: %v", err))
		} else {
			if changed {
				s.log.Print("enabled IP forwarding for hub-only clients and NAT routes")
			}
			s.note("forward", "")
		}
	}
	if spec.Empty() && s.fwClean {
		return true
	}
	if err := s.fw.apply(spec); err != nil {
		if len(spec.Clients) > 0 {
			s.note("firewall", fmt.Sprintf("firewall: %v; %d hub-only client(s) are left off %s until it applies", err, len(spec.Clients), spec.Interface))
			return false
		}
		s.note("firewall", fmt.Sprintf("firewall: %v", err))
		return true
	}
	s.fwClean = spec.Empty()
	s.note("firewall", "")
	return true
}

// syncHubRoutes routes every mesh client's routes through the interface, so
// the hub can forward hub-only traffic to them. They are only installed while
// hub-only clients exist, and at a metric that defers to routes someone else
// (a CNI) already installed for the same prefix.
func (s *Service) syncHubRoutes(cc *config.CoordinatorConfig, needed bool) {
	var want []string
	if needed {
		for _, c := range cc.Clients {
			if c.HubOnly || c.Blacklisted || c.PublicKey == "" {
				continue
			}
			want = append(want, resolveRoutes(cc, c.Routes)...)
		}
	}
	if err := s.fw.routes(cc.Interface, want); err != nil && !errors.Is(err, wgctl.ErrUnsupported) {
		s.note("routes", err.Error())
		return
	}
	s.note("routes", "")
}

// note logs msg under topic only when it differs from the last one, and logs
// a recovery when a topic's message clears.
func (s *Service) note(topic, msg string) {
	if s.last == nil {
		s.last = map[string]string{}
	}
	prev := s.last[topic]
	if msg == prev {
		return
	}
	s.last[topic] = msg
	switch {
	case msg != "":
		s.log.Print(msg)
	case prev != "":
		s.log.Printf("%s: recovered", topic)
	}
}

// firewallSpec derives the firewall state from the registry.
func firewallSpec(cc *config.CoordinatorConfig) firewall.Spec {
	spec := firewall.Spec{Interface: cc.Interface, ControlPort: cc.ControlPort}
	if a, err := netip.ParseAddr(cc.Address); err == nil {
		spec.Hub = a
	}
	if m, ok := meshPrefix(cc); ok {
		spec.Mesh = m
	}
	for _, c := range hubOnlyClients(cc) {
		a, err := netip.ParseAddr(c.Address)
		if err != nil {
			continue
		}
		spec.Clients = append(spec.Clients, firewall.Client{Name: c.Name, Addr: a, Rules: effectiveRules(cc, c)})
	}
	for _, r := range resolveRoutes(cc, cc.NATRoutes) {
		if p, err := netip.ParsePrefix(r); err == nil {
			spec.NAT = append(spec.NAT, p)
		}
	}
	return spec
}

// desiredInterface renders the hub's interface. Hub-only clients get their
// own /32 only; they are left out entirely when includeHubOnly is false, which
// is how the hub fails closed when it cannot enforce their grants.
func desiredInterface(cc *config.CoordinatorConfig, includeHubOnly bool) (wgctl.Interface, error) {
	bits, err := ipalloc.PrefixBits(cc.IPRange)
	if err != nil {
		return wgctl.Interface{}, err
	}
	iface := wgctl.Interface{
		Name:       cc.Interface,
		PrivateKey: cc.PrivateKey,
		ListenPort: cc.ListenPort,
		Address:    fmt.Sprintf("%s/%d", cc.Address, bits),
	}
	for _, c := range cc.Clients {
		if c.Blacklisted || c.PublicKey == "" || (c.HubOnly && !includeHubOnly) {
			continue
		}
		routes := resolveRoutes(cc, c.Routes)
		if c.HubOnly {
			routes = nil
		}
		iface.Peers = append(iface.Peers, wgctl.Peer{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: allowedIPs(c.Address, routes),
		})
	}
	return iface, nil
}
