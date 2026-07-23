package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"wgcoord/internal/config"
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
}

func NewService(logger *log.Logger) *Service {
	return &Service{store: NewStore(), log: logger}
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

// reconcile renders the interface, writes an inspectable .conf, and applies it
// live (warning once if wireguard-tools is absent).
func (s *Service) reconcile() {
	cc, err := Load()
	if err != nil {
		s.log.Printf("reconcile: load config: %v", err)
		return
	}
	iface, err := desiredInterface(cc)
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
				s.log.Printf("live apply unavailable on this host; wrote %s — apply with `wg-quick up %s` on Linux", confPath, confPath)
			})
			return
		}
		s.log.Printf("reconcile: apply %s: %v", cc.Interface, err)
	}
}

func desiredInterface(cc *config.CoordinatorConfig) (wgctl.Interface, error) {
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
		if c.Blacklisted || c.PublicKey == "" {
			continue
		}
		iface.Peers = append(iface.Peers, wgctl.Peer{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: allowedIPs(c.Address, c.Routes),
		})
	}
	return iface, nil
}
