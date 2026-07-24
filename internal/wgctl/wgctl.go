// Package wgctl applies WireGuard state to the live interface. On Linux it drives
// the in-kernel device directly via wireguard-tools (`wg syncconf`) and iproute2
// (`ip`); on macOS, which has no kernel WireGuard, it drives the userspace
// wireguard-go tunnel through `wg-quick` for interface up/down and reconciles the
// peer set live with `wg syncconf`. `syncconf` makes the peer set exactly match
// the generated config, so dropping a blacklisted peer from the desired set
// removes it live. On any other host (or without the tools) mutating calls return
// ErrUnsupported with no side effects, so the control-plane still works.
package wgctl

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"wgcoord/internal/config"
)

// ErrUnsupported means live apply isn't possible on this host (sentinel for errors.Is).
var ErrUnsupported = errors.New("live WireGuard apply unavailable (needs Linux with wireguard-tools `wg` + iproute2 `ip`, or macOS with wireguard-tools `wg` + `wg-quick`)")

// Peer is one desired peer of the interface.
type Peer struct {
	PublicKey  string
	Endpoint   string // host:port; empty when the peer has no reachable endpoint
	AllowedIPs []string
	Keepalive  int // persistent-keepalive seconds; 0 omits the line
}

// Interface is the full desired state of a WireGuard device.
type Interface struct {
	Name       string
	PrivateKey string
	ListenPort int
	Address    string // CIDR to assign, e.g. 10.55.0.1/24
	Peers      []Peer
}

// Available reports whether live apply can run on this host.
func Available() bool {
	switch runtime.GOOS {
	case "linux":
		// In-kernel WireGuard, managed through iproute2.
		return haveTool("wg") && haveTool("ip")
	case "darwin":
		// Userspace wireguard-go, brought up through wg-quick.
		return haveTool("wg") && haveTool("wg-quick")
	default:
		return false
	}
}

func haveTool(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// Apply reconciles the live interface to iface: create if missing, sync
// key/port/peers, assign the address, bring it up. The mechanism is
// platform-specific — kernel + iproute2 on Linux, wg-quick + wireguard-go on
// macOS — but the outcome is the same reconciled interface.
func Apply(iface Interface) error {
	if !Available() {
		return ErrUnsupported
	}
	switch runtime.GOOS {
	case "linux":
		return applyLinux(iface)
	case "darwin":
		return applyDarwin(iface)
	}
	return ErrUnsupported
}

// applyLinux drives the in-kernel WireGuard device: create it via netlink if
// missing, sync the peer set, then assign the address and bring the link up.
func applyLinux(iface Interface) error {
	if !linkExists(iface.Name) {
		if err := run("ip", "link", "add", "dev", iface.Name, "type", "wireguard"); err != nil {
			return fmt.Errorf("create interface %s: %w", iface.Name, err)
		}
	}
	if err := wgSyncconf(iface); err != nil {
		return err
	}
	if iface.Address != "" {
		if err := run("ip", "address", "replace", iface.Address, "dev", iface.Name); err != nil {
			return fmt.Errorf("assign %s to %s: %w", iface.Address, iface.Name, err)
		}
	}
	if err := run("ip", "link", "set", "up", "dev", iface.Name); err != nil {
		return fmt.Errorf("bring up %s: %w", iface.Name, err)
	}
	return nil
}

// applyDarwin drives the userspace tunnel: macOS has no kernel WireGuard, so the
// first apply brings the interface up from a wg-quick config (forking
// wireguard-go, assigning the address, installing a route per AllowedIPs), and
// later applies reconcile the peer set in place with `wg syncconf` — no teardown,
// so a steady-state heartbeat costs one cheap resync and never blips the tunnel.
//
// Caveat: `wg syncconf` updates peers (keys, endpoints, crypto AllowedIPs) but
// not the system routing table. A brand-new *routed subnet* gets its route only
// when the interface is next brought up (Down + Apply, or `wg-quick up`); peers
// inside the already-routed mesh range apply live.
func applyDarwin(iface Interface) error {
	confPath := wgQuickConfPath(iface.Name)
	if err := WriteConfigFile(confPath, iface); err != nil {
		return err
	}
	if !wgInterfaceUp(iface.Name) {
		if err := run("wg-quick", "up", confPath); err != nil {
			return fmt.Errorf("wg-quick up %s: %w", confPath, err)
		}
		return nil
	}
	return wgSyncconf(iface)
}

// wgSyncconf makes the live interface's peer set exactly match iface via
// `wg syncconf`. The stripped config (no Address line — that is applied
// separately) is written 0600 into the config dir, not world-traversable /tmp,
// because it briefly contains the interface's private key.
func wgSyncconf(iface Interface) error {
	tmp, err := os.CreateTemp(config.Dir(), ".wgsync-*.conf")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(renderSyncConf(iface)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := run("wg", "syncconf", iface.Name, tmpName); err != nil {
		return fmt.Errorf("wg syncconf %s: %w", iface.Name, err)
	}
	return nil
}

// RemovePeer drops a single peer from the live interface immediately.
func RemovePeer(ifaceName, publicKey string) error {
	if !Available() {
		return ErrUnsupported
	}
	return run("wg", "set", ifaceName, "peer", publicKey, "remove")
}

// Down removes the interface entirely.
func Down(ifaceName string) error {
	if !Available() {
		return ErrUnsupported
	}
	switch runtime.GOOS {
	case "linux":
		if !linkExists(ifaceName) {
			return nil
		}
		return run("ip", "link", "del", "dev", ifaceName)
	case "darwin":
		if !wgInterfaceUp(ifaceName) {
			return nil
		}
		confPath := wgQuickConfPath(ifaceName)
		if err := run("wg-quick", "down", confPath); err != nil {
			return fmt.Errorf("wg-quick down %s: %w", confPath, err)
		}
		return nil
	}
	return ErrUnsupported
}

// WriteConfigFile writes a portable wg-quick config (0600) for manual
// `wg-quick up <path>` or inspection.
func WriteConfigFile(path string, iface Interface) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(RenderQuickConfig(iface)), 0o600)
}

// RenderQuickConfig renders a wg-quick config (with an Address line).
func RenderQuickConfig(iface Interface) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if iface.Address != "" {
		fmt.Fprintf(&b, "Address = %s\n", iface.Address)
	}
	fmt.Fprintf(&b, "PrivateKey = %s\n", iface.PrivateKey)
	if iface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", iface.ListenPort)
	}
	writePeers(&b, iface.Peers)
	return b.String()
}

// renderSyncConf renders the stripped config `wg syncconf` expects: no Address
// line (that is applied separately via `ip`).
func renderSyncConf(iface Interface) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", iface.PrivateKey)
	if iface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", iface.ListenPort)
	}
	writePeers(&b, iface.Peers)
	return b.String()
}

func writePeers(b *strings.Builder, peers []Peer) {
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(b, "PublicKey = %s\n", clean(p.PublicKey))
		if len(p.AllowedIPs) > 0 {
			ips := make([]string, len(p.AllowedIPs))
			for i, ip := range p.AllowedIPs {
				ips[i] = clean(ip)
			}
			fmt.Fprintf(b, "AllowedIPs = %s\n", strings.Join(ips, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(b, "Endpoint = %s\n", clean(p.Endpoint))
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(b, "PersistentKeepalive = %s\n", strconv.Itoa(p.Keepalive))
		}
	}
}

// clean strips CR/LF so a field value can never inject extra config directives,
// even if upstream validation is bypassed.
func clean(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

// wgQuickConfPath is the stable wg-quick config for an interface. wg-quick
// derives the interface name from the file's basename and, on macOS, records the
// name→utun mapping so `wg show <name>` and `wg syncconf <name>` work afterward.
func wgQuickConfPath(name string) string {
	return filepath.Join(config.Dir(), name+".conf")
}

// wgInterfaceUp reports whether a WireGuard interface is currently present.
// `wg show <name>` resolves the name (via the mapping wg-quick records on macOS)
// and exits non-zero when the interface is absent.
func wgInterfaceUp(name string) bool {
	return exec.Command("wg", "show", name).Run() == nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}
