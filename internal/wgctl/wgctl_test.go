package wgctl

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var base = time.Date(2026, 7, 25, 16, 33, 46, 0, time.UTC)

// tunnel lays out what wg-quick leaves behind for a live tunnel: a name mapping
// and wireguard-go's socket, stamped skew apart.
func tunnel(t *testing.T, name, dev string, skew time.Duration) {
	t.Helper()
	wgRunDir = t.TempDir()
	nameFile := filepath.Join(wgRunDir, name+".name")
	if err := os.WriteFile(nameFile, []byte(dev+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(wgRunDir, dev+".sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chtimes(nameFile, base, base); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sock, base.Add(skew), base.Add(skew)); err != nil {
		t.Fatal(err)
	}
}

func TestResolveUp(t *testing.T) {
	tunnel(t, "wg0", "utun4", 0)

	dev, up := resolveUserspace("wg0")
	if !up || dev != "utun4" {
		t.Fatalf("resolveUserspace = (%q, %v), want (\"utun4\", true)", dev, up)
	}
}

// A socket far newer than its mapping belongs to a different tunnel that reused
// the utun; adopting it would point `wg syncconf` at a foreign device.
func TestResolveStale(t *testing.T) {
	tunnel(t, "wg0", "utun4", 30*time.Second)

	if dev, up := resolveUserspace("wg0"); up {
		t.Fatalf("stale mapping resolved to %q, want not up", dev)
	}
}

func TestResolveDown(t *testing.T) {
	wgRunDir = t.TempDir()

	// Never brought up.
	if _, up := resolveUserspace("wg0"); up {
		t.Fatal("missing mapping reported up")
	}

	// wireguard-go exited and took the socket with it.
	if err := os.WriteFile(filepath.Join(wgRunDir, "wg1.name"), []byte("utun9\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, up := resolveUserspace("wg1"); up {
		t.Fatal("mapping without a socket reported up")
	}

	// A plain file is not a live control socket.
	if err := os.WriteFile(filepath.Join(wgRunDir, "utun9.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, up := resolveUserspace("wg1"); up {
		t.Fatal("regular file accepted as a control socket")
	}

	if err := os.WriteFile(filepath.Join(wgRunDir, "wg2.name"), []byte("\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, up := resolveUserspace("wg2"); up {
		t.Fatal("empty mapping reported up")
	}
}

// The mapping feeds an interface name straight into `wg`, so a path in it must
// never escape the run dir.
func TestResolveRejectsPath(t *testing.T) {
	tunnel(t, "wg0", "utun4", 0)
	nameFile := filepath.Join(wgRunDir, "wg0.name")
	if err := os.Remove(nameFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nameFile, []byte("../wireguard/utun4\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	if dev, up := resolveUserspace("wg0"); up {
		t.Fatalf("path in mapping resolved to %q, want not up", dev)
	}
}
