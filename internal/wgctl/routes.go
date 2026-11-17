package wgctl

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// RouteProto tags the kernel routes wgcoord installs on Linux, so it can find
// and remove its own without touching routes added by a CNI or by hand.
const RouteProto = "211"

// routeMetric keeps wgcoord's routes below any route someone else installed
// for the same prefix (e.g. a CNI route with metric 0), which then wins.
const routeMetric = "1000"

// output runs a command and returns its stdout; replaced in tests.
var output = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// runRoute runs a route-changing command; replaced in tests.
var runRoute = run

// TagsRoutes reports whether this platform finds wgcoord's routes by a kernel
// tag (Linux), so stale ones can be cleaned up without a record of them.
func TagsRoutes() bool { return runtime.GOOS == "linux" }

// SyncRoutes makes the kernel route the prefixes in want through iface, and
// removes routes wgcoord installed earlier that are no longer wanted.
//
// Linux tags its routes with RouteProto and finds them again by tag, so
// managed is ignored and nil is returned. macOS has no such tag, so the
// routes installed are tracked by the caller: pass the previous result back
// as managed.
func SyncRoutes(iface string, want, managed []string) ([]string, error) {
	want = canonList(want)
	switch runtime.GOOS {
	case "linux":
		if !Available() {
			return nil, ErrUnsupported
		}
		return nil, syncLinux(iface, want)
	case "darwin":
		if !Available() {
			return managed, ErrUnsupported
		}
		if len(want) == 0 && len(managed) == 0 {
			return nil, nil // nothing installed, nothing wanted
		}
		return syncDarwin(iface, want, canonList(managed))
	}
	return managed, ErrUnsupported
}

func syncLinux(iface string, want []string) error {
	have, err := linuxTagged(iface)
	if err != nil {
		return err
	}
	var errs []string
	for _, p := range want {
		if have[p] {
			continue
		}
		if err := runRoute("ip", familyFlag(p), "route", "replace", p, "dev", iface, "proto", RouteProto, "metric", routeMetric); err != nil {
			errs = append(errs, err.Error())
		}
	}
	wanted := toSet(want)
	for p := range have {
		if wanted[p] {
			continue
		}
		if err := runRoute("ip", familyFlag(p), "route", "del", p, "dev", iface, "proto", RouteProto, "metric", routeMetric); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("routes: %s", strings.Join(errs, "; "))
	}
	return nil
}

// linuxTagged lists the prefixes routed through iface with wgcoord's tag.
func linuxTagged(iface string) (map[string]bool, error) {
	have := map[string]bool{}
	for _, fam := range []string{"-4", "-6"} {
		out, err := output("ip", fam, "-o", "route", "show", "dev", iface, "proto", RouteProto)
		if err != nil {
			return nil, fmt.Errorf("list routes on %s: %w", iface, err)
		}
		for _, p := range parseRouteList(out) {
			have[p] = true
		}
	}
	return have, nil
}

// parseRouteList extracts the destination of each `ip -o route` line. Host
// routes print without a mask, so one is added.
func parseRouteList(out string) []string {
	var ps []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		dst := f[0]
		if !strings.Contains(dst, "/") {
			if a, err := netip.ParseAddr(dst); err == nil {
				dst = netip.PrefixFrom(a, a.BitLen()).String()
			}
		}
		if p, err := netip.ParsePrefix(dst); err == nil {
			ps = append(ps, p.Masked().String())
		}
	}
	return ps
}

func syncDarwin(iface string, want, managed []string) ([]string, error) {
	dev, up := realInterface(iface)
	if !up {
		return managed, fmt.Errorf("routes: interface %s is not up", iface)
	}
	var errs []string
	installed := toSet(managed)
	for _, p := range want {
		err := runRoute("route", "-q", "-n", "add", inetFlag(p), p, "-interface", dev)
		if err != nil && !strings.Contains(err.Error(), "File exists") {
			errs = append(errs, err.Error())
			continue
		}
		installed[p] = true
	}
	wanted := toSet(want)
	for p := range installed {
		if wanted[p] {
			continue
		}
		// A route that is already gone (interface recreated) is fine.
		_ = runRoute("route", "-q", "-n", "delete", inetFlag(p), p, "-interface", dev)
		delete(installed, p)
	}
	out := make([]string, 0, len(installed))
	for p := range installed {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(errs) > 0 {
		return out, fmt.Errorf("routes: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

func familyFlag(p string) string {
	if strings.Contains(p, ":") {
		return "-6"
	}
	return "-4"
}

func inetFlag(p string) string {
	if strings.Contains(p, ":") {
		return "-inet6"
	}
	return "-inet"
}

func canonList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		c := p.Masked().String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func toSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[s] = true
	}
	return m
}
