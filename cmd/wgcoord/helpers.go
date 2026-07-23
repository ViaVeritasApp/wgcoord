package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wgcoord/internal/valid"
	"wgcoord/internal/wgctl"
)

// cmdOut is where human-facing command output goes.
var cmdOut = os.Stdout

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func newLogger() *log.Logger { return log.New(os.Stderr, "", log.LstdFlags) }

func orStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func orInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// canonicalRoutes validates and canonicalizes route CIDRs typed on the command
// line (used where routes are written straight to config, e.g. `coordinator
// init`, rather than through the store which canonicalizes itself). Duplicates
// are dropped, order preserved.
func canonicalRoutes(routes []string) ([]string, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(routes))
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		canon, err := valid.CIDR(r)
		if err != nil {
			return nil, err
		}
		if seen[canon] {
			continue
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out, nil
}

// routesCell renders a node's routes for a status table cell.
func routesCell(routes []string) string {
	if len(routes) == 0 {
		return "-"
	}
	return strings.Join(routes, ",")
}

// shortKey trims a base64 WireGuard key to a recognizable prefix for tables.
func shortKey(k string) string {
	if k == "" {
		return "-"
	}
	if len(k) <= 12 {
		return k
	}
	return k[:12] + "…"
}

// relTime renders an RFC3339 timestamp as a compact "3m ago"-style string.
func relTime(ts string) string {
	if ts == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// reportApply prints the outcome of a live-apply attempt in operator-friendly
// terms, distinguishing "not supported here" from a real failure.
func reportApply(confPath string, err error) {
	switch {
	case err == nil:
		fmt.Printf("Applied WireGuard interface (config: %s)\n", confPath)
	case errors.Is(err, wgctl.ErrUnsupported):
		fmt.Printf("Live apply unavailable on this host — wrote %s\n", confPath)
		fmt.Printf("Apply it on a Linux host with: wg-quick up %s\n", confPath)
	default:
		fmt.Printf("warning: apply failed: %v (config written to %s)\n", err, confPath)
	}
}
