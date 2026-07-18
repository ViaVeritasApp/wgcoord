// Command wgcoord is a CLI WireGuard mesh coordinator. It runs in one of two
// modes: `coordinator` (the control-plane hub that hands out peers and manages
// the server interface) and `client` (a node that joins, heartbeats, and keeps
// its own interface in sync). State lives in a single 0600 config.json.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"wgcoord/internal/config"
)

func main() {
	root := &cobra.Command{
		Use:           "wgcoord",
		Short:         "WireGuard mesh coordinator and client",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("config", "", "path to config.json (overrides the default location)")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		v, _ := cmd.Flags().GetString("config")
		if v = strings.TrimSpace(v); v != "" {
			abs, err := filepath.Abs(v)
			if err != nil {
				return fmt.Errorf("resolve --config %q: %w", v, err)
			}
			config.SetPath(abs)
		}
		return nil
	}

	root.AddCommand(coordinatorCmd(), clientCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
