package main

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"wgcoord/internal/client"
	"wgcoord/internal/config"
	"wgcoord/internal/valid"
)

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Join a coordinator and run as a mesh client",
	}
	cmd.AddCommand(
		clientJoinCmd(),
		clientRunCmd(),
		clientSyncCmd(),
		clientUpCmd(),
		clientDownCmd(),
		clientStatusCmd(),
		clientEndpointCmd(),
	)
	return cmd
}

func clientJoinCmd() *cobra.Command {
	var server, token, iface, publicIP, address string
	var peerEndpoints []string
	var wgPort, keepalive, heartbeat int
	c := &cobra.Command{
		Use:   "join",
		Short: "Register with a coordinator using an auth token",
		RunE: func(_ *cobra.Command, _ []string) error {
			if config.Exists() {
				return fmt.Errorf("config already exists at %s (already joined?) — remove it to re-join", config.Path())
			}
			iface = orStr(iface, "wg0")
			if err := valid.InterfaceName(iface); err != nil {
				return err
			}
			if publicIP != "" {
				if err := valid.EndpointHost(publicIP); err != nil {
					return err
				}
			}
			overrides, err := parsePeerEndpoints(peerEndpoints)
			if err != nil {
				return err
			}
			cc, err := client.Join(client.JoinOptions{
				CoordinatorURL:    server,
				Token:             token,
				Interface:         iface,
				ListenPort:        wgPort,
				PublicEndpoint:    publicIP,
				RequestedAddress:  address,
				Keepalive:         keepalive,
				HeartbeatSeconds:  heartbeat,
				EndpointOverrides: overrides,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Joined as %q — address %s, %d peer(s)\n", cc.Name, cc.Address, len(cc.Peers))
			confPath, aerr := client.Apply(cc)
			reportApply(confPath, aerr)
			fmt.Println("\nStart the heartbeat daemon with: wgcoord client run")
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "coordinator control-plane URL, e.g. http://host:51821 (required)")
	c.Flags().StringVar(&token, "token", "", "auth token from `coordinator client add` (required)")
	c.Flags().StringVar(&iface, "interface", "wg0", "WireGuard interface name")
	c.Flags().IntVar(&wgPort, "wg-port", 0, "local WireGuard UDP port (default 51820)")
	c.Flags().StringVar(&publicIP, "public-ip", "", "this node's public IP/host to share with peers")
	c.Flags().StringVar(&address, "address", "", "request a specific mesh IP (granted if free)")
	c.Flags().StringArrayVar(&peerEndpoints, "peer-endpoint", nil,
		"dial a peer at a different address than the coordinator advertises: <peer>=<host[:port]>, or <peer>=- to drop its endpoint (repeatable)")
	c.Flags().IntVar(&keepalive, "keepalive", 0, "persistent-keepalive seconds toward peers (default 25)")
	c.Flags().IntVar(&heartbeat, "heartbeat", 0, "heartbeat interval seconds (default 25)")
	_ = c.MarkFlagRequired("server")
	_ = c.MarkFlagRequired("token")
	return c
}

func clientRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Heartbeat the coordinator and keep the interface in sync (Ctrl+C to stop)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, _, err := config.LoadClient(); err != nil {
				return err
			}
			ctx, cancel := signalContext()
			defer cancel()
			return client.Run(ctx, newLogger())
		},
	}
}

func clientSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Send one heartbeat, fetch missing peers, and re-apply",
		RunE: func(_ *cobra.Command, _ []string) error {
			cc, resp, err := client.Sync()
			if err != nil {
				return err
			}
			fmt.Printf("Synced: +%d peer(s), -%d, %d total\n", len(resp.Add), len(resp.Remove), len(cc.Peers))
			confPath, aerr := client.Apply(cc)
			reportApply(confPath, aerr)
			return nil
		},
	}
}

func clientUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply the cached peer set to the interface (no coordinator call)",
		RunE: func(_ *cobra.Command, _ []string) error {
			confPath, err := client.Up()
			reportApply(confPath, err)
			return nil
		},
	}
}

func clientDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Tear down the WireGuard interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := client.Down(); err != nil {
				return err
			}
			fmt.Println("Interface removed.")
			return nil
		},
	}
}

func clientStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show this client's identity and its peers",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, cc, err := config.LoadClient()
			if err != nil {
				return err
			}
			fmt.Printf("Client %q  %s\n", cc.Name, config.Path())
			coord := cc.CoordinatorURL + " (public)"
			if cc.InternalURL != "" {
				coord += ", " + cc.InternalURL + " (mesh, preferred)"
			}
			fmt.Printf("  coordinator %s\n", coord)
			fmt.Printf("  interface %s (udp/%d), address %s\n", cc.Interface, cc.ListenPort, orStr(cc.Address, "-"))
			fmt.Printf("  public key %s\n", cc.PublicKey)
			if cc.PublicEndpoint != "" {
				fmt.Printf("  public endpoint %s\n", cc.PublicEndpoint)
			}
			fmt.Printf("\n%d peer(s):\n", len(cc.Peers))
			if len(cc.Peers) == 0 {
				return nil
			}
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tALLOWED IPS\tPUBLIC KEY\tENDPOINT")
			for _, p := range cc.Peers {
				ep := orStr(cc.ResolveEndpoint(p), "-")
				if _, ok := cc.EndpointOverrideFor(p); ok {
					ep += " (override)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.AllowedIPs, shortKey(p.PublicKey), ep)
			}
			return tw.Flush()
		},
	}
}

// clientEndpointCmd manages the local peer-endpoint overrides: which address
// *this* node dials for a given peer, regardless of what the coordinator says.
func clientEndpointCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoint",
		Short: "Override the address this node dials for a peer (NAT hairpin, split LAN)",
		Long: "Pin the WireGuard endpoint this node uses for a peer, overriding the one the\n" +
			"coordinator advertises. The override is local to this machine and survives\n" +
			"heartbeats, so a node sharing a NAT with a peer can dial it on the LAN\n" +
			"instead of a public IP the router will not hairpin.",
	}
	cmd.AddCommand(clientEndpointSetCmd(), clientEndpointClearCmd(), clientEndpointListCmd())
	return cmd
}

func clientEndpointSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <peer> <host[:port]|->",
		Short: "Pin the endpoint for a peer (name or id); `-` drops it entirely",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			cc, err := client.SetEndpointOverride(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Printf("Peer %q pinned to %s\n", args[0], args[1])
			if !cc.KnownPeer(args[0]) {
				fmt.Printf("note: no current peer is named %q — it applies if one appears\n", args[0])
			}
			confPath, aerr := client.Apply(cc)
			reportApply(confPath, aerr)
			return nil
		},
	}
}

func clientEndpointClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "clear <peer>",
		Short:   "Drop an override and go back to the coordinator-advertised endpoint",
		Aliases: []string{"unset", "remove", "rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cc, err := client.ClearEndpointOverride(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Override for %q removed\n", args[0])
			confPath, aerr := client.Apply(cc)
			reportApply(confPath, aerr)
			return nil
		},
	}
}

func clientEndpointListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "Show the endpoint overrides configured on this node",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, cc, err := config.LoadClient()
			if err != nil {
				return err
			}
			if len(cc.EndpointOverrides) == 0 {
				fmt.Println("No endpoint overrides — every peer is dialed at the address the coordinator advertises.")
				return nil
			}
			keys := make([]string, 0, len(cc.EndpointOverrides))
			for k := range cc.EndpointOverrides {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PEER\tOVERRIDE\tSTATUS")
			for _, k := range keys {
				status := "active"
				if !cc.KnownPeer(k) {
					status = "no such peer (yet)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", k, cc.EndpointOverrides[k], status)
			}
			return tw.Flush()
		},
	}
}

// parsePeerEndpoints turns repeated `--peer-endpoint <peer>=<host[:port]>` flags
// into the override map stored on the client config.
func parsePeerEndpoints(items []string) (map[string]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(items))
	for _, item := range items {
		peer, endpoint, ok := strings.Cut(item, "=")
		peer, endpoint = strings.TrimSpace(peer), strings.TrimSpace(endpoint)
		if !ok || peer == "" || endpoint == "" {
			return nil, fmt.Errorf("--peer-endpoint wants <peer>=<host[:port]>, got %q", item)
		}
		if err := valid.EndpointOverride(endpoint); err != nil {
			return nil, err
		}
		m[peer] = endpoint
	}
	return m, nil
}
