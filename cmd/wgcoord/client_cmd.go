package main

import (
	"fmt"
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
	)
	return cmd
}

func clientJoinCmd() *cobra.Command {
	var server, token, iface, publicIP, address string
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
			cc, err := client.Join(client.JoinOptions{
				CoordinatorURL:   server,
				Token:            token,
				Interface:        iface,
				ListenPort:       wgPort,
				PublicEndpoint:   publicIP,
				RequestedAddress: address,
				Keepalive:        keepalive,
				HeartbeatSeconds: heartbeat,
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
			fmt.Printf("  coordinator %s\n", cc.CoordinatorURL)
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
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.AllowedIPs, shortKey(p.PublicKey), orStr(p.Endpoint, "-"))
			}
			return tw.Flush()
		},
	}
}
