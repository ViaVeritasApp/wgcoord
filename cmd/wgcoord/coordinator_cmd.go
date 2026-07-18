package main

import (
	"fmt"
	"net"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"wgcoord/internal/config"
	"wgcoord/internal/coordinator"
	"wgcoord/internal/ipalloc"
	"wgcoord/internal/valid"
	"wgcoord/internal/wgkey"
)

func coordinatorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "coordinator",
		Aliases: []string{"coord"},
		Short:   "Run and manage the coordinator (mesh hub)",
	}
	cmd.AddCommand(
		coordInitCmd(),
		coordRunCmd(),
		coordClientCmd(),
		coordTokenCmd(),
		coordBlacklistCmd(),
		coordStatusCmd(),
	)
	return cmd
}

func coordInitCmd() *cobra.Command {
	var controlPort, wgPort, clientWGPort int
	var iface, ipRange, address, publicIP, tlsCert, tlsKey string
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Initialize this machine as the coordinator",
		RunE: func(_ *cobra.Command, _ []string) error {
			if config.Exists() && !force {
				return fmt.Errorf("config already exists at %s (use --force to overwrite)", config.Path())
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
			ipRange = orStr(ipRange, config.DefaultIPRange)
			if address == "" {
				a, err := ipalloc.FirstHost(ipRange)
				if err != nil {
					return err
				}
				address = a
			} else if ok, err := ipalloc.Usable(ipRange, address); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("%s is not a usable host in %s", address, ipRange)
			}
			kp, err := wgkey.Generate()
			if err != nil {
				return err
			}
			cc := &config.CoordinatorConfig{
				ControlPort:    orInt(controlPort, config.DefaultControlPort),
				Interface:      iface,
				ListenPort:     orInt(wgPort, config.DefaultWGPort),
				PublicEndpoint: publicIP,
				IPRange:        ipRange,
				Address:        address,
				ClientWGPort:   orInt(clientWGPort, config.DefaultClientWGPort),
				PrivateKey:     kp.PrivateKey,
				PublicKey:      kp.PublicKey,
				TLSCertFile:    tlsCert,
				TLSKeyFile:     tlsKey,
				Clients:        []*config.Client{},
			}
			if err := config.Save(&config.Config{Mode: config.ModeCoordinator, Coordinator: cc}); err != nil {
				return err
			}
			fmt.Printf("Coordinator initialized at %s\n", config.Path())
			fmt.Printf("  interface:    %s (udp/%d)\n", cc.Interface, cc.ListenPort)
			fmt.Printf("  control port: tcp/%d\n", cc.ControlPort)
			fmt.Printf("  mesh range:   %s (hub %s)\n", cc.IPRange, cc.Address)
			fmt.Printf("  public key:   %s\n", cc.PublicKey)
			if publicIP == "" {
				fmt.Println("\n⚠  No --public-ip set: clients can't dial this hub until you provide one (re-run with --force, or edit config).")
			} else {
				fmt.Printf("  public:       %s\n", net.JoinHostPort(publicIP, strconv.Itoa(cc.ListenPort)))
			}
			fmt.Println("\nNext: add a client with `wgcoord coordinator client add <name>`, then start `wgcoord coordinator run`.")
			return nil
		},
	}
	c.Flags().IntVar(&controlPort, "control-port", 0, "HTTP control-plane port (default 51821)")
	c.Flags().IntVar(&wgPort, "wg-port", 0, "hub WireGuard UDP port (default 51820)")
	c.Flags().IntVar(&clientWGPort, "client-wg-port", 0, "WireGuard port advertised for clients (default 51820)")
	c.Flags().StringVar(&iface, "interface", "wg0", "WireGuard interface name")
	c.Flags().StringVar(&ipRange, "ip-range", config.DefaultIPRange, "mesh address pool (CIDR)")
	c.Flags().StringVar(&address, "address", "", "hub's own mesh IP (default: first host of the range)")
	c.Flags().StringVar(&publicIP, "public-ip", "", "public IP/host clients dial to reach this hub")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file for the control plane (enables HTTPS)")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file for the control plane (enables HTTPS)")
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	return c
}

func coordRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "run",
		Aliases: []string{"serve"},
		Short:   "Start the control plane and manage the hub interface (Ctrl+C to stop)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, _, err := config.LoadCoordinator(); err != nil {
				return err
			}
			ctx, cancel := signalContext()
			defer cancel()
			return coordinator.NewService(newLogger()).Serve(ctx)
		},
	}
}

func coordClientCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "client", Short: "Manage named clients"}
	cmd.AddCommand(coordClientAddCmd(), coordClientRemoveCmd(), coordClientRenameCmd())
	return cmd
}

func coordClientAddCmd() *cobra.Command {
	var address string
	c := &cobra.Command{
		Use:   "add <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Create a named client and print its one-time auth token",
		RunE: func(_ *cobra.Command, args []string) error {
			cl, tok, err := coordinator.NewStore().AddClient(args[0], address)
			if err != nil {
				return err
			}
			_, cc, _ := config.LoadCoordinator()
			fmt.Printf("Client %q created\n", cl.Name)
			fmt.Printf("  id:      %s\n", cl.ID)
			fmt.Printf("  address: %s\n", cl.Address)
			fmt.Printf("  token:   %s\n", tok)
			fmt.Println("\nOn the client machine run:")
			fmt.Printf("  wgcoord client join --server %s --token %s\n", coordinatorURLHint(cc), tok)
			fmt.Println("\n⚠  The token is shown once. Store it now; regenerate with `wgcoord coordinator token regenerate` if lost.")
			return nil
		},
	}
	c.Flags().StringVar(&address, "address", "", "assign a specific mesh IP (default: auto-allocate lowest free)")
	return c
}

func coordClientRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"rm", "delete"},
		Args:    cobra.ExactArgs(1),
		Short:   "Delete a client from the registry",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := coordinator.NewStore().RemoveClient(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed client %q. The hub drops it on the next reconcile.\n", args[0])
			return nil
		},
	}
}

func coordClientRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old-name> <new-name>",
		Args:  cobra.ExactArgs(2),
		Short: "Rename a client",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := coordinator.NewStore().RenameClient(args[0], args[1]); err != nil {
				return err
			}
			fmt.Printf("Renamed %q to %q\n", args[0], args[1])
			return nil
		},
	}
}

func coordTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage client auth tokens"}
	cmd.AddCommand(&cobra.Command{
		Use:     "regenerate <name>",
		Aliases: []string{"regen", "new"},
		Args:    cobra.ExactArgs(1),
		Short:   "Rotate a client's auth token, invalidating the old one",
		RunE: func(_ *cobra.Command, args []string) error {
			tok, err := coordinator.NewStore().RegenToken(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("New token for %q:\n  %s\n", args[0], tok)
			fmt.Println("The previous token is now invalid; update the client and re-run its join/heartbeat.")
			return nil
		},
	})
	return cmd
}

func coordBlacklistCmd() *cobra.Command {
	blacklist := &cobra.Command{
		Use:   "blacklist <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Block a client from the mesh (refused at control plane, dropped from the hub)",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := coordinator.NewStore().SetBlacklist(args[0], true); err != nil {
				return err
			}
			fmt.Printf("Blacklisted %q. The hub removes its peer on the next reconcile (≤15s).\n", args[0])
			return nil
		},
	}
	blacklist.AddCommand(&cobra.Command{
		Use:   "remove <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Lift the blacklist on a client",
		RunE: func(_ *cobra.Command, args []string) error {
			if err := coordinator.NewStore().SetBlacklist(args[0], false); err != nil {
				return err
			}
			fmt.Printf("Unblacklisted %q. It may rejoin on its next heartbeat.\n", args[0])
			return nil
		},
	})
	return blacklist
}

func coordStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the hub and its configured clients",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, cc, err := config.LoadCoordinator()
			if err != nil {
				return err
			}
			fmt.Printf("Coordinator  %s\n", config.Path())
			fmt.Printf("  interface %s (udp/%d), control tcp/%d\n", cc.Interface, cc.ListenPort, cc.ControlPort)
			fmt.Printf("  range %s, hub %s\n", cc.IPRange, cc.Address)
			if cc.PublicEndpoint != "" {
				fmt.Printf("  public %s\n", net.JoinHostPort(cc.PublicEndpoint, strconv.Itoa(cc.ListenPort)))
			}
			fmt.Printf("\n%d client(s):\n", len(cc.Clients))
			if len(cc.Clients) == 0 {
				return nil
			}
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tADDRESS\tPUBLIC KEY\tENDPOINT\tSTATUS\tLAST SEEN")
			for _, cl := range cc.Clients {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					cl.Name, cl.Address, shortKey(cl.PublicKey), orStr(cl.Endpoint, "-"),
					clientStatus(cl), relTime(cl.LastSeenAt))
			}
			return tw.Flush()
		},
	}
}

func clientStatus(cl *config.Client) string {
	if cl.Blacklisted {
		return "blacklisted"
	}
	if cl.PublicKey == "" {
		return "pending"
	}
	return "registered"
}

// coordinatorURLHint builds the control-plane URL to print in join instructions,
// preferring the configured public endpoint.
func coordinatorURLHint(cc *config.CoordinatorConfig) string {
	host := cc.PublicEndpoint
	if host == "" {
		host = "<coordinator-host>"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(cc.ControlPort))
}
