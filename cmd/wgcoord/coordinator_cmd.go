package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
		coordRouteCmd(),
		coordGroupCmd(),
		coordGrantCmd(),
		coordTokenCmd(),
		coordBlacklistCmd(),
		coordStatusCmd(),
	)
	return cmd
}

func coordInitCmd() *cobra.Command {
	var controlPort, wgPort, clientWGPort int
	var iface, ipRange, address, publicIP, tlsCert, tlsKey string
	var routes []string
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
			canonRoutes, err := canonicalRoutes(routes)
			if err != nil {
				return err
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
				Routes:         canonRoutes,
				Clients:        []*config.Client{},
			}
			if err := config.Save(&config.Config{Mode: config.ModeCoordinator, Coordinator: cc}); err != nil {
				return err
			}
			fmt.Printf("Coordinator initialized at %s\n", config.Path())
			fmt.Printf("  interface:    %s (udp/%d)\n", cc.Interface, cc.ListenPort)
			fmt.Printf("  control port: tcp/%d\n", cc.ControlPort)
			fmt.Printf("  mesh range:   %s (hub %s)\n", cc.IPRange, cc.Address)
			if len(cc.Routes) > 0 {
				fmt.Printf("  routes:       %s\n", strings.Join(cc.Routes, ", "))
			}
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
	c.Flags().StringArrayVar(&routes, "route", nil, "extra CIDR the hub carries, added to its advertised AllowedIPs (e.g. a pod subnet); repeatable")
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
	cmd.AddCommand(coordClientAddCmd(), coordClientRemoveCmd(), coordClientRenameCmd(), coordClientModeCmd())
	return cmd
}

func coordClientAddCmd() *cobra.Command {
	var address string
	var routes, grants []string
	var hubOnly bool
	c := &cobra.Command{
		Use:   "add <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Create a named client and print its one-time auth token",
		Long: "Create a named client and print its one-time auth token.\n\n" +
			"A mesh client (the default) peers with every node. A --hub-only client peers\n" +
			"with the coordinator alone; the coordinator forwards its traffic and its\n" +
			"firewall limits it to the client's grants (--grant, or `coordinator grant add`).",
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := coordinator.NewStore().AddClient(args[0], coordinator.ClientOptions{
				Address: address, Routes: routes, HubOnly: hubOnly, Grants: grants,
			})
			if err != nil {
				return err
			}
			cl, tok := res.Client, res.Token
			_, cc, _ := config.LoadCoordinator()
			fmt.Printf("Client %q created\n", cl.Name)
			fmt.Printf("  id:      %s\n", cl.ID)
			fmt.Printf("  address: %s\n", cl.Address)
			fmt.Printf("  mode:    %s\n", modeName(cl))
			if len(cl.Routes) > 0 {
				fmt.Printf("  routes:  %s\n", strings.Join(cl.Routes, ", "))
			}
			if len(cl.Grants) > 0 {
				fmt.Printf("  grants:  %s\n", grantsCell(cl))
			}
			for _, w := range res.Warnings {
				fmt.Printf("  warning: %s\n", w)
			}
			fmt.Printf("  token:   %s\n", tok)
			fmt.Println("\nOn the client machine run:")
			fmt.Printf("  wgcoord client join --server %s --token %s\n", coordinatorURLHint(cc), tok)
			if cl.HubOnly && cl.Grants == nil {
				fmt.Printf("\nIt can reach nothing yet: grant access with `wgcoord coordinator grant add %s <cidr|group>`.\n", cl.Name)
			}
			fmt.Println("\n⚠  The token is shown once. Store it now; regenerate with `wgcoord coordinator token regenerate` if lost.")
			return nil
		},
	}
	c.Flags().StringVar(&address, "address", "", "assign a specific mesh IP (default: auto-allocate lowest free)")
	c.Flags().StringArrayVar(&routes, "route", nil, "CIDR or group this client carries, added to its advertised AllowedIPs (e.g. a pod subnet); repeatable")
	c.Flags().BoolVar(&hubOnly, "hub-only", false, "peer with the coordinator only; access is limited to the client's grants")
	c.Flags().StringArrayVar(&grants, "grant", nil, "CIDR, group or \"all\" a hub-only client may reach; repeatable (ports: use `coordinator grant add`)")
	return c
}

func coordClientModeCmd() *cobra.Command {
	var clearGrants bool
	c := &cobra.Command{
		Use:   "mode <name> mesh|hub-only",
		Args:  cobra.ExactArgs(2),
		Short: "Switch a client between mesh and hub-only",
		Long: "Switch a client between mesh (peers with every node, full access) and hub-only\n" +
			"(peers with the coordinator alone, limited to its grants). Leaving hub-only\n" +
			"while grants exist needs --clear-grants, so widening access is deliberate.",
		RunE: func(_ *cobra.Command, args []string) error {
			var hubOnly bool
			switch args[1] {
			case "hub-only", "hubonly", "hub":
				hubOnly = true
			case "mesh":
			default:
				return fmt.Errorf("unknown mode %q (want mesh or hub-only)", args[1])
			}
			changed, err := coordinator.NewStore().SetMode(args[0], hubOnly, clearGrants)
			if err != nil {
				return err
			}
			if !changed {
				fmt.Printf("%q is already %s.\n", args[0], args[1])
				return nil
			}
			fmt.Printf("%q is now %s. Every node picks this up on its next heartbeat.\n", args[0], args[1])
			if hubOnly {
				fmt.Printf("Grant access with `wgcoord coordinator grant add %s <cidr|group>`.\n", args[0])
			}
			return nil
		},
	}
	c.Flags().BoolVar(&clearGrants, "clear-grants", false, "drop the client's grants when switching to mesh")
	return c
}

func modeName(cl *config.Client) string {
	if cl.HubOnly {
		return "hub-only"
	}
	return "mesh"
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

// coordRouteCmd manages the extra CIDRs a node carries beyond its mesh /32.
// Those routes are appended to the AllowedIPs advertised for the node, so peers
// route the subnets (Kubernetes pod CIDRs, LANs behind a node) through its
// tunnel instead of WireGuard's cryptokey routing dropping them. <node> is a
// client name, or "coordinator" for the hub itself.
func coordRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Manage extra routes (AllowedIPs) a node advertises, e.g. Kubernetes pod CIDRs",
		Long: "Manage the extra CIDRs a node carries beyond its own mesh address. Each is\n" +
			"appended to the AllowedIPs advertised for that node, so peers send the subnet\n" +
			"through its tunnel. Use this to let Kubernetes pod traffic (or any subnet\n" +
			"behind a node) cross the mesh. <node> is a client name, or \"coordinator\" for\n" +
			"the hub. A route may be a CIDR or a port-free group. Changes reach every peer\n" +
			"on its next heartbeat (≤ the beat interval).",
	}
	cmd.AddCommand(coordRouteAddCmd(), coordRouteRemoveCmd(), coordRouteListCmd())
	return cmd
}

func coordRouteAddCmd() *cobra.Command {
	var nat bool
	c := &cobra.Command{
		Use:   "add <node> <cidr|group> [<cidr|group>...]",
		Short: "Add one or more routes to a node's advertised AllowedIPs",
		Long: "Add routes to a node. --nat (coordinator only) marks networks next to the\n" +
			"coordinator, such as a cloud VPC: the coordinator forwards mesh traffic into\n" +
			"them and masquerades it, so hosts there need no route back to the mesh.",
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			added, err := coordinator.NewStore().AddRoutes(args[0], args[1:], nat)
			if err != nil {
				return err
			}
			if len(added) == 0 {
				fmt.Printf("No new routes for %q (already present).\n", args[0])
				return nil
			}
			suffix := ""
			if nat {
				suffix = " (NAT)"
			}
			fmt.Printf("Added to %q: %s%s\n", args[0], strings.Join(added, ", "), suffix)
			fmt.Println("Peers pick this up on their next heartbeat.")
			return nil
		},
	}
	c.Flags().BoolVar(&nat, "nat", false, "coordinator only: masquerade mesh traffic into this network next to the coordinator")
	return c
}

func coordRouteRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <node> <cidr|group> [<cidr|group>...]",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove one or more routes from a node's advertised AllowedIPs",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			removed, err := coordinator.NewStore().RemoveRoutes(args[0], args[1:])
			if err != nil {
				return err
			}
			if len(removed) == 0 {
				fmt.Printf("No matching routes on %q.\n", args[0])
				return nil
			}
			fmt.Printf("Removed from %q: %s\n", args[0], strings.Join(removed, ", "))
			fmt.Println("Peers drop it on their next heartbeat.")
			return nil
		},
	}
}

func coordRouteListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [<node>]",
		Short: "List routes for a node, or every node when omitted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, cc, err := config.LoadCoordinator()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				routes, name, err := coordinator.NewStore().Routes(args[0])
				if err != nil {
					return err
				}
				printRoutes(cc, name, routes)
				return nil
			}
			printRoutes(cc, "coordinator", cc.Routes)
			for _, cl := range cc.Clients {
				if cl.HubOnly {
					continue
				}
				printRoutes(cc, cl.Name, cl.Routes)
			}
			return nil
		},
	}
}

func printRoutes(cc *config.CoordinatorConfig, name string, routes []string) {
	if len(routes) == 0 {
		fmt.Printf("%s: (none)\n", name)
		return
	}
	fmt.Printf("%s: %s\n", name, describeRefs(cc, routes, name == "coordinator"))
}

// describeRefs renders route refs, expanding groups and marking NAT routes:
// "10.42.0.0/24, cloud-net (10.0.0.0/16) [nat]".
func describeRefs(cc *config.CoordinatorConfig, refs []string, hub bool) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		part := r
		if exp := coordinator.ResolveRoutes(cc, []string{r}); len(exp) > 0 && (len(exp) != 1 || exp[0] != r) {
			part += " (" + strings.Join(exp, ", ") + ")"
		} else if len(exp) == 0 {
			part += " (empty group)"
		}
		if hub {
			for _, n := range cc.NATRoutes {
				if n == r {
					part += " [nat]"
				}
			}
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
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
			if len(cc.Routes) > 0 {
				fmt.Printf("  routes %s\n", describeRefs(cc, cc.Routes, true))
			}
			if len(cc.Groups) > 0 {
				names := make([]string, 0, len(cc.Groups))
				for _, g := range cc.Groups {
					names = append(names, g.Name)
				}
				fmt.Printf("  groups %s\n", strings.Join(names, ", "))
			}
			if cc.PublicEndpoint != "" {
				fmt.Printf("  public %s\n", net.JoinHostPort(cc.PublicEndpoint, strconv.Itoa(cc.ListenPort)))
			}
			fmt.Printf("  control plane %s (public)", coordinatorURLHint(cc))
			if in := cc.InternalControlURL(); in != "" {
				fmt.Printf(", %s (mesh — clients prefer this once their tunnel is up)", in)
			}
			fmt.Println()
			fmt.Printf("\n%d client(s):\n", len(cc.Clients))
			if len(cc.Clients) == 0 {
				return nil
			}
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tADDRESS\tMODE\tROUTES\tGRANTS\tPUBLIC KEY\tENDPOINT\tSTATUS\tLAST SEEN")
			for _, cl := range cc.Clients {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					cl.Name, cl.Address, modeName(cl), routesCell(cl.Routes), grantsCell(cl), shortKey(cl.PublicKey), orStr(cl.Endpoint, "-"),
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

// coordinatorURLHint builds the public control-plane URL to print in join
// instructions, on the scheme the hub actually serves.
func coordinatorURLHint(cc *config.CoordinatorConfig) string {
	host := cc.PublicEndpoint
	if host == "" {
		host = "<coordinator-host>"
	}
	scheme := "http"
	if cc.TLSEnabled() {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(cc.ControlPort))
}
