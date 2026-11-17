package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"wgcoord/internal/client"
	"wgcoord/internal/config"
	"wgcoord/internal/valid"
)

// profileFlag is `--profile`: the profile a client command acts on. Empty
// means the active profile. Each command registers it with its own help text.
var profileFlag string

// withProfile adds `--profile`/`-p` to c, completing profile names.
func withProfile(c *cobra.Command, usage string) *cobra.Command {
	c.Flags().StringVarP(&profileFlag, "profile", "p", "", usage)
	_ = c.RegisterFlagCompletionFunc("profile", completeProfiles)
	return c
}

// completeProfiles offers the profile names in the config.
func completeProfiles(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	// Completion skips PersistentPreRunE, so --config has to be applied here.
	if f := cmd.Flag("config"); f != nil && strings.TrimSpace(f.Value.String()) != "" {
		if abs, err := filepath.Abs(strings.TrimSpace(f.Value.String())); err == nil {
			config.SetPath(abs)
		}
	}
	c, err := config.LoadClient()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return c.ProfileNames(), cobra.ShellCompDirectiveNoFileComp
}

// completeFirstProfile completes a command's first argument as a profile name.
func completeFirstProfile(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeProfiles(cmd, args, toComplete)
}

func clientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Join coordinators and run as a mesh client",
		Long: "Join one or more coordinators and run as a mesh client. Each coordinator\n" +
			"joined is a profile in the one config file; one profile is active (connected)\n" +
			"at a time. Switch with `wgcoord client use <profile>`.",
	}
	cmd.AddCommand(
		clientJoinCmd(),
		clientRunCmd(),
		clientSyncCmd(),
		clientUpCmd(),
		clientDownCmd(),
		clientStatusCmd(),
		clientEndpointCmd(),
		clientUseCmd(),
		clientProfileCmd(),
	)
	return cmd
}

func clientJoinCmd() *cobra.Command {
	var server, token, iface, publicIP, address string
	var peerEndpoints []string
	var wgPort, keepalive, heartbeat int
	c := &cobra.Command{
		Use:   "join",
		Short: "Register with a coordinator using an auth token, as a new profile",
		Long: "Register with a coordinator and save it as a new profile. The first profile\n" +
			"is named \"default\" unless --profile names it; later ones need --profile.\n" +
			"A new profile becomes active only when no other profile is.",
		RunE: func(_ *cobra.Command, _ []string) error {
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
			j, err := client.Join(client.JoinOptions{
				Profile:           profileFlag,
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
			cc := j.Client
			fmt.Printf("Joined as %q — profile %q, address %s, %d peer(s)\n", cc.Name, j.Profile, cc.Address, len(cc.Peers))
			if !j.Active {
				fmt.Printf("\nAnother profile is active, so %q is saved but not connected.\n", j.Profile)
				fmt.Printf("Switch to it with: wgcoord client use %s\n", j.Profile)
				return nil
			}
			reportApplied(j.Applied)
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
	// Not withProfile: the name is new, so there is nothing to complete.
	c.Flags().StringVarP(&profileFlag, "profile", "p", "",
		`name for the new profile (default "default"; required once a profile exists)`)
	return c
}

func clientRunCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "run",
		Short: "Heartbeat the active profile's coordinator and keep the interface in sync (Ctrl+C to stop)",
		Long: "Heartbeat the active profile's coordinator and keep the interface in sync.\n" +
			"The daemon follows the active profile: `wgcoord client use <other>` switches it\n" +
			"within seconds. With --profile, switch to that profile first.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := config.LoadClient(); err != nil {
				return err
			}
			release, ok, err := config.TryLockDaemon()
			if err != nil {
				return err
			}
			if !ok {
				if profileFlag == "" {
					return fmt.Errorf("`wgcoord client run` is already running on %s — switch profiles with `wgcoord client use <profile>`", config.Path())
				}
				if err := upAndReport(profileFlag); err != nil {
					return err
				}
				fmt.Println("`wgcoord client run` is already running on this config; it follows the switch.")
				return nil
			}
			defer release()
			if profileFlag != "" {
				if err := upAndReport(profileFlag); err != nil {
					return err
				}
			}
			ctx, cancel := signalContext()
			defer cancel()
			return client.Run(ctx, newLogger())
		},
	}
	return withProfile(c, "switch to this profile before running (default: the active profile)")
}

func clientSyncCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "sync",
		Short: "Send one heartbeat, fetch missing peers, and re-apply",
		RunE: func(_ *cobra.Command, _ []string) error {
			res, err := client.Sync(profileFlag)
			if err != nil {
				return err
			}
			fmt.Printf("Synced %q: +%d peer(s), -%d, %d total\n", res.Profile, len(res.Resp.Add), len(res.Resp.Remove), len(res.Client.Peers))
			reportApplied(res.Applied)
			return nil
		},
	}
	return withProfile(c, "profile to heartbeat; an inactive one is saved but not applied (default: the active profile)")
}

func clientUpCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "up",
		Short: "Apply the cached peer set to the interface (no coordinator call); --profile switches to it",
		RunE: func(_ *cobra.Command, _ []string) error {
			return upAndReport(profileFlag)
		},
	}
	return withProfile(c, "profile to bring up, switching to it if another is active (default: the active profile)")
}

func clientDownCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "down",
		Short: "Tear down the active profile's WireGuard interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			name, err := client.Down(profileFlag)
			if err != nil {
				return err
			}
			fmt.Printf("Interface removed (profile %q).\n", name)
			return nil
		},
	}
	return withProfile(c, "profile whose interface to tear down (default: the active profile)")
}

// clientUseCmd switches the active profile, closing the previous one.
func clientUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "use <profile>",
		ValidArgsFunction: completeFirstProfile,
		Aliases:           []string{"switch"},
		Short:             "Connect to a profile's coordinator, closing every other profile's interface",
		Args:              cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			a, err := client.Use(args[0])
			if err != nil {
				return err
			}
			reportActivated(a)
			// The daemon holds this lock while it runs, so getting it means none is.
			if release, free, err := config.TryLockDaemon(); err == nil {
				if free {
					release()
					fmt.Println("Start the heartbeat daemon with: wgcoord client run")
				} else {
					fmt.Println("The running `wgcoord client run` follows the switch.")
				}
			}
			return nil
		},
	}
}

// upAndReport brings up a profile (switching to it when it isn't active) and
// prints the outcome.
func upAndReport(profile string) error {
	a, err := client.Up(profile)
	if err != nil {
		return err
	}
	reportActivated(a)
	return nil
}

func reportActivated(a *client.Activated) {
	switch {
	case a.Previous == a.Profile:
		fmt.Printf("Profile %q (client %q, coordinator %s)\n", a.Profile, a.Client.Name, a.Client.CoordinatorURL)
	case a.Previous == "":
		fmt.Printf("Switched to profile %q (client %q, coordinator %s)\n", a.Profile, a.Client.Name, a.Client.CoordinatorURL)
	default:
		fmt.Printf("Closed profile %q; switched to %q (client %q, coordinator %s)\n", a.Previous, a.Profile, a.Client.Name, a.Client.CoordinatorURL)
	}
	reportApplied(a.Applied)
}

// reportApplied prints a live-apply outcome, or that the profile is inactive.
func reportApplied(a client.Applied) {
	if a.Skipped {
		fmt.Println("Profile is not active, so the interface was left alone; it applies on `wgcoord client use`.")
		return
	}
	reportApply(a.ConfPath, a.Err)
}

func clientStatusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Show a profile's identity and its peers (the active profile by default)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, name, cc, err := config.LoadProfile(profileFlag)
			if err != nil {
				return err
			}
			state := "inactive"
			if name == c.ActiveProfile {
				state = "active"
			}
			fmt.Printf("Client %q  profile %q (%s)  %s\n", cc.Name, name, state, config.Path())
			coord := cc.CoordinatorURL + " (public)"
			if cc.InternalURL != "" {
				coord += ", " + cc.InternalURL + " (mesh, preferred)"
			}
			fmt.Printf("  coordinator %s\n", coord)
			fmt.Printf("  interface %s (udp/%d), address %s\n", cc.Interface, cc.ListenPort, orStr(cc.Address, "-"))
			if cc.HubOnly {
				fmt.Println("  mode hub-only (all traffic goes through the coordinator, which enforces this client's grants)")
			} else {
				fmt.Println("  mode mesh")
			}
			fmt.Printf("  public key %s\n", cc.PublicKey)
			if cc.PublicEndpoint != "" {
				fmt.Printf("  public endpoint %s\n", cc.PublicEndpoint)
			}
			if others := len(c.Profiles) - 1; others > 0 {
				fmt.Printf("  %d other profile(s): wgcoord client profile list\n", others)
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
	return withProfile(c, "profile to show (default: the active profile)")
}

// clientProfileCmd manages the profiles: one per coordinator joined.
func clientProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "profile",
		Aliases: []string{"profiles"},
		Short:   "List, switch, rename, remove or import client profiles (one per coordinator)",
	}
	cmd.AddCommand(clientProfileListCmd(), clientUseCmd(), clientProfileRenameCmd(),
		clientProfileRemoveCmd(), clientProfileImportCmd())
	return cmd
}

func clientProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "Show every profile; * marks the active one",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := config.LoadClient()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "\tPROFILE\tCLIENT\tCOORDINATOR\tINTERFACE\tADDRESS\tMODE\tPEERS")
			for _, n := range c.ProfileNames() {
				p := c.Profiles[n]
				mark, mode := "", "mesh"
				if n == c.ActiveProfile {
					mark = "*"
				}
				if p.HubOnly {
					mode = "hub-only"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", mark, n, orStr(p.Name, "-"), p.CoordinatorURL,
					p.Interface, orStr(p.Address, "-"), mode, len(p.Peers))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if c.ActiveProfile == "" {
				fmt.Println("\nNo profile is active. Connect one with: wgcoord client use <profile>")
			}
			return nil
		},
	}
}

func clientProfileRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "rename <old> <new>",
		ValidArgsFunction: completeFirstProfile,
		Aliases:           []string{"mv"},
		Short:             "Rename a profile",
		Args:              cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := client.RenameProfile(args[0], args[1]); err != nil {
				return err
			}
			fmt.Printf("Profile %q renamed to %q\n", args[0], args[1])
			return nil
		},
	}
}

func clientProfileRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "remove <profile>",
		ValidArgsFunction: completeFirstProfile,
		Aliases:           []string{"rm", "delete"},
		Short:             "Delete a profile with its keys and token (the active one is taken down first)",
		Args:              cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			wasActive, err := client.RemoveProfile(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Profile %q removed.\n", args[0])
			if wasActive {
				fmt.Println("It was the active profile: its interface is down and no profile is active now.")
			}
			fmt.Println("The coordinator still lists this client; remove it there with `wgcoord coordinator client remove <name>`.")
			return nil
		},
	}
}

func clientProfileImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <profile> <config.json>",
		Short: "Copy the client from another wgcoord config file in as a new profile",
		Long: "Copy the client joined through another wgcoord config file (one used with\n" +
			"--config) into this config as a new profile, keys, token and endpoint overrides\n" +
			"included, so no re-join is needed. The other file is left as it was.",
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			cc, err := client.ImportProfile(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Printf("Imported client %q (coordinator %s) as profile %q into %s\n", cc.Name, cc.CoordinatorURL, args[0], config.Path())
			fmt.Printf("Connect it with: wgcoord client use %s\n", args[0])
			return nil
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
	c := &cobra.Command{
		Use:   "set <peer> <host[:port]|->",
		Short: "Pin the endpoint for a peer (name or id); `-` drops it entirely",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			e, err := client.SetEndpointOverride(profileFlag, args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Printf("Peer %q pinned to %s (profile %q)\n", args[0], args[1], e.Profile)
			if !e.Client.KnownPeer(args[0]) {
				fmt.Printf("note: no current peer is named %q — it applies if one appears\n", args[0])
			}
			reportApplied(e.Applied)
			return nil
		},
	}
	return withProfile(c, "profile to pin the endpoint in; applied only if active (default: the active profile)")
}

func clientEndpointClearCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "clear <peer>",
		Short:   "Drop an override and go back to the coordinator-advertised endpoint",
		Aliases: []string{"unset", "remove", "rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			e, err := client.ClearEndpointOverride(profileFlag, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Override for %q removed (profile %q)\n", args[0], e.Profile)
			reportApplied(e.Applied)
			return nil
		},
	}
	return withProfile(c, "profile to clear the override in; applied only if active (default: the active profile)")
}

func clientEndpointListCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "list",
		Short:   "Show the endpoint overrides configured on this node",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, _, cc, err := config.LoadProfile(profileFlag)
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
	return withProfile(c, "profile whose overrides to list (default: the active profile)")
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
