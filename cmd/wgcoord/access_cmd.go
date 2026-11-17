package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"wgcoord/internal/config"
	"wgcoord/internal/coordinator"
)

// coordGroupCmd manages named groups of addresses: reusable sets of CIDRs,
// optionally limited to ports, for grants and (when port-free) routes.
func coordGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage named groups of CIDRs (with optional ports) for grants and routes",
		Long: "A group is a named set of CIDRs, each optionally limited to ports, e.g.\n" +
			"\"staging\" = 10.8.0.0/28 on tcp/25432 and tcp/26379. Grant a group to hub-only\n" +
			"clients, or use a port-free group as a route. Editing a group updates every\n" +
			"grant and route that uses it.\n\n" +
			"Ports: tcp/5432, udp/53, tcp/8000-8100, or tcp/udp alone for the whole protocol.",
	}
	cmd.AddCommand(coordGroupCreateCmd(), coordGroupAddCmd(), coordGroupRemoveCmd(),
		coordGroupDeleteCmd(), coordGroupListCmd(), coordGroupShowCmd())
	return cmd
}

func coordGroupCreateCmd() *cobra.Command {
	var ports []string
	c := &cobra.Command{
		Use:   "create <name> [<cidr>...]",
		Short: "Create a group, optionally with CIDRs (--port applies to the CIDRs given here)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			g, err := coordinator.NewStore().GroupCreate(args[0], args[1:], ports)
			if err != nil {
				return err
			}
			fmt.Printf("Created group %q", g.Name)
			if len(g.Entries) > 0 {
				fmt.Printf(": %s", entriesCell(g.Entries))
			}
			fmt.Println()
			return nil
		},
	}
	c.Flags().StringArrayVar(&ports, "port", nil, "limit these CIDRs to a port: tcp/5432, udp/53, tcp/8000-8100, tcp; repeatable")
	return c
}

func coordGroupAddCmd() *cobra.Command {
	var ports []string
	c := &cobra.Command{
		Use:   "add <name> <cidr> [<cidr>...]",
		Short: "Add CIDRs to a group (--port applies to the CIDRs given here)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			added, err := coordinator.NewStore().GroupAdd(args[0], args[1:], ports)
			if err != nil {
				return err
			}
			if len(added) == 0 {
				fmt.Printf("Nothing new for group %q (already present).\n", args[0])
				return nil
			}
			fmt.Printf("Added to group %q: %s\n", args[0], entriesCell(added))
			fmt.Println("Grants and routes using it update on the next reconcile and heartbeat.")
			return nil
		},
	}
	c.Flags().StringArrayVar(&ports, "port", nil, "limit these CIDRs to a port: tcp/5432, udp/53, tcp/8000-8100, tcp; repeatable")
	return c
}

func coordGroupRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name> <cidr> [<cidr>...]",
		Aliases: []string{"rm"},
		Short:   "Remove CIDRs (all their port entries) from a group",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			removed, err := coordinator.NewStore().GroupRemove(args[0], args[1:])
			if err != nil {
				return err
			}
			if len(removed) == 0 {
				fmt.Printf("No matching entries in group %q.\n", args[0])
				return nil
			}
			fmt.Printf("Removed from group %q: %s\n", args[0], strings.Join(removed, ", "))
			return nil
		},
	}
}

func coordGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a group that no grant or route uses",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := coordinator.NewStore().GroupDelete(args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted group %q.\n", args[0])
			return nil
		},
	}
}

func coordGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List groups",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, cc, err := config.LoadCoordinator()
			if err != nil {
				return err
			}
			if len(cc.Groups) == 0 {
				fmt.Println("No groups. Create one with `wgcoord coordinator group create <name> <cidr>...`.")
				return nil
			}
			tw := tabwriter.NewWriter(cmdOut, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tENTRIES\tUSED BY")
			for _, g := range cc.Groups {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", g.Name, orStr(entriesCell(g.Entries), "(empty)"),
					orStr(strings.Join(coordinator.GroupUsers(cc, g.Name), ", "), "-"))
			}
			return tw.Flush()
		},
	}
}

func coordGroupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a group's entries and what uses it",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, cc, err := config.LoadCoordinator()
			if err != nil {
				return err
			}
			for _, g := range cc.Groups {
				if g.Name != args[0] {
					continue
				}
				fmt.Printf("Group %q\n", g.Name)
				if len(g.Entries) == 0 {
					fmt.Println("  (no entries)")
				}
				for _, e := range g.Entries {
					fmt.Printf("  %s  %s\n", e.CIDR, orStr(strings.Join(e.Ports, ", "), "all ports"))
				}
				fmt.Printf("Used by: %s\n", orStr(strings.Join(coordinator.GroupUsers(cc, g.Name), ", "), "nothing"))
				return nil
			}
			return fmt.Errorf("no group named %q", args[0])
		},
	}
}

// coordGrantCmd manages what hub-only clients may reach.
func coordGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Manage what hub-only clients may reach (CIDRs, groups, ports)",
		Long: "Grants are what a hub-only client may open through the coordinator: a CIDR,\n" +
			"a group, or \"all\" (the mesh range plus every route), optionally limited to\n" +
			"ports. The coordinator's firewall enforces them; changes apply on its next\n" +
			"reconcile (≤15s) and reach the client on its next heartbeat.",
	}
	cmd.AddCommand(coordGrantAddCmd(), coordGrantRemoveCmd(), coordGrantListCmd())
	return cmd
}

func coordGrantAddCmd() *cobra.Command {
	var ports []string
	c := &cobra.Command{
		Use:   "add <client> <cidr|group|all> [...]",
		Short: "Allow a hub-only client to reach CIDRs or groups, optionally on --port only",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			added, warnings, err := coordinator.NewStore().GrantAdd(args[0], args[1:], ports)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Printf("warning: %s\n", w)
			}
			if len(added) == 0 {
				fmt.Printf("No new grants for %q (already present).\n", args[0])
				return nil
			}
			labels := make([]string, len(added))
			for i, g := range added {
				labels[i] = grantLabel(g)
			}
			fmt.Printf("Granted %q: %s\n", args[0], strings.Join(labels, ", "))
			return nil
		},
	}
	c.Flags().StringArrayVar(&ports, "port", nil, "limit to a port: tcp/5432, udp/53, tcp/8000-8100, tcp; repeatable")
	return c
}

func coordGrantRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <client> <cidr|group|all> [...]",
		Aliases: []string{"rm", "revoke"},
		Short:   "Revoke grants (whatever their ports)",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			removed, err := coordinator.NewStore().GrantRemove(args[0], args[1:])
			if err != nil {
				return err
			}
			if len(removed) == 0 {
				fmt.Printf("No matching grants on %q.\n", args[0])
				return nil
			}
			fmt.Printf("Revoked from %q: %s\n", args[0], strings.Join(removed, ", "))
			fmt.Println("The coordinator's firewall drops it on its next reconcile (≤15s).")
			return nil
		},
	}
}

func coordGrantListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list [<client>]",
		Aliases: []string{"ls"},
		Short:   "Show grants and what they resolve to",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, cc, err := config.LoadCoordinator()
			if err != nil {
				return err
			}
			found := false
			for _, cl := range cc.Clients {
				if len(args) == 1 && cl.Name != args[0] {
					continue
				}
				found = true
				if !cl.HubOnly {
					if len(args) == 1 {
						fmt.Printf("%s: mesh client (reaches every node; grants don't apply)\n", cl.Name)
					}
					continue
				}
				views := coordinator.DescribeGrants(cc, cl)
				if len(views) == 0 {
					fmt.Printf("%s: no grants (reaches only the coordinator's control plane)\n", cl.Name)
					continue
				}
				fmt.Printf("%s:\n", cl.Name)
				for _, v := range views {
					reach := strings.Join(v.Reaches, "; ")
					if reach == "" {
						reach = "nothing routed right now"
					}
					fmt.Printf("  %-28s → %s\n", v.Label, reach)
				}
			}
			if len(args) == 1 && !found {
				return fmt.Errorf("no client named %q", args[0])
			}
			return nil
		},
	}
}

func entriesCell(es []config.GroupEntry) string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		if len(e.Ports) == 0 {
			parts = append(parts, e.CIDR)
		} else {
			parts = append(parts, e.CIDR+" ("+strings.Join(e.Ports, ", ")+")")
		}
	}
	return strings.Join(parts, ", ")
}

func grantLabel(g config.Grant) string {
	if len(g.Ports) == 0 {
		return g.Target
	}
	return g.Target + " (" + strings.Join(g.Ports, ", ") + ")"
}

// grantsCell renders a client's grants for a status table cell.
func grantsCell(cl *config.Client) string {
	if !cl.HubOnly {
		return "-"
	}
	if len(cl.Grants) == 0 {
		return "(none)"
	}
	parts := make([]string, len(cl.Grants))
	for i, g := range cl.Grants {
		parts[i] = g.Target
		if len(g.Ports) > 0 {
			parts[i] += ":" + strings.Join(g.Ports, "+")
		}
	}
	return strings.Join(parts, ",")
}
