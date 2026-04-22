package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available Mullvad servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, err := cmd.Flags().GetInt("limit")
		if err != nil {
			return fmt.Errorf("failed to get limit flag: %w", err)
		}

		p := mullvad.New()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		servers, err := p.GetFilteredServers(ctx, buildBaseFilter())
		if err != nil {
			return fmt.Errorf("failed to list servers: %w", err)
		}

		if limit > 0 && len(servers) > limit {
			servers = servers[:limit]
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Country\tCity\tSOCKS5\tIPv4\tProvider\tMultihop\tHostname")
		fmt.Fprintln(w, "-------\t----\t-------\t----\t--------\t--------\t--------")

		for _, s := range servers {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				s.Country, s.City, s.SOCKS5, s.IPv4, s.Provider, s.Multihop, s.Hostname)
		}
		w.Flush()

		fmt.Fprintf(os.Stderr, "\nTotal: %d servers\n", len(servers))
		return nil
	},
}

func init() {
	listCmd.Flags().Int("limit", 0, "Limit number of results")
	registerFilterFlags(listCmd)
	rootCmd.AddCommand(listCmd)
}
