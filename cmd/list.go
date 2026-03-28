package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/praktiskt/mulprox/internal/mullvad"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available Mullvad servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		country, err := cmd.Flags().GetString("country")
		if err != nil {
			return fmt.Errorf("failed to get country flag: %w", err)
		}
		city, err := cmd.Flags().GetString("city")
		if err != nil {
			return fmt.Errorf("failed to get city flag: %w", err)
		}
		limit, err := cmd.Flags().GetInt("limit")
		if err != nil {
			return fmt.Errorf("failed to get limit flag: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		p := mullvad.New()
		servers, err := p.FetchMullvadList(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch server list: %w", err)
		}

		if country != "" {
			servers = p.GetServersByCountry(country)
		}
		if city != "" {
			servers = p.GetServersByCity(city)
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
	listCmd.Flags().String("country", "", "Filter by country")
	listCmd.Flags().String("city", "", "Filter by city")
	listCmd.Flags().Int("limit", 0, "Limit number of results")
	rootCmd.AddCommand(listCmd)
}
