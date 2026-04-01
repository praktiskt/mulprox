package cmd

import (
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func buildBaseFilter() mullvad.Filter {
	f := mullvad.Filter{
		Countries: viper.GetStringSlice("country"),
		Cities:    viper.GetStringSlice("city"),
		Providers: viper.GetStringSlice("provider"),
		MinSpeed:  viper.GetInt("speed"),
		Multihop:  viper.GetBool("multihop"),
	}
	if viper.IsSet("owned") {
		owned := viper.GetBool("owned")
		f.Owned = &owned
	}
	return f
}

func registerFilterFlags(cmd *cobra.Command) {
	cmd.Flags().StringSlice("country", nil, "Filter by country (comma-separated or repeated)")
	cmd.Flags().StringSlice("city", nil, "Filter by city (comma-separated or repeated)")
	cmd.Flags().StringSlice("provider", nil, "Filter by provider (comma-separated or repeated)")
	cmd.Flags().Int("speed", 0, "Minimum server speed in Mbps")
	cmd.Flags().Bool("owned", false, "Only Mullvad-owned servers")
	cmd.Flags().Bool("multihop", false, "Require multihop support")
}
