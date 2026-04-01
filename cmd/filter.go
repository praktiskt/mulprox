package cmd

import (
	"strings"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func buildBaseFilter() mullvad.Filter {
	f := mullvad.Filter{
		Countries: stringSliceFromViper("country"),
		Cities:    stringSliceFromViper("city"),
		Providers: stringSliceFromViper("provider"),
		MinSpeed:  viper.GetInt("speed"),
		Multihop:  viper.GetBool("multihop"),
	}
	if viper.IsSet("owned") {
		owned := viper.GetBool("owned")
		f.Owned = &owned
	}
	return f
}

func stringSliceFromViper(key string) []string {
	raw := viper.GetStringSlice(key)
	if len(raw) == 1 && strings.Contains(raw[0], ",") {
		return strings.Split(raw[0], ",")
	}
	return raw
}

func registerFilterFlags(cmd *cobra.Command) {
	cmd.Flags().StringSlice("country", nil, "Filter by country (comma-separated or repeated)")
	cmd.Flags().StringSlice("city", nil, "Filter by city (comma-separated or repeated)")
	cmd.Flags().StringSlice("provider", nil, "Filter by provider (comma-separated or repeated)")
	cmd.Flags().Int("speed", 0, "Minimum server speed in Mbps")
	cmd.Flags().Bool("owned", false, "Only Mullvad-owned servers")
	cmd.Flags().Bool("multihop", false, "Require multihop support")
}
