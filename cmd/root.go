package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	timeout      time.Duration
	checkMullvad bool
	debug        bool
	configFile   string
	logger       *slog.Logger
)

var rootCmd = &cobra.Command{
	Use:   "mulprox",
	Short: "Mullvad proxy service - route HTTP requests through random Mullvad IPs",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 5*time.Second, "Request timeout")
	rootCmd.PersistentFlags().BoolVar(&checkMullvad, "check-mullvad", false, "Check local Mullvad status and exit")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file path (default: mulprox.yaml in current directory)")

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if checkMullvad {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			p := mullvad.New()
			isMullvad, err := p.CheckMullvadStatus(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking status: %v\n", err)
				os.Exit(1)
			}
			if isMullvad {
				fmt.Println("You are on Mullvad VPN")
				os.Exit(0)
			}
			fmt.Println("You are NOT on Mullvad VPN")
			os.Exit(0)
			return nil
		}

		level := slog.LevelInfo
		if debug {
			level = slog.LevelDebug
		}
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		}))

		viper.AutomaticEnv()
		if configFile != "" {
			viper.SetConfigFile(configFile)
		} else {
			viper.SetConfigName("mulprox")
			viper.SetConfigType("yaml")
			viper.AddConfigPath(".")
		}
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return fmt.Errorf("failed to read config: %w", err)
			}
		}
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("failed to bind flags: %w", err)
		}

		return nil
	}
}
