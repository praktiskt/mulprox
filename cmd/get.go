package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/sardanioss/httpcloak/client"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <url>",
	Short: "Fetch a URL through Mullvad proxy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		url := args[0]
		outputPath, _ := cmd.Flags().GetString("output")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		start := time.Now()

		p := mullvad.New()

		server, err := p.GetFilteredServer(ctx, buildBaseFilter())
		if err != nil {
			return fmt.Errorf("failed to get server: %w", err)
		}

		socksAddr := fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort)
		c := client.NewSession("chrome-latest",
			client.WithTimeout(timeout),
			client.WithProxy("socks5://"+socksAddr),
		)
		defer c.Close()

		logger.Debug("fetching URL", slog.String("url", url), slog.String("method", "GET"))

		req := &client.Request{
			Method:  "GET",
			URL:     url,
			Headers: map[string][]string{"User-Agent": {"mulprox/1.0"}},
		}

		resp, err := c.Do(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to fetch: %w", err)
		}
		defer resp.Close()

		logger.Debug("fetch completed",
			slog.String("url", url),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)))

		body, err := resp.Bytes()
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}

		return writeOutput(outputPath, body)
	},
}

func writeOutput(path string, content []byte) error {
	if path == "-" || path == "" {
		os.Stdout.Write(content)
		return nil
	}
	return os.WriteFile(path, content, 0o644)
}

func init() {
	getCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	registerFilterFlags(getCmd)
	rootCmd.AddCommand(getCmd)
}
