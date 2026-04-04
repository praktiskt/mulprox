package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/praktiskt/mulprox/internal/dashboard"
	"github.com/praktiskt/mulprox/internal/health"
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/stats"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Mullvad HTTP proxy server",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := cmd.Flags().GetString("host")
		if err != nil {
			return fmt.Errorf("failed to get host flag: %w", err)
		}
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return fmt.Errorf("failed to get port flag: %w", err)
		}
		httpsOnly, err := cmd.Flags().GetBool("https-only")
		if err != nil {
			return fmt.Errorf("failed to get https-only flag: %w", err)
		}

		mullvadProvider := mullvad.New()
		statsStore := stats.NewInMemoryStore(logger)
		statsCollector := stats.NewCollector(logger, statsStore, mullvadProvider, stats.DefaultConfig())

		ctx, cancelStats := context.WithCancel(context.Background())
		statsCollector.Start(ctx)
		statsStore.Start()

		proxyHandler := proxy.New(logger, timeout, mullvadProvider, httpsOnly, statsStore, buildBaseFilter())
		dashboardHandler := dashboard.New(statsStore)
		healthHandler := health.New(statsStore)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("request", slog.String("method", r.Method), slog.String("url", r.URL.String()), slog.String("path", r.URL.Path))
			switch {
			case r.URL.Path == "/healthz":
				healthHandler.Livez(w, r)
			case r.URL.Path == "/readyz":
				healthHandler.Readyz(w, r)
			case strings.HasPrefix(r.URL.Path, "/dashboard"):
				dashboardHandler.ServeHTTP(w, r)
			default:
				proxyHandler.ServeHTTP(w, r)
			}
		})

		addr := fmt.Sprintf("%s:%d", host, port)
		logger.Info("proxy server listening", slog.String("addr", addr))

		s := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		go func() {
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
				logger.Error("server error", slog.String("error", err.Error()))
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		logger.Info("shutting down server")

		cancelStats()
		statsCollector.Stop()
		statsStore.Stop()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.Shutdown(shutdownCtx)
		cancel()

		return nil
	},
}

func init() {
	serveCmd.Flags().String("host", "0.0.0.0", "Host to bind to")
	serveCmd.Flags().IntP("port", "p", 8080, "Port to listen on")
	serveCmd.Flags().Bool("https-only", false, "Reject HTTP requests, only allow HTTPS")
	registerFilterFlags(serveCmd)
	rootCmd.AddCommand(serveCmd)
}
