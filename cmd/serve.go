package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/praktiskt/mulprox/internal/dashboard"
	"github.com/praktiskt/mulprox/internal/health"
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/socks5"
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
		socks5Port, err := cmd.Flags().GetInt("socks5-port")
		if err != nil {
			return fmt.Errorf("failed to get socks5-port flag: %w", err)
		}
		upstreamSOCKS5, err := cmd.Flags().GetString("upstream-socks5")
		if err != nil {
			return fmt.Errorf("failed to get upstream-socks5 flag: %w", err)
		}
		if upstreamSOCKS5 == "" {
			upstreamSOCKS5 = os.Getenv("SOCKS5_PROXY")
		}

		dnsAddr, _ := cmd.Flags().GetString("dns")
		mullvadProvider := mullvad.NewWithDNS(dnsAddr)
		statsStore := stats.NewInMemoryStore(logger)
		cfg := stats.DefaultConfig()
		if v := os.Getenv("FAST_HEALTH_CHECK"); v != "" {
			b, err := strconv.ParseBool(v)
			if err == nil {
				cfg.FastHealthCheck = b
			}
		}
		statsCollector := stats.NewCollector(logger, statsStore, mullvadProvider, cfg)

		ctx, cancelStats := context.WithCancel(context.Background())
		defer cancelStats()
		statsStore.Start()
	mullvadProvider.Start(ctx, logger)

		var proxyHandler *proxy.Handler
		if upstreamSOCKS5 != "" {
			proxyHandler = proxy.NewWithUpstream(logger, timeout, mullvadProvider, httpsOnly, statsStore, buildBaseFilter(), upstreamSOCKS5)
		} else {
			proxyHandler = proxy.New(logger, timeout, mullvadProvider, httpsOnly, statsStore, buildBaseFilter())
		}

		if socks5Port > 0 {
			socks5Server := socks5.NewServer(logger, timeout, mullvadProvider, statsStore, buildBaseFilter())
			socks5Addr := fmt.Sprintf("%s:%d", host, socks5Port)
			if err := socks5Server.Listen(socks5Addr); err != nil {
				return fmt.Errorf("failed to start SOCKS5 server: %w", err)
			}
			logger.Info("SOCKS5 server listening", slog.String("addr", socks5Server.Addr()))
			go func() {
				if err := socks5Server.Serve(); err != nil {
					logger.Error("SOCKS5 server error", slog.String("error", err.Error()))
				}
			}()
		}
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

		if cfg.FastHealthCheck {
			logger.Info("running fast health check for startup")
			go func() {
				server, err := statsCollector.CheckHealthOne(ctx)
				if err != nil {
					logger.Warn("fast health check failed", slog.String("error", err.Error()))
				} else {
					logger.Info("fast health check found online server", slog.String("hostname", server.Hostname))
				}
			}()
		}

		statsCollector.Start(ctx)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		logger.Info("shutting down server")

		statsCollector.Stop()
		statsStore.Stop()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", slog.String("error", err.Error()))
		}

		return nil
	},
}

func init() {
	serveCmd.Flags().String("host", "0.0.0.0", "Host to bind to")
	serveCmd.Flags().IntP("port", "p", 8080, "Port to listen on")
	serveCmd.Flags().Bool("https-only", false, "Reject HTTP requests, only allow HTTPS")
	serveCmd.Flags().Int("socks5-port", 0, "SOCKS5 server port (0 = disabled)")
	serveCmd.Flags().String("upstream-socks5", "", "Upstream SOCKS5 proxy address for chaining (also SOCKS5_PROXY env)")
	serveCmd.Flags().String("dns", "", "DNS server for Mullvad relay resolution (default: 194.242.2.2:853, Mullvad DoT)")
	registerFilterFlags(serveCmd)
	rootCmd.AddCommand(serveCmd)
}
