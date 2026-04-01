package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/praktiskt/mulprox/internal/dashboard"
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/stats"
	"github.com/praktiskt/mulprox/internal/util"

	"github.com/spf13/cobra"
)

var stressCmd = &cobra.Command{
	Use:   "stress",
	Short: "Run a stress test against the proxy server",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, err := cmd.Flags().GetString("host")
		if err != nil {
			return fmt.Errorf("failed to get host flag: %w", err)
		}
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return fmt.Errorf("failed to get port flag: %w", err)
		}
		target, err := cmd.Flags().GetString("target")
		if err != nil {
			return fmt.Errorf("failed to get target flag: %w", err)
		}
		rate, err := cmd.Flags().GetInt("rate")
		if err != nil {
			return fmt.Errorf("failed to get rate flag: %w", err)
		}
		duration, err := cmd.Flags().GetDuration("duration")
		if err != nil {
			return fmt.Errorf("failed to get duration flag: %w", err)
		}
		concurrency, err := cmd.Flags().GetInt("concurrency")
		if err != nil {
			return fmt.Errorf("failed to get concurrency flag: %w", err)
		}

		mullvadProvider := mullvad.New()
		statsStore := stats.NewInMemoryStore()
		statsCollector := stats.NewCollector(logger, statsStore, mullvadProvider, stats.DefaultConfig())

		ctx, cancelStats := context.WithCancel(context.Background())
		statsCollector.Start(ctx)
		statsStore.Start()

		proxyHandler := proxy.New(logger, timeout, mullvadProvider, false, statsStore, mullvad.Filter{})
		dashboardHandler := dashboard.New(statsStore)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/dashboard") {
				dashboardHandler.ServeHTTP(w, r)
			} else {
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

		time.Sleep(500 * time.Millisecond)

		logger.Info("starting stress test",
			slog.String("target", target),
			slog.Int("concurrency", concurrency),
			slog.Duration("duration", duration))

		proxyURL := url.URL{
			Scheme: "http",
			Host:   addr,
		}

		delayPerReq := time.Duration(int64(time.Second) / int64(rate))

		httpClient := &http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyURL(&proxyURL),
				MaxIdleConns:        concurrency,
				MaxIdleConnsPerHost: concurrency,
				IdleConnTimeout:     30 * time.Second,
			},
			Timeout: 30 * time.Second,
		}

		var totalRequests int64
		var totalErrors int64
		var totalBytes int64
		var totalLatencyUs int64
		var minLatency int64 = 1<<62 - 1
		var maxLatency int64

		var wg sync.WaitGroup

		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		startTime := time.Now()
		lastRequests := int64(0)

		go func() {
			for {
				select {
				case <-ticker.C:
					current := atomic.LoadInt64(&totalRequests)
					elapsed := time.Since(startTime).Seconds()
					rps := float64(current-lastRequests) / 1.0
					errors := atomic.LoadInt64(&totalErrors)
					fmt.Printf("\r[%d] req/s: %.1f, errors: %d, total: %d",
						int(elapsed), rps, errors, current)
					lastRequests = current
				case <-ctx.Done():
					return
				}
			}
		}()

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					default:
						if rate > 0 {
							time.Sleep(delayPerReq / time.Duration(concurrency))
						}
						reqStart := time.Now()
						resp, err := httpClient.Get(target)
						if err != nil {
							atomic.AddInt64(&totalErrors, 1)
							continue
						}
						n, _ := io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						latency := time.Since(reqStart).Microseconds()

						atomic.AddInt64(&totalRequests, 1)
						atomic.AddInt64(&totalBytes, n)
						atomic.AddInt64(&totalLatencyUs, latency)

						oldMin := atomic.LoadInt64(&minLatency)
						for latency < oldMin {
							if atomic.CompareAndSwapInt64(&minLatency, oldMin, latency) {
								break
							}
							oldMin = atomic.LoadInt64(&minLatency)
						}

						oldMax := atomic.LoadInt64(&maxLatency)
						for latency > oldMax {
							if atomic.CompareAndSwapInt64(&maxLatency, oldMax, latency) {
								break
							}
							oldMax = atomic.LoadInt64(&maxLatency)
						}
					}
				}
			}()
		}

		<-ctx.Done()

		wg.Wait()

		elapsed := time.Since(startTime)
		finalRequests := atomic.LoadInt64(&totalRequests)
		finalErrors := atomic.LoadInt64(&totalErrors)
		finalBytes := atomic.LoadInt64(&totalBytes)
		avgLatencyUs := atomic.LoadInt64(&totalLatencyUs)
		minLat := atomic.LoadInt64(&minLatency)
		maxLat := atomic.LoadInt64(&maxLatency)

		fmt.Printf("\n\n=== Stress Test Results ===\n")
		fmt.Printf("Duration:      %v\n", elapsed.Round(time.Millisecond))
		fmt.Printf("Target:        %s\n", target)
		fmt.Printf("Total Requests: %d\n", finalRequests)
		fmt.Printf("Requests/sec:   %.1f\n", float64(finalRequests)/elapsed.Seconds())
		fmt.Printf("Errors:        %d\n", finalErrors)
		fmt.Printf("Bytes recv:    %s\n", formatBytes(finalBytes))
		if finalRequests > 0 {
			fmt.Printf("Avg latency:   %v\n", time.Duration(avgLatencyUs/finalRequests)*time.Microsecond)
			fmt.Printf("Min latency:   %v\n", time.Duration(minLat)*time.Microsecond)
			fmt.Printf("Max latency:   %v\n", time.Duration(maxLat)*time.Microsecond)
		}
		fmt.Printf("\nDashboard available at: http://%s/dashboard\n", addr)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		logger.Info("shutting down server")

		cancelStats()
		statsCollector.Stop()
		statsStore.Stop()

		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		s.Shutdown(shutdownCtx)
		cancelShutdown()

		return nil
	},
}

func formatBytes(n int64) string {
	return util.FormatBytes(n)
}

func init() {
	stressCmd.Flags().String("host", "0.0.0.0", "Host to bind to")
	stressCmd.Flags().IntP("port", "p", 8080, "Port to listen on")
	stressCmd.Flags().String("target", "https://example.com", "Target URL to request (use http:// for accurate stats)")
	stressCmd.Flags().Int("rate", 1000, "Target requests per second (approximate)")
	stressCmd.Flags().Duration("duration", 30*time.Second, "Test duration")
	stressCmd.Flags().Int("concurrency", 50, "Number of parallel workers")
	rootCmd.AddCommand(stressCmd)
}
