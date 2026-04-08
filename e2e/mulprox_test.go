package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/stats"
)

func TestSeedDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	// Fetch server list to verify provider is working
	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("no mullvad servers found")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	statsStore := stats.NewInMemoryStore(logger)
	h := proxy.New(logger, 30*time.Second, p, false, statsStore, mullvad.Filter{})

	// Create test server
	ts := &http.Server{
		Handler:           h,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		if err := ts.Serve(listener); err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()
	defer ts.Close()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Helper to create Basic auth header for connection string
	makeAuthHeader := func(connStr string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(connStr))
	}

	// Helper to fetch exit IP via httpbin with Proxy-Authorization header
	fetchIP := func(seed string) string {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse("http://" + listener.Addr().String())
				},
				ProxyConnectHeader: http.Header{
					"Proxy-Authorization": {makeAuthHeader("seed=" + seed)},
				},
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/ip", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		var result struct {
			Origin string `json:"origin"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return result.Origin
	}

	// Test same seed returns same IP
	ip1 := fetchIP("123")
	ip2 := fetchIP("123")
	ip3 := fetchIP("123")

	if ip1 != ip2 || ip2 != ip3 {
		t.Errorf("seed 123 should return same IP, got: %s, %s, %s", ip1, ip2, ip3)
	} else {
		t.Logf("seed 123 consistently returns IP: %s", ip1)
	}

	// Test different seed returns different IP
	ip4 := fetchIP("456")
	if ip4 == ip1 {
		t.Errorf("seed 456 should return different IP than seed 123, both got: %s", ip1)
	} else {
		t.Logf("seed 456 returns different IP: %s", ip4)
	}
}

func TestHTTPSOnlyMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	p := mullvad.New()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	statsStore := stats.NewInMemoryStore(logger)
	h := proxy.New(logger, 30*time.Second, p, true, statsStore, mullvad.Filter{})

	ts := &http.Server{
		Handler:           h,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		if err := ts.Serve(listener); err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()
	defer ts.Close()

	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://" + listener.Addr().String())
			},
		},
	}

	resp, err := client.Get("http://example.com")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for HTTP request in https-only mode, got %d", resp.StatusCode)
	}

	httpsClient := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://" + listener.Addr().String())
			},
			ProxyConnectHeader: http.Header{
				"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("seed=1"))},
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/ip", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err = httpsClient.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for HTTPS request, got %d", resp.StatusCode)
	}

	var result struct {
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Origin == "" {
		t.Error("expected non-empty origin IP from HTTPS request")
	}
	t.Logf("HTTPS request succeeded, exit IP: %s", result.Origin)
}
