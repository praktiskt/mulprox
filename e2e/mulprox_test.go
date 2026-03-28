package e2e

import (
	"context"
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
)

func TestMullvadProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p := mullvad.New()

	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	if len(servers) == 0 {
		t.Fatal("no mullvad servers found")
	}

	t.Logf("found %d mullvad servers", len(servers))

	first := servers[0]
	t.Logf("first server: country=%s, city=%s, socks5=%s, ipv4=%s, provider=%s, hostname=%s, owned=%v, multihop=%d",
		first.Country, first.City, first.SOCKS5, first.IPv4, first.Provider, first.Hostname, first.Owned, first.Multihop)

	if first.Country == "" {
		t.Error("expected non-empty country")
	}
	if first.City == "" {
		t.Error("expected non-empty city")
	}
	if first.SOCKS5 == "" {
		t.Error("expected non-empty socks5")
	}
	if first.IPv4 == "" {
		t.Error("expected non-empty ipv4")
	}
	if first.Hostname == "" {
		t.Error("expected non-empty hostname")
	}

	usServers := p.GetServersByCountry("USA")
	t.Logf("found %d US servers", len(usServers))

	if len(usServers) > 0 {
		t.Logf("first US server: %s %s", usServers[0].City, usServers[0].Hostname)
	}

	owned := p.GetOwnedServers()
	t.Logf("found %d owned servers", len(owned))

	multihop := p.GetMultihopServers()
	t.Logf("found %d multihop servers", len(multihop))
}

func TestMullvadSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://am.i.mullvad.net/json", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var status struct {
		IP            string `json:"ip"`
		MullvadExitIP bool   `json:"mullvad_exit_ip"`
	}

	if err := resp.JSON(&status); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if !status.MullvadExitIP {
		t.Fatalf("expected mullvad exit IP, got %s", status.IP)
	}

	t.Logf("connected via IP: %s (mullvad: %v)", status.IP, status.MullvadExitIP)
}

func TestIPRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	p := mullvad.New()

	var IPs []string
	for i := 0; i < 5; i++ {
		client, err := p.Session(ctx, 30*time.Second)
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i+1, err)
		}

		resp, err := client.Get(ctx, "https://am.i.mullvad.net/json", nil)
		if err != nil {
			t.Fatalf("failed to fetch %d: %v", i+1, err)
		}

		var status struct {
			IP            string `json:"ip"`
			MullvadExitIP bool   `json:"mullvad_exit_ip"`
		}
		if err := resp.JSON(&status); err != nil {
			resp.Close()
			t.Fatalf("failed to parse JSON %d: %v", i+1, err)
		}
		resp.Close()
		client.Close()

		if !status.MullvadExitIP {
			t.Fatalf("expected mullvad exit IP on request %d, got %s", i+1, status.IP)
		}

		IPs = append(IPs, status.IP)
		t.Logf("request %d: IP=%s", i+1, status.IP)

		time.Sleep(500 * time.Millisecond)
	}

	uniqueIPs := make(map[string]bool)
	for _, ip := range IPs {
		uniqueIPs[ip] = true
	}

	if len(uniqueIPs) <= 1 {
		t.Logf("WARNING: IP rotation may not be working - got same IP %d times: %v", len(IPs), IPs)
	} else {
		t.Logf("IP rotation working - %d unique IPs out of 5 requests", len(uniqueIPs))
	}
}

func TestProxyThroughHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := resp.Bytes()
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}

	t.Logf("fetched %d bytes from example.com", len(body))
}

func TestJsonResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

	client, err := p.Session(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer client.Close()

	resp, err := client.Get(ctx, "https://httpbin.org/json", nil)
	if err != nil {
		t.Fatalf("failed to fetch: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data json.RawMessage
	if err := resp.JSON(&data); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty JSON response")
	}

	t.Logf("received JSON: %s", string(data))
}

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
	h := proxy.New(logger, 30*time.Second, p, false)

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

	// Helper to fetch exit IP via httpbin with Proxy-Authorization header
	fetchIP := func(seed string) string {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse("http://" + listener.Addr().String())
				},
				ProxyConnectHeader: http.Header{
					"Proxy-Authorization": {`{"seed":` + seed + `}`},
				},
			},
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/ip", nil)
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
	h := proxy.New(logger, 30*time.Second, p, true)

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
				"Proxy-Authorization": {`{"seed":1}`},
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
