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
	"strings"
	"testing"
	"time"

	"github.com/praktiskt/mulprox/internal/dashboard"
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/proxy"
	"github.com/praktiskt/mulprox/internal/socks5"
	"github.com/praktiskt/mulprox/internal/stats"
	xproxy "golang.org/x/net/proxy"
)

func TestSeedDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	p := mullvad.New()

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

	waitReady(t, listener.Addr().String())

	makeAuthHeader := func(connStr string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(connStr))
	}

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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		var result struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return result.IP
	}

	ip1 := fetchIP("123")
	ip2 := fetchIP("123")
	ip3 := fetchIP("123")

	if ip1 != ip2 || ip2 != ip3 {
		t.Errorf("seed 123 should return same IP, got: %s, %s, %s", ip1, ip2, ip3)
	} else {
		t.Logf("seed 123 consistently returns IP: %s", ip1)
	}

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

	waitReady(t, listener.Addr().String())

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

	req, err := http.NewRequestWithContext(ctx, "GET", "https://am.i.mullvad.net/json", nil)
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
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.IP == "" {
		t.Error("expected non-empty origin IP from HTTPS request")
	}
	t.Logf("HTTPS request succeeded, exit IP: %s", result.IP)
}

func TestStatsRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	p := mullvad.New()
	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("no mullvad servers found")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	statsStore := stats.NewInMemoryStore(logger)
	statsStore.Start()
	defer statsStore.Stop()

	h := proxy.New(logger, 30*time.Second, p, false, statsStore, mullvad.Filter{})
	dashboardHandler := dashboard.New(statsStore)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dashboard/stats":
			dashboardHandler.ServeHTTP(w, r)
		case r.URL.Path == "/dashboard/proxies":
			dashboardHandler.ServeHTTP(w, r)
		default:
			h.ServeHTTP(w, r)
		}
	})

	ts := &http.Server{
		Handler:           handler,
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

	waitReady(t, listener.Addr().String())

	makeAuthHeader := func(connStr string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(connStr))
	}

	makeProxyClient := func(seed string) *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse("http://" + listener.Addr().String())
				},
				ProxyConnectHeader: http.Header{
					"Proxy-Authorization": {makeAuthHeader("seed=" + seed)},
				},
			},
		}
	}

	fetchIP := func(seed string) string {
		client := makeProxyClient(seed)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		var result struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return result.IP
	}

	ips := make(map[string]bool)
	for _, seed := range []string{"1", "2", "3"} {
		ip := fetchIP(seed)
		if ip == "" {
			t.Fatalf("empty IP for seed %s", seed)
		}
		ips[ip] = true
		t.Logf("seed %s -> IP %s", seed, ip)
	}

	if len(ips) < 1 {
		t.Fatal("expected at least one IP")
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(statsStore.GetAllRemoteStats()) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	remotes := statsStore.GetAllRemoteStats()
	if len(remotes) == 0 {
		t.Fatal("expected at least one remote in stats")
	}
	t.Logf("found %d remotes in stats", len(remotes))

	var usedRemotes []*stats.RemoteStats
	for _, r := range remotes {
		reqCount := r.RequestCount.Load()
		if reqCount > 0 {
			usedRemotes = append(usedRemotes, r)
		}
	}

	if len(usedRemotes) == 0 {
		t.Fatal("expected at least one remote with request count > 0")
	}
	t.Logf("found %d used remotes (with requests)", len(usedRemotes))

	for _, r := range usedRemotes {
		reqCount := r.RequestCount.Load()
		t.Logf("remote %s: requests=%d, bytes_sent=%d, bytes_recv=%d, country=%s, city=%s",
			r.Hostname, reqCount, r.BytesSent.Load(), r.BytesRecv.Load(), r.Country, r.City)

		if reqCount == 0 {
			t.Errorf("remote %s has zero request count", r.Hostname)
		}
		if r.BytesRecv.Load() == 0 {
			t.Errorf("remote %s has zero bytes received", r.Hostname)
		}
		if r.Hostname == "" {
			t.Errorf("remote missing hostname")
		}
		if r.Country == "" {
			t.Errorf("remote %s missing country", r.Hostname)
		}
	}

	agg := statsStore.GetAggregatedStats()
	if agg.TotalRequests == 0 {
		t.Error("expected non-zero total requests in aggregated stats")
	}
	if agg.TotalBytesRecv == 0 {
		t.Error("expected non-zero total bytes received in aggregated stats")
	}
	t.Logf("aggregated: requests=%d, bytes_sent=%d, bytes_recv=%d, active_remotes=%d",
		agg.TotalRequests, agg.TotalBytesSent, agg.TotalBytesRecv, agg.ActiveRemotes)

	resp, err := makeProxyClient("1").Get("http://" + listener.Addr().String() + "/dashboard/stats")
	if err != nil {
		t.Fatalf("failed to fetch dashboard stats: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("dashboard stats endpoint returned %d", resp.StatusCode)
	}

	var dashAgg stats.AggregatedStats
	if err := json.NewDecoder(resp.Body).Decode(&dashAgg); err != nil {
		t.Fatalf("failed to decode dashboard stats: %v", err)
	}

	if dashAgg.TotalRequests == 0 {
		t.Error("dashboard stats shows zero total requests")
	}
	t.Logf("dashboard stats: total_requests=%d, total_bytes_recv=%d", dashAgg.TotalRequests, dashAgg.TotalBytesRecv)

	resp, err = http.Get("http://" + listener.Addr().String() + "/dashboard/proxies")
	if err != nil {
		t.Fatalf("failed to fetch dashboard proxies: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("dashboard proxies endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read dashboard proxies body: %v", err)
	}

	if !strings.Contains(string(body), "localhost") && !strings.Contains(string(body), "mullvad") {
		t.Logf("dashboard proxies response: %s", string(body)[:min(500, len(body))])
	}
}

func TestSOCKS5ServerDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	p := mullvad.New()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	statsStore := stats.NewInMemoryStore(logger)

	server := socks5.NewServer(logger, 30*time.Second, p, statsStore, mullvad.Filter{})
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("failed to start SOCKS5 server: %v", err)
	}
	defer server.Close()

	go func() {
		if err := server.Serve(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("SOCKS5 server error: %v", err)
		}
	}()

	waitSocksReady(t, server.Addr())

	dialer, err := xproxy.SOCKS5("tcp", server.Addr(), nil, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("failed to create SOCKS5 dialer: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("SOCKS5 direct request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.IP == "" {
		t.Fatal("expected non-empty origin IP")
	}
	t.Logf("SOCKS5 direct request succeeded, exit IP: %s", result.IP)
}

func TestMultiHopChaining(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	p := mullvad.New()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	statsStoreA := stats.NewInMemoryStore(logger)
	statsStoreA.Start()
	defer statsStoreA.Stop()
	statsStoreB := stats.NewInMemoryStore(logger)
	statsStoreB.Start()
	defer statsStoreB.Stop()

	serverB := socks5.NewServer(logger, 30*time.Second, p, statsStoreB, mullvad.Filter{})
	if err := serverB.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("failed to start SOCKS5 server B: %v", err)
	}
	defer serverB.Close()

	go func() {
		if err := serverB.Serve(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("SOCKS5 server B error: %v", err)
		}
	}()

	waitSocksReady(t, serverB.Addr())

	proxyA := proxy.NewWithUpstream(logger, 30*time.Second, p, false, statsStoreA, mullvad.Filter{}, "direct://"+serverB.Addr())

	ts := &http.Server{
		Handler:           proxyA,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener for A: %v", err)
	}
	defer listener.Close()

	go func() {
		if err := ts.Serve(listener); err != http.ErrServerClosed {
			t.Errorf("proxy server A error: %v", err)
		}
	}()
	defer ts.Close()

	waitReady(t, listener.Addr().String())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://" + listener.Addr().String())
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/json", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("multi-hop request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.IP == "" {
		t.Fatal("expected non-empty origin IP")
	}
	t.Logf("Multi-hop request succeeded, exit IP: %s", result.IP)

	foundA := false
	for _, r := range statsStoreA.GetAllRemoteStats() {
		if r.RequestCount.Load() > 0 {
			foundA = true
			t.Logf("proxy A recorded upstream: %s, requests=%d", r.RemoteID, r.RequestCount.Load())
			if r.RemoteID != serverB.Addr() {
				t.Errorf("expected A's remote ID to be B's address %s, got %s", serverB.Addr(), r.RemoteID)
			}
		}
	}
	if !foundA {
		t.Fatal("proxy A did not record any request stats")
	}

	foundB := false
	for _, r := range statsStoreB.GetAllRemoteStats() {
		if r.RequestCount.Load() > 0 {
			foundB = true
			t.Logf("proxy B recorded remote: %s, requests=%d, country=%s", r.RemoteID, r.RequestCount.Load(), r.Country)
			if r.RemoteID == serverB.Addr() || r.RemoteID == "" {
				t.Errorf("expected B's remote ID to be a Mullvad hostname, got %s", r.RemoteID)
			}
		}
	}
	if !foundB {
		t.Fatal("proxy B did not record any request stats")
	}
}
