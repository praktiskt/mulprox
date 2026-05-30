package e2e

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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

func requireNetworkB(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping network benchmark in short mode")
	}
}

func waitReady(tb testing.TB, addr string) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tb.Fatalf("proxy not ready after 5s: %s", addr)
}

func waitSocksReady(tb testing.TB, addr string) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tb.Fatalf("SOCKS5 server not ready after 5s: %s", addr)
}

// startBenchProxy starts HTTP proxy on random port. Returns addr and close func.
func startBenchProxy(b *testing.B, httpsOnly bool, extraFilter mullvad.Filter) (addr string, close func()) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := mullvad.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		b.Fatalf("fetch relay list: %v", err)
	}

	st := stats.NewInMemoryStore(logger)
	st.Start()
	h := proxy.New(logger, 30*time.Second, p, httpsOnly, st, extraFilter)

	ts := &http.Server{
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	go func() {
		if err := ts.Serve(listener); err != nil && err != http.ErrServerClosed {
			b.Logf("proxy serve: %v", err)
		}
	}()
	waitReady(b, listener.Addr().String())
	return listener.Addr().String(), func() {
		ts.Close()
		listener.Close()
		st.Stop()
	}
}

// BenchmarkEndToEndCONNECT measures full proxy CONNECT flow: DNS + SOCKS5 + TLS + HTTP.
func BenchmarkEndToEndCONNECT(b *testing.B) {
	requireNetworkB(b)

	addr, closer := startBenchProxy(b, true, mullvad.Filter{Seed: 12345})
	defer closer()

	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		b.Fatal(err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		ProxyConnectHeader: http.Header{
			"Proxy-Authorization": {makeAuthHeaderB("seed=42")},
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get("https://am.i.mullvad.net/json")
		if err != nil {
			b.Fatalf("GET: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func makeAuthHeaderB(connStr string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(connStr))
}
