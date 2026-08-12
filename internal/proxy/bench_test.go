package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

// BenchmarkParseProxyAuth measures auth string parsing throughput.
func BenchmarkParseProxyAuth(b *testing.B) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"seed_only", "seed=12345"},
		{"country_only", "country=se"},
		{"full_filter", "seed=42,country=se,city=stockholm,speed=1000,owned=true,multihop=1,provider=Mullvad"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = ParseProxyAuth(tc.input)
			}
		})
	}
}

// BenchmarkResolveSOCKS5 measures relay selection + health filter.
func BenchmarkResolveSOCKS5(b *testing.B) {
	if testing.Short() {
		b.Skip("needs relay list fetch")
	}
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := mullvad.New()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		b.Fatal(err)
	}
	h := New(logger, 30*time.Second, p, true, nil, mullvad.Filter{})
	r, _ := http.NewRequest("CONNECT", "example.com:443", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("seed=42")))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := h.resolveSOCKS5(ctx, r, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseProxyAuthHeader measures base64 decode + auth parse.
func BenchmarkParseProxyAuthHeader(b *testing.B) {
	header := "Basic c2VlZD00Mixjb3VudHJ5PXNlLGNpdHk9c3RvY2tob2xt"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseProxyAuthHeader(header)
	}
}
