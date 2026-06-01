package mullvad

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func requireNetworkB(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping network benchmark in short mode")
	}
}

// BenchmarkResolveRelayAddr measures DNS resolution latency across 3 relays.
func BenchmarkResolveRelayAddr(b *testing.B) {
	requireNetworkB(b)
	p := New()
	ctx := context.Background()

	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		b.Fatal(err)
	}
	indices := []int{0, len(servers) / 2, len(servers) - 1}
	for _, idx := range indices {
		relay := servers[idx]
		addr := relay.SOCKS5 + ":" + strconv.Itoa(relay.SOCKSPort)
		b.Run(relay.Hostname, func(b *testing.B) {
			_, err := p.ResolveRelayAddr(ctx, addr)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = p.ResolveRelayAddr(ctx, addr)
			}
		})
	}
}

// BenchmarkSOCKS5Dial measures SOCKS5 dial latency: TCP + auth + CONNECT.
func BenchmarkSOCKS5Dial(b *testing.B) {
	requireNetworkB(b)
	p := New()
	ctx := context.Background()

	servers, err := p.FetchMullvadList(ctx)
	if err != nil {
		b.Fatal(err)
	}
	ownedTrue := true
	relays := p.filterByFilter(servers, Filter{Owned: &ownedTrue})
	if len(relays) == 0 {
		relays = servers
	}
	var relay Server
	for _, r := range relays {
		if r.SOCKS5 != "" && r.SOCKSPort > 0 {
			relay = r
			break
		}
	}
	if relay.SOCKS5 == "" {
		b.Fatal("no relay with SOCKS5")
	}
	relayAddr := net.JoinHostPort(relay.SOCKS5, strconv.Itoa(relay.SOCKSPort))

	resolved, err := p.ResolveRelayAddr(ctx, relayAddr)
	if err != nil {
		b.Fatal(err)
	}

	const target = "am.i.mullvad.net:443"
	timeout := 10 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dialer, err := p.SOCKS5DialerFromResolved(ctx, resolved, timeout)
		if err != nil {
			b.Fatal(err)
		}
		conn, err := dialer.Dial("tcp", target)
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}
