package mullvad

import (
	"context"
	"log/slog"
	"strconv"
	"testing"
	"time"
)

func TestGetFilteredServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p := New()

	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatalf("failed to fetch mullvad list: %v", err)
	}

	t.Run("seed selection", func(t *testing.T) {
		s1, err := p.GetFilteredServer(ctx, Filter{Seed: 12345})
		if err != nil {
			t.Fatalf("failed to get server by seed: %v", err)
		}

		s2, err := p.GetFilteredServer(ctx, Filter{Seed: 12345})
		if err != nil {
			t.Fatalf("failed to get server by seed: %v", err)
		}

		if s1.SOCKS5 != s2.SOCKS5 || s1.SOCKSPort != s2.SOCKSPort {
			t.Error("same seed should return same server")
		}
		t.Logf("seed 12345 -> %s:%d", s1.SOCKS5, s1.SOCKSPort)
	})

	t.Run("country filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(ctx, Filter{Countries: []string{"Sweden"}})
		if err != nil {
			t.Fatalf("failed to get server by country: %v", err)
		}
		if s.Country != "Sweden" {
			t.Errorf("expected Sweden, got %s", s.Country)
		}
		t.Logf("Sweden -> %s", s.City)
	})

	t.Run("country+seed filter", func(t *testing.T) {
		s1, err := p.GetFilteredServer(ctx, Filter{Countries: []string{"Sweden"}, Seed: 42})
		if err != nil {
			t.Fatalf("failed to get server: %v", err)
		}
		s2, err := p.GetFilteredServer(ctx, Filter{Countries: []string{"Sweden"}, Seed: 42})
		if err != nil {
			t.Fatalf("failed to get server: %v", err)
		}
		if s1.SOCKS5 != s2.SOCKS5 {
			t.Error("same country+seed should return same server")
		}
		t.Logf("Sweden+seed42 -> %s", s1.City)
	})

	t.Run("city filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(ctx, Filter{Cities: []string{"Stockholm"}})
		if err != nil {
			t.Fatalf("failed to get server by city: %v", err)
		}
		if s.City != "Stockholm" {
			t.Errorf("expected Stockholm, got %s", s.City)
		}
		t.Logf("Stockholm -> %s", s.Country)
	})

	t.Run("owned filter", func(t *testing.T) {
		owned := true
		s, err := p.GetFilteredServer(ctx, Filter{Owned: &owned})
		if err != nil {
			t.Fatalf("failed to get owned server: %v", err)
		}
		if !s.Owned {
			t.Error("expected owned server")
		}
		t.Logf("owned -> %s (%s)", s.Country, s.Provider)
	})

	t.Run("min speed filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(ctx, Filter{MinSpeed: 100})
		if err != nil {
			t.Fatalf("failed to get server by speed: %v", err)
		}
		if s.Speed < 100 {
			t.Errorf("expected speed >= 100, got %d", s.Speed)
		}
		t.Logf("min speed 100 -> %d Mbps", s.Speed)
	})

	t.Run("multihop filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(ctx, Filter{Multihop: true})
		if err != nil {
			t.Fatalf("failed to get multihop server: %v", err)
		}
		if s.Multihop == 0 {
			t.Error("expected multihop server")
		}
		t.Logf("multihop -> port %d", s.Multihop)
	})

	t.Run("combined filters", func(t *testing.T) {
		owned := true
		s, err := p.GetFilteredServer(ctx, Filter{
			Countries: []string{"Sweden"},
			Owned:     &owned,
			MinSpeed:  100,
			Seed:      99,
		})
		if err != nil {
			t.Fatalf("failed to get server with combined filters: %v", err)
		}
		if s.Country != "Sweden" {
			t.Errorf("expected Sweden, got %s", s.Country)
		}
		if !s.Owned {
			t.Error("expected owned server")
		}
		t.Logf("combined -> %s (%s, %d Mbps)", s.City, s.Provider, s.Speed)
	})
}

func TestConnPool(t *testing.T) {
	logger := slog.Default()
	p := New()
	ctx := context.Background()
	_, err := p.FetchMullvadList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Start(ctx, logger)
	defer p.Stop()

	relay := p.mullvadList[0]
	relayAddr := relay.SOCKS5 + ":" + strconv.Itoa(relay.SOCKSPort)
	resolved, err := p.ResolveRelayAddr(ctx, relayAddr)
	if err != nil {
		t.Fatal(err)
	}

	const target = "am.i.mullvad.net:443"
	timeout := 10 * time.Second

	// Call 1: pool empty, fallback path.
	t1 := time.Now()
	d1, err := p.SOCKS5DialerFromResolved(ctx, resolved, timeout)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := d1.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	lat1 := time.Since(t1)

	// Wait for replenish goroutine to fill pool.
	time.Sleep(2 * time.Second)

	// Call 2: pool hit.
	t2 := time.Now()
	d2, err := p.SOCKS5DialerFromResolved(ctx, resolved, timeout)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := d2.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	lat2 := time.Since(t2)

	t.Logf("call 1 (cold): %v", lat1.Round(time.Millisecond))
	t.Logf("call 2 (warm): %v", lat2.Round(time.Millisecond))
	if lat2 >= lat1 {
		t.Errorf("warm call slower than cold: %v >= %v", lat2, lat1)
	}
}
