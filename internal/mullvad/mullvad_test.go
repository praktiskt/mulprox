package mullvad

import (
	"context"
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
		s1, err := p.GetFilteredServer(Filter{Seed: 12345})
		if err != nil {
			t.Fatalf("failed to get server by seed: %v", err)
		}

		s2, err := p.GetFilteredServer(Filter{Seed: 12345})
		if err != nil {
			t.Fatalf("failed to get server by seed: %v", err)
		}

		if s1.SOCKS5 != s2.SOCKS5 || s1.SOCKSPort != s2.SOCKSPort {
			t.Error("same seed should return same server")
		}
		t.Logf("seed 12345 -> %s:%d", s1.SOCKS5, s1.SOCKSPort)
	})

	t.Run("country filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(Filter{Country: "Sweden"})
		if err != nil {
			t.Fatalf("failed to get server by country: %v", err)
		}
		if s.Country != "Sweden" {
			t.Errorf("expected Sweden, got %s", s.Country)
		}
		t.Logf("Sweden -> %s", s.City)
	})

	t.Run("country+seed filter", func(t *testing.T) {
		s1, err := p.GetFilteredServer(Filter{Country: "Sweden", Seed: 42})
		if err != nil {
			t.Fatalf("failed to get server: %v", err)
		}
		s2, err := p.GetFilteredServer(Filter{Country: "Sweden", Seed: 42})
		if err != nil {
			t.Fatalf("failed to get server: %v", err)
		}
		if s1.SOCKS5 != s2.SOCKS5 {
			t.Error("same country+seed should return same server")
		}
		t.Logf("Sweden+seed42 -> %s", s1.City)
	})

	t.Run("city filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(Filter{City: "Stockholm"})
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
		s, err := p.GetFilteredServer(Filter{Owned: &owned})
		if err != nil {
			t.Fatalf("failed to get owned server: %v", err)
		}
		if !s.Owned {
			t.Error("expected owned server")
		}
		t.Logf("owned -> %s (%s)", s.Country, s.Provider)
	})

	t.Run("min speed filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(Filter{MinSpeed: 100})
		if err != nil {
			t.Fatalf("failed to get server by speed: %v", err)
		}
		if s.Speed < 100 {
			t.Errorf("expected speed >= 100, got %d", s.Speed)
		}
		t.Logf("min speed 100 -> %d Mbps", s.Speed)
	})

	t.Run("multihop filter", func(t *testing.T) {
		s, err := p.GetFilteredServer(Filter{Multihop: true})
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
		s, err := p.GetFilteredServer(Filter{
			Country:  "Sweden",
			Owned:    &owned,
			MinSpeed: 100,
			Seed:     99,
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
