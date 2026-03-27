package proxy

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

func TestProxyAuthJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ProxyAuth
	}{
		{
			name:     "seed only",
			input:    `{"seed": 123}`,
			expected: ProxyAuth{Seed: 123},
		},
		{
			name:     "country only",
			input:    `{"country": "Sweden"}`,
			expected: ProxyAuth{Country: "Sweden"},
		},
		{
			name:  "all fields",
			input: `{"seed": 42, "country": "Norway", "city": "Oslo", "speed": 1000, "multihop": true}`,
			expected: ProxyAuth{
				Seed:     42,
				Country:  "Norway",
				City:     "Oslo",
				MinSpeed: 1000,
				Multihop: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var auth ProxyAuth
			if err := json.Unmarshal([]byte(tt.input), &auth); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if auth != tt.expected {
				t.Errorf("expected %+v, got %+v", tt.expected, auth)
			}
		})
	}
}

func TestProxyAuthApply(t *testing.T) {
	owned := true
	auth := ProxyAuth{
		Seed:     123,
		Country:  "Sweden",
		City:     "Stockholm",
		Owned:    &owned,
		Provider: "Mullvad",
		MinSpeed: 100,
		Multihop: true,
	}

	filter := mullvad.Filter{}
	auth.Apply(&filter)

	if filter.Seed != 123 {
		t.Errorf("expected seed 123, got %d", filter.Seed)
	}
	if filter.Country != "Sweden" {
		t.Errorf("expected country Sweden, got %s", filter.Country)
	}
	if filter.City != "Stockholm" {
		t.Errorf("expected city Stockholm, got %s", filter.City)
	}
	if filter.Owned == nil || *filter.Owned != true {
		t.Error("expected owned to be true")
	}
	if filter.Provider != "Mullvad" {
		t.Errorf("expected provider Mullvad, got %s", filter.Provider)
	}
	if filter.MinSpeed != 100 {
		t.Errorf("expected min speed 100, got %d", filter.MinSpeed)
	}
	if !filter.Multihop {
		t.Error("expected multihop to be true")
	}
}

func TestGetSOCKS5AddrFromRequest(t *testing.T) {
	t.Skip("requires network access to fetch Mullvad server list")
	h := &Handler{}

	tests := []struct {
		name      string
		authJSON  string
		expectErr bool
	}{
		{
			name:     "seed",
			authJSON: `{"seed": 123}`,
		},
		{
			name:     "country",
			authJSON: `{"country": "Sweden"}`,
		},
		{
			name:     "combined",
			authJSON: `{"seed": 42, "country": "Sweden"}`,
		},
		{
			name:      "invalid JSON",
			authJSON:  `{invalid}`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{
					"Proxy-Authorization": {tt.authJSON},
				},
			}

			addr, err := h.getSOCKS5AddrFromRequest(req)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if addr == "" {
				t.Error("expected non-empty address")
			}

			t.Logf("selected server: %s", addr)
		})
	}
}
