package proxy

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/praktiskt/mulprox/internal/mullvad"
)

func TestParseProxyAuth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ProxyAuth
	}{
		{
			name:     "empty string",
			input:    "",
			expected: ProxyAuth{},
		},
		{
			name:     "seed only",
			input:    "seed=123",
			expected: ProxyAuth{Seed: 123},
		},
		{
			name:     "country only",
			input:    "country=Sweden",
			expected: ProxyAuth{Countries: []string{"Sweden"}},
		},
		{
			name:  "multiple fields",
			input: "seed=42,country=Norway,city=Oslo,speed=1000,multihop=true",
			expected: ProxyAuth{
				Seed:      42,
				Countries: []string{"Norway"},
				Cities:    []string{"Oslo"},
				MinSpeed:  1000,
				Multihop:  true,
			},
		},
		{
			name:     "case insensitive keys",
			input:    "SEED=123,COUNTRY=Sweden,CITY=Stockholm",
			expected: ProxyAuth{Seed: 123, Countries: []string{"Sweden"}, Cities: []string{"Stockholm"}},
		},
		{
			name:     "mixed case keys",
			input:    "Seed=123,CoUnTrY=Sweden",
			expected: ProxyAuth{Seed: 123, Countries: []string{"Sweden"}},
		},
		{
			name:     "url encoded spaces",
			input:    "country=South%20Africa",
			expected: ProxyAuth{Countries: []string{"South Africa"}},
		},
		{
			name:     "url encoded special chars",
			input:    "city=S%C3%A3o%20Paulo",
			expected: ProxyAuth{Cities: []string{"São Paulo"}},
		},
		{
			name:     "owned true",
			input:    "owned=true",
			expected: ProxyAuth{Owned: boolPtr(true)},
		},
		{
			name:     "owned TRUE",
			input:    "owned=TRUE",
			expected: ProxyAuth{Owned: boolPtr(true)},
		},
		{
			name:     "owned false",
			input:    "owned=false",
			expected: ProxyAuth{Owned: boolPtr(false)},
		},
		{
			name:     "owned yes",
			input:    "owned=yes",
			expected: ProxyAuth{Owned: boolPtr(true)},
		},
		{
			name:     "owned 1",
			input:    "owned=1",
			expected: ProxyAuth{Owned: boolPtr(true)},
		},
		{
			name:     "owned 0",
			input:    "owned=0",
			expected: ProxyAuth{Owned: boolPtr(false)},
		},
		{
			name:     "trailing comma ignored",
			input:    "seed=123,",
			expected: ProxyAuth{Seed: 123},
		},
		{
			name:     "leading comma ignored",
			input:    ",seed=123",
			expected: ProxyAuth{Seed: 123},
		},
		{
			name:     "extra spaces",
			input:    " seed = 123 , country = Sweden ",
			expected: ProxyAuth{Seed: 123, Countries: []string{"Sweden"}},
		},
		{
			name:     "repeated country keys",
			input:    "country=Sweden,country=Norway",
			expected: ProxyAuth{Countries: []string{"Sweden", "Norway"}},
		},
		{
			name:     "comma-separated country values",
			input:    "country=Finland,Sweden",
			expected: ProxyAuth{Countries: []string{"Finland", "Sweden"}},
		},
		{
			name:     "comma-separated with other keys",
			input:    "seed=123,country=Finland,Sweden",
			expected: ProxyAuth{Seed: 123, Countries: []string{"Finland", "Sweden"}},
		},
		{
			name:     "comma-separated city values",
			input:    "city=Oslo,Stockholm",
			expected: ProxyAuth{Cities: []string{"Oslo", "Stockholm"}},
		},
		{
			name:     "comma-separated provider values",
			input:    "provider=Provider1,Provider2",
			expected: ProxyAuth{Providers: []string{"Provider1", "Provider2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := ParseProxyAuth(tt.input)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			if !slices.Equal(auth.Countries, tt.expected.Countries) {
				t.Errorf("countries: expected %v, got %v", tt.expected.Countries, auth.Countries)
			}
			if !slices.Equal(auth.Cities, tt.expected.Cities) {
				t.Errorf("cities: expected %v, got %v", tt.expected.Cities, auth.Cities)
			}
			if auth.Seed != tt.expected.Seed {
				t.Errorf("seed: expected %d, got %d", tt.expected.Seed, auth.Seed)
			}
			if !slices.Equal(auth.Providers, tt.expected.Providers) {
				t.Errorf("providers: expected %v, got %v", tt.expected.Providers, auth.Providers)
			}
			if auth.MinSpeed != tt.expected.MinSpeed {
				t.Errorf("speed: expected %d, got %d", tt.expected.MinSpeed, auth.MinSpeed)
			}
			if auth.Multihop != tt.expected.Multihop {
				t.Errorf("multihop: expected %v, got %v", tt.expected.Multihop, auth.Multihop)
			}
			// Compare Owned pointers by value
			if (auth.Owned == nil) != (tt.expected.Owned == nil) {
				t.Errorf("owned: expected nil=%v, got nil=%v", tt.expected.Owned == nil, auth.Owned == nil)
			} else if auth.Owned != nil && tt.expected.Owned != nil && *auth.Owned != *tt.expected.Owned {
				t.Errorf("owned: expected %v, got %v", *tt.expected.Owned, *auth.Owned)
			}
		})
	}
}

func TestParseProxyAuthErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "missing equals",
			input: "country",
		},
		{
			name:  "unknown parameter",
			input: "foo=bar",
		},
		{
			name:  "invalid seed",
			input: "seed=abc",
		},
		{
			name:  "invalid speed",
			input: "speed=fast",
		},
		{
			name:  "invalid owned",
			input: "owned=maybe",
		},
		{
			name:  "invalid multihop",
			input: "multihop=yesplease",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProxyAuth(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseProxyAuthHeader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ProxyAuth
	}{
		{
			name:     "basic auth with connection string",
			input:    "Basic " + base64.StdEncoding.EncodeToString([]byte("seed=123,country=Sweden")),
			expected: ProxyAuth{Seed: 123, Countries: []string{"Sweden"}},
		},
		{
			name:     "basic auth with trailing colon",
			input:    "Basic " + base64.StdEncoding.EncodeToString([]byte("seed=123:")),
			expected: ProxyAuth{Seed: 123},
		},
		{
			name:     "basic auth with empty userinfo",
			input:    "Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
			expected: ProxyAuth{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := parseProxyAuthHeader(tt.input)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			if !slices.Equal(auth.Countries, tt.expected.Countries) {
				t.Errorf("countries: expected %v, got %v", tt.expected.Countries, auth.Countries)
			}
			if !slices.Equal(auth.Cities, tt.expected.Cities) {
				t.Errorf("cities: expected %v, got %v", tt.expected.Cities, auth.Cities)
			}
			if auth.Seed != tt.expected.Seed {
				t.Errorf("seed: expected %d, got %d", tt.expected.Seed, auth.Seed)
			}
			if !slices.Equal(auth.Providers, tt.expected.Providers) {
				t.Errorf("providers: expected %v, got %v", tt.expected.Providers, auth.Providers)
			}
			if auth.MinSpeed != tt.expected.MinSpeed {
				t.Errorf("speed: expected %d, got %d", tt.expected.MinSpeed, auth.MinSpeed)
			}
			if auth.Multihop != tt.expected.Multihop {
				t.Errorf("multihop: expected %v, got %v", tt.expected.Multihop, auth.Multihop)
			}
			// Compare Owned pointers by value
			if (auth.Owned == nil) != (tt.expected.Owned == nil) {
				t.Errorf("owned: expected nil=%v, got nil=%v", tt.expected.Owned == nil, auth.Owned == nil)
			} else if auth.Owned != nil && tt.expected.Owned != nil && *auth.Owned != *tt.expected.Owned {
				t.Errorf("owned: expected %v, got %v", *tt.expected.Owned, *auth.Owned)
			}
		})
	}
}

func TestParseProxyAuthHeaderErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "not basic auth",
			input: "Bearer token123",
		},
		{
			name:  "invalid base64",
			input: "Basic not-valid-base64!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseProxyAuthHeader(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestProxyAuthApply(t *testing.T) {
	owned := true
	auth := ProxyAuth{
		Seed:      123,
		Countries: []string{"Sweden"},
		Cities:    []string{"Stockholm"},
		Owned:     &owned,
		Providers: []string{"Mullvad"},
		MinSpeed:  100,
		Multihop:  true,
	}

	filter := mullvad.Filter{}
	auth.ApplyTo(&filter)

	if filter.Seed != 123 {
		t.Errorf("expected seed 123, got %d", filter.Seed)
	}
	if len(filter.Countries) != 1 || filter.Countries[0] != "Sweden" {
		t.Errorf("expected countries [Sweden], got %v", filter.Countries)
	}
	if len(filter.Cities) != 1 || filter.Cities[0] != "Stockholm" {
		t.Errorf("expected cities [Stockholm], got %v", filter.Cities)
	}
	if filter.Owned == nil || *filter.Owned != true {
		t.Error("expected owned to be true")
	}
	if len(filter.Providers) != 1 || filter.Providers[0] != "Mullvad" {
		t.Errorf("expected providers [Mullvad], got %v", filter.Providers)
	}
	if filter.MinSpeed != 100 {
		t.Errorf("expected min speed 100, got %d", filter.MinSpeed)
	}
	if !filter.Multihop {
		t.Error("expected multihop to be true")
	}
}

func boolPtr(b bool) *bool {
	return &b
}
