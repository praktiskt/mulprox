package proxy

import (
	"net/http"
	"testing"
)

func TestStripProxyHeaders(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name     string
		input    map[string][]string
		expected map[string][]string
	}{
		{
			name: "removes X-Mulprox headers",
			input: map[string][]string{
				"Accept":            {"*/*"},
				"X-Mulprox-Country": {"Sweden"},
				"X-Mulprox-Seed":    {"12345"},
				"User-Agent":        {"curl/7.68.0"},
			},
			expected: map[string][]string{
				"Accept":     {"*/*"},
				"User-Agent": {"curl/7.68.0"},
			},
		},
		{
			name: "keeps non-X-Mulprox headers",
			input: map[string][]string{
				"Accept-Encoding": {"gzip"},
				"Authorization":   {"Bearer token"},
				"X-Forwarded-For": {"1.2.3.4"},
			},
			expected: map[string][]string{
				"Accept-Encoding": {"gzip"},
				"Authorization":   {"Bearer token"},
				"X-Forwarded-For": {"1.2.3.4"},
			},
		},
		{
			name:     "handles empty headers",
			input:    map[string][]string{},
			expected: map[string][]string{},
		},
		{
			name: "handles only X-Mulprox headers",
			input: map[string][]string{
				"X-Mulprox-Country":  {"Sweden"},
				"X-Mulprox-City":     {"Stockholm"},
				"X-Mulprox-Owned":    {"true"},
				"X-Mulprox-Provider": {"M247"},
				"X-Mulprox-Speed":    {"1000"},
				"X-Mulprox-Multihop": {"false"},
				"X-Mulprox-Seed":     {"42"},
			},
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header(tt.input)
			result := h.stripProxyHeaders(headers)

			for key, expectedValues := range tt.expected {
				if result.Get(key) == "" {
					t.Errorf("expected header %q to be present", key)
					continue
				}
				if len(result[key]) != len(expectedValues) {
					t.Errorf("expected %d values for %q, got %d", len(expectedValues), key, len(result[key]))
				}
			}

			for key := range result {
				if _, ok := tt.expected[key]; !ok {
					t.Errorf("unexpected header %q in result", key)
				}
			}
		})
	}
}

func TestGetSOCKS5AddrFromRequest(t *testing.T) {
	t.Skip("requires network access to fetch Mullvad server list")
	h := &Handler{}

	tests := []struct {
		name          string
		headers       map[string]string
		expectErr     bool
		expectCountry string
	}{
		{
			name: "country header",
			headers: map[string]string{
				"X-Mulprox-Country": "Sweden",
			},
			expectCountry: "Sweden",
		},
		{
			name: "seed header",
			headers: map[string]string{
				"X-Mulprox-Seed": "12345",
			},
		},
		{
			name: "city header",
			headers: map[string]string{
				"X-Mulprox-City": "Stockholm",
			},
		},
		{
			name: "owned header",
			headers: map[string]string{
				"X-Mulprox-Owned": "true",
			},
		},
		{
			name: "provider header",
			headers: map[string]string{
				"X-Mulprox-Provider": "M247",
			},
		},
		{
			name: "speed header",
			headers: map[string]string{
				"X-Mulprox-Speed": "1000",
			},
		},
		{
			name: "multihop header",
			headers: map[string]string{
				"X-Mulprox-Multihop": "true",
			},
		},
		{
			name: "combined headers",
			headers: map[string]string{
				"X-Mulprox-Country": "Sweden",
				"X-Mulprox-Seed":    "42",
			},
			expectCountry: "Sweden",
		},
		{
			name: "invalid seed",
			headers: map[string]string{
				"X-Mulprox-Seed": "not-a-number",
			},
			expectErr: true,
		},
		{
			name: "invalid speed",
			headers: map[string]string{
				"X-Mulprox-Speed": "not-a-number",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{},
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
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
