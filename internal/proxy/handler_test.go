package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"golang.org/x/net/proxy"
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

// --- stub provider + dialers for handler retry tests ---

type stubDialResult struct {
	dialer proxy.Dialer
	err    error
}

type stubProvider struct {
	relayAddr    string
	relayErr     error
	filterServer mullvad.Server
	filterErr    error
	dialResults  []stubDialResult
	dialIdx      int
}

func (s *stubProvider) FetchMullvadList(ctx context.Context) ([]mullvad.Server, error) { return nil, nil }

func (s *stubProvider) GetFilteredServer(ctx context.Context, filter mullvad.Filter) (mullvad.Server, error) {
	if s.filterErr != nil {
		return mullvad.Server{}, s.filterErr
	}
	return s.filterServer, nil
}

func (s *stubProvider) GetFilteredServerWithHealth(ctx context.Context, filter mullvad.Filter, isOnline func(string) bool) (mullvad.Server, error) {
	if s.filterErr != nil {
		return mullvad.Server{}, s.filterErr
	}
	return s.filterServer, nil
}

func (s *stubProvider) ResolveRelayAddr(ctx context.Context, socksAddr string) (string, error) {
	if s.relayErr != nil {
		return "", s.relayErr
	}
	return s.relayAddr, nil
}

func (s *stubProvider) SOCKS5DialerFromAddr(ctx context.Context, socksAddr string, timeout time.Duration) (proxy.Dialer, error) {
	return s.SOCKS5DialerFromResolved(ctx, socksAddr, timeout)
}

func (s *stubProvider) SOCKS5DialerFromResolved(ctx context.Context, resolvedAddr string, timeout time.Duration) (proxy.Dialer, error) {
	if s.dialIdx >= len(s.dialResults) {
		return nil, fmt.Errorf("stub: no more dial results")
	}
	r := s.dialResults[s.dialIdx]
	s.dialIdx++
	return r.dialer, r.err
}

type dummyConn struct{}

func (dummyConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (dummyConn) Write(b []byte) (int, error)        { return len(b), nil }
func (dummyConn) Close() error                        { return nil }
func (dummyConn) LocalAddr() net.Addr                 { return &net.TCPAddr{} }
func (dummyConn) RemoteAddr() net.Addr                { return &net.TCPAddr{} }
func (dummyConn) SetDeadline(_ time.Time) error       { return nil }
func (dummyConn) SetReadDeadline(_ time.Time) error   { return nil }
func (dummyConn) SetWriteDeadline(_ time.Time) error  { return nil }

type successDialer struct{}

func (d successDialer) Dial(_, _ string) (net.Conn, error) { return dummyConn{}, nil }

type failDialer struct{}

func (d failDialer) Dial(_, _ string) (net.Conn, error) { return nil, errors.New("simulated dial failure") }

// --- test helpers ---

func waitTestReady(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy not ready")
}

func startTestProxy(t *testing.T, p mullvad.ServerProvider, upstream string) (addr string, closeFn func()) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewWithUpstream(logger, 5*time.Second, p, false, nil, mullvad.Filter{}, upstream)
	ts := &http.Server{Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ts.Serve(listener)
	waitTestReady(t, listener.Addr().String())
	return listener.Addr().String(), func() {
		ts.Close()
		listener.Close()
	}
}

func sendConnect(t *testing.T, conn net.Conn, host string) {
	t.Helper()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	_, err := conn.Write([]byte(req))
	if err != nil {
		t.Fatal(err)
	}
}

func readStatus(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return ""
	}
	return line
}

func startNoopSocks5(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleNoopSocks5(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleNoopSocks5(conn net.Conn) {
	defer conn.Close()
	// read auth methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, make([]byte, nmethods)); err != nil {
		return
	}
	// accept no-auth
	conn.Write([]byte{0x05, 0x00})
	// read CONNECT request
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	switch hdr[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, make([]byte, 6))
	case 0x03: // domain
		var lb [1]byte
		io.ReadFull(conn, lb[:])
		io.ReadFull(conn, make([]byte, int(lb[0])+2))
	case 0x04: // IPv6
		io.ReadFull(conn, make([]byte, 18))
	}
	// success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	io.Copy(io.Discard, conn)
}

// --- handler retry tests ---

func baseServer() mullvad.Server {
	return mullvad.Server{Hostname: "test-relay", SOCKS5: "test", SOCKSPort: 1080}
}

func TestConnectSuccess(t *testing.T) {
	p := &stubProvider{
		relayAddr:    "192.0.2.1:1080",
		filterServer: baseServer(),
		dialResults:  []stubDialResult{{dialer: successDialer{}}},
	}
	addr, closer := startTestProxy(t, p, "")
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if status == "" {
		t.Fatal("no response after CONNECT")
	}
	if !containsStatus(status, "200") {
		t.Errorf("expected 200, got %q", status)
	}
}

func TestConnectRetryDialerError(t *testing.T) {
	dialErr := errors.New("relay unreachable")
	p := &stubProvider{
		relayAddr:    "192.0.2.1:1080",
		filterServer: baseServer(),
		dialResults: []stubDialResult{
			{err: dialErr},
			{dialer: successDialer{}},
		},
	}
	addr, closer := startTestProxy(t, p, "")
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if !containsStatus(status, "200") {
		t.Errorf("expected 200 after retry, got %q", status)
	}
}

func TestConnectRetryTargetDialFail(t *testing.T) {
	p := &stubProvider{
		relayAddr:    "192.0.2.1:1080",
		filterServer: baseServer(),
		dialResults: []stubDialResult{
			{dialer: failDialer{}},
			{dialer: successDialer{}},
		},
	}
	addr, closer := startTestProxy(t, p, "")
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if !containsStatus(status, "200") {
		t.Errorf("expected 200 after retry, got %q", status)
	}
}

func TestConnectExhausted(t *testing.T) {
	dialErr := errors.New("relay unreachable")
	p := &stubProvider{
		relayAddr:    "192.0.2.1:1080",
		filterServer: baseServer(),
		dialResults: []stubDialResult{
			{err: dialErr},
			{err: dialErr},
			{err: dialErr},
		},
	}
	addr, closer := startTestProxy(t, p, "")
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if status != "" {
		t.Errorf("expected no response (connection closed), got %q", status)
	}
}

func TestConnectPreHijackDNSFail(t *testing.T) {
	p := &stubProvider{
		relayErr:     errors.New("dns timeout"),
		filterServer: baseServer(),
	}
	addr, closer := startTestProxy(t, p, "")
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if !containsStatus(status, "502") {
		t.Errorf("expected 502 Bad Gateway, got %q", status)
	}
}

func TestConnectDirect(t *testing.T) {
	socksAddr, socksClose := startNoopSocks5(t)
	defer socksClose()

	p := &stubProvider{} // not used, direct path bypasses provider
	addr, closer := startTestProxy(t, p, "direct://"+socksAddr)
	defer closer()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendConnect(t, conn, "example.com:443")
	status := readStatus(t, conn)
	if !containsStatus(status, "200") {
		t.Errorf("expected 200 for direct, got %q", status)
	}
}

func containsStatus(line, code string) bool {
	return len(line) > 0 && len(line) >= 12 && line[9:12] == code
}
