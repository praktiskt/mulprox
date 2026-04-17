package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/stats"
	"github.com/praktiskt/mulprox/internal/util"
	"golang.org/x/net/proxy"
)

const (
	maxRetries            = 3
	copyBufSize           = 32 * 1024
	maxTransportCacheSize = 50
)

type roundTripResult struct {
	resp       *http.Response
	remoteID   string
	sent       int64
	err        error
	proxyError bool
}

type ProxyAuth struct {
	Countries []string `json:"country,omitempty"`
	Cities    []string `json:"city,omitempty"`
	Seed      int64    `json:"seed,omitempty"`
	Owned     *bool    `json:"owned,omitempty"`
	Providers []string `json:"provider,omitempty"`
	MinSpeed  int      `json:"speed,omitempty"`
	Multihop  bool     `json:"multihop,omitempty"`
}

func (p *ProxyAuth) ApplyTo(filter *mullvad.Filter) {
	if len(p.Countries) > 0 {
		filter.Countries = append(filter.Countries, p.Countries...)
	}
	if len(p.Cities) > 0 {
		filter.Cities = append(filter.Cities, p.Cities...)
	}
	if p.Seed != 0 {
		filter.Seed = p.Seed
	}
	if p.Owned != nil {
		filter.Owned = p.Owned
	}
	if len(p.Providers) > 0 {
		filter.Providers = append(filter.Providers, p.Providers...)
	}
	if p.MinSpeed > 0 {
		filter.MinSpeed = p.MinSpeed
	}
	if p.Multihop {
		filter.Multihop = p.Multihop
	}
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, copyBufSize)
	},
}

type Handler struct {
	logger         *slog.Logger
	timeout        time.Duration
	mullvad        mullvad.ServerProvider
	httpsOnly      bool
	stats          stats.Store
	baseFilter     mullvad.Filter
	transportCache *util.LRUCache[*http.Transport]
}

func New(logger *slog.Logger, timeout time.Duration, mullvad mullvad.ServerProvider, httpsOnly bool, statsStore stats.Store, baseFilter mullvad.Filter) *Handler {
	return &Handler{
		logger:         logger,
		timeout:        timeout,
		mullvad:        mullvad,
		httpsOnly:      httpsOnly,
		stats:          statsStore,
		baseFilter:     baseFilter,
		transportCache: util.NewLRUCache[*http.Transport](maxTransportCacheSize),
	}
}

// ServeHTTP dispatches to CONNECT tunneling or regular HTTP proxying.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("proxy handler received",
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("host", r.Host),
		slog.String("path", r.URL.Path))

	if h.httpsOnly && r.Method != http.MethodConnect {
		http.Error(w, "HTTPS only", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	h.handleHTTP(w, r)
}

// handleHTTP proxies a regular HTTP request.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()

	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if targetURL == "/" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Mullvad Proxy Server\nUsage: Set HTTP_PROXY environment variable to point to this server"))
		return
	}

	targetURL = strings.TrimPrefix(targetURL, "/")
	if targetURL == "" {
		targetURL = "/"
	}
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	h.logger.Debug("proxying request", slog.String("url", targetURL), slog.String("method", r.Method))

	h.proxyHTTP(r.Context(), w, r, targetURL, h.timeout)
}

// proxyHTTP performs the HTTP proxy request with retries on transient errors.
// Each retry attempt gets its own fresh context with the full timeout budget.
func (h *Handler) proxyHTTP(parentCtx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, timeout time.Duration) {
	body, err := h.readBody(r)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var lastResult *roundTripResult

	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(parentCtx, timeout)
		result := h.roundTrip(ctx, r, targetURL, body)
		cancel() // Release context resources immediately

		if result.err != nil {
			if !isRetryable(result.err) {
				h.logAndRespond(w, result.remoteID, result.err, false)
				return
			}
			lastResult = result
			continue
		}

		defer result.resp.Body.Close()
		h.writeResponse(w, result.resp, result.remoteID, result.sent)
		return
	}

	h.logger.Error("proxy request exhausted retries",
		slog.String("error", lastResult.err.Error()),
		slog.Int("attempts", maxRetries))
	h.logAndRespond(w, lastResult.remoteID, lastResult.err, false)
}

// roundTrip performs a single proxy attempt: resolves a SOCKS5 server, builds
// a transport, and executes the request.
func (h *Handler) roundTrip(ctx context.Context, r *http.Request, targetURL string, body []byte) *roundTripResult {
	socksAddr, remoteID, err := h.resolveSOCKS5(ctx, r)
	if err != nil {
		return &roundTripResult{err: err, proxyError: true}
	}

	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return &roundTripResult{remoteID: remoteID, err: err, proxyError: true}
	}

	tr := h.getTransport(socksAddr, socksDialer)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, reqBody)
	if err != nil {
		return &roundTripResult{remoteID: remoteID, err: err, proxyError: true}
	}
	for key, values := range r.Header {
		req.Header[key] = values
	}

	sent := httpRequestSize(req, len(body))

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return &roundTripResult{remoteID: remoteID, err: err, proxyError: true}
	}
	return &roundTripResult{resp: resp, remoteID: remoteID, sent: sent, proxyError: false}
}

// httpRequestSize returns the approximate number of bytes the HTTP request
// will write on the wire (request line + headers + body).
func httpRequestSize(req *http.Request, bodyLen int) int64 {
	// Request line: METHOD SP REQUEST_URI PROTO\r\n
	size := int64(len(req.Method)) + 1 + int64(len(req.URL.RequestURI())) + 1 + int64(len(req.Proto)) + 2
	// Headers
	for key, values := range req.Header {
		for _, v := range values {
			size += int64(len(key)) + 2 + int64(len(v)) + 2 // "Key: Value\r\n"
		}
	}
	// Blank line
	size += 2
	// Body
	size += int64(bodyLen)
	return size
}

type countingWriter struct {
	http.ResponseWriter
	n        int64
	remoteID string
	stats    stats.Store
	lastSent int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	if c.stats != nil && c.remoteID != "" && n > 0 {
		delta := int64(n) - c.lastSent
		if delta > 0 {
			c.stats.RecordBytes(c.remoteID, 0, delta)
			c.lastSent += delta
		}
	}
	return n, err
}

// writeResponse copies the upstream response to the client and records stats.
func (h *Handler) writeResponse(w http.ResponseWriter, resp *http.Response, remoteID string, sentBytes int64) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	cw := &countingWriter{
		ResponseWriter: w,
		remoteID:       remoteID,
		stats:          h.stats,
	}
	cw.WriteHeader(resp.StatusCode)

	if h.stats != nil && remoteID != "" {
		h.stats.RecordRequest(remoteID)
	}

	_, _ = io.Copy(cw, resp.Body)
}

// handleConnect handles CONNECT requests by tunneling bytes between client
// and the upstream SOCKS5 target.
// It retries on transient errors with a fresh Mullvad server each attempt.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	h.logger.Debug("handling CONNECT", slog.String("host", host))

	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	var lastErr error
	var lastRemoteID string

	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
		socksAddr, remoteID, err := h.resolveSOCKS5(ctx, r)
		if err != nil {
			cancel()
			h.logger.Debug("failed to get Mullvad server, retrying", slog.String("error", err.Error()))
			lastErr = err
			lastRemoteID = remoteID
			continue
		}

		dialer, err := h.mullvad.SOCKS5DialerFromAddr(socksAddr, h.timeout)
		if err != nil {
			cancel()
			h.logger.Debug("failed to create Mullvad session, retrying", slog.String("error", err.Error()))
			lastErr = err
			lastRemoteID = remoteID
			continue
		}

		targetConn, err := dialer.Dial("tcp", host)
		if err != nil {
			cancel()
			h.logger.Debug("failed to connect to target, retrying", slog.String("error", err.Error()))
			lastErr = err
			lastRemoteID = remoteID
			continue
		}

		w.Header().Set("Connection", "Keep-Alive")
		w.WriteHeader(http.StatusOK)

		if h.stats != nil && remoteID != "" {
			h.stats.RecordRequest(remoteID)
		}

		hij, ok := w.(http.Hijacker)
		if !ok {
			cancel()
			targetConn.Close()
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}

		clientConn, _, err := hij.Hijack()
		cancel() // Release context after hijack
		if err != nil {
			targetConn.Close()
			h.logger.Debug("failed to hijack connection, retrying", slog.String("error", err.Error()))
			lastErr = err
			lastRemoteID = remoteID
			continue
		}

		h.tunnel(clientConn, targetConn, remoteID)
		return
	}

	h.logger.Error("CONNECT request exhausted retries",
		slog.String("error", lastErr.Error()),
		slog.Int("attempts", maxRetries))
	if h.stats != nil && lastRemoteID != "" {
		h.stats.RecordError(lastRemoteID)
	}
	http.Error(w, "failed to reach target", http.StatusBadGateway)
}

type countingReader struct {
	reader io.Reader
	count  *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	*c.count += int64(n)
	return n, err
}

// tunnel copies data bidirectionally between client and target connections.
func (h *Handler) tunnel(clientConn, targetConn net.Conn, remoteID string) {
	buf1 := bufferPool.Get().([]byte)
	buf2 := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf1)
	defer bufferPool.Put(buf2)

	var sent, received int64

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.CopyBuffer(targetConn, &countingReader{reader: clientConn, count: &sent}, buf1)
		targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.CopyBuffer(clientConn, &countingReader{reader: targetConn, count: &received}, buf2)
		clientConn.Close()
	}()

	var lastSent, lastRecv int64
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for {
		select {
		case <-ticker.C:
			deltaSent := sent - lastSent
			deltaRecv := received - lastRecv
			if deltaSent > 0 || deltaRecv > 0 {
				if h.stats != nil && remoteID != "" {
					h.stats.RecordBytes(remoteID, deltaSent, deltaRecv)
				}
				lastSent = sent
				lastRecv = received
			}
		case <-done:
			ticker.Stop()
			deltaSent := sent - lastSent
			deltaRecv := received - lastRecv
			if deltaSent > 0 || deltaRecv > 0 {
				if h.stats != nil && remoteID != "" {
					h.stats.RecordBytes(remoteID, deltaSent, deltaRecv)
				}
			}
			return
		}
	}
}

// resolveSOCKS5 picks a Mullvad SOCKS5 server based on the request's
// Proxy-Authorization header and returns its address and identifier.
// It skips servers that are offline according to health checks.
//
// The header is expected to be in the format:
//
//	Proxy-Authorization: Basic <base64(connection-string)>
//
// where the connection string is comma-separated key=value pairs, e.g.:
//
//	seed=123,country=Stockholm
//
// Parameter keys are case-insensitive.
func (h *Handler) resolveSOCKS5(ctx context.Context, r *http.Request) (addr, remoteID string, err error) {
	filter := h.baseFilter

	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		auth, err := parseProxyAuthHeader(v)
		if err != nil {
			return "", "", fmt.Errorf("invalid Proxy-Authorization: %w", err)
		}
		auth.ApplyTo(&filter)
	}

	isOnline := func(hostname string) bool {
		if h.stats == nil {
			return true
		}
		stats := h.stats.GetRemoteStats(hostname)
		return stats == nil || stats.IsOnline()
	}

	server, err := h.mullvad.GetFilteredServerWithHealth(ctx, filter, isOnline)
	if err == nil {
		if h.stats != nil {
			h.stats.SetRemoteMetadata(server.Hostname, server.Hostname, server.Country, server.City)
		}
		return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), server.Hostname, nil
	}

	h.logger.Debug("no healthy server found, falling back to any server", slog.String("error", err.Error()))

	server, err = h.mullvad.GetFilteredServer(ctx, filter)
	if err != nil {
		return "", "", err
	}

	if h.stats != nil {
		h.stats.SetRemoteMetadata(server.Hostname, server.Hostname, server.Country, server.City)
	}
	return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), server.Hostname, nil
}

// parseProxyAuthHeader parses the Proxy-Authorization header value.
// It supports the "Basic <base64>" format where the decoded value is a
// connection string (comma-separated key=value pairs).
func parseProxyAuthHeader(header string) (*ProxyAuth, error) {
	// Expect "Basic <base64>"
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("expected Basic auth, got: %q", header[:min(len(header), 20)])
	}

	encoded := strings.TrimPrefix(header, prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	connStr := string(decoded)
	// Trim trailing colon if present (empty password in URL userinfo format)
	connStr = strings.TrimSuffix(connStr, ":")

	return ParseProxyAuth(connStr)
}

// getTransport returns a cached http.Transport for the given SOCKS5 address.
func (h *Handler) getTransport(socksAddr string, dialer proxy.Dialer) *http.Transport {
	if tr, ok := h.transportCache.Get(socksAddr); ok {
		return tr
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   100,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	h.transportCache.Set(socksAddr, tr)
	return tr
}

// readBody buffers the request body so it can be replayed across retries.
func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

// logAndRespond logs a proxy error, records stats, and writes a 502 response.
// If markUnhealthy is true, the proxy is also marked as offline.
func (h *Handler) logAndRespond(w http.ResponseWriter, remoteID string, err error, markUnhealthy bool) {
	h.logger.Error("proxy request failed", slog.String("error", err.Error()))
	if h.stats != nil && remoteID != "" {
		h.stats.RecordError(remoteID)
		if markUnhealthy {
			current := h.stats.GetRemoteStats(remoteID)
			newFailures := current.Health.ConsecutiveFailures + 1
			health := stats.RemoteHealth{
				Online:               false,
				ConsecutiveFailures:  newFailures,
				ConsecutiveSuccesses: 0,
				LastCheck:            time.Now(),
			}
			h.stats.SetRemoteHealth(remoteID, health)
		}
	}
	http.Error(w, "failed to reach target", http.StatusBadGateway)
}

// isRetryable reports whether the error is likely transient and the request
// should be tried again with a fresh connection.
func isRetryable(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}
