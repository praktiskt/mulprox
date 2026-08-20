package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/praktiskt/mulprox/internal/stats"
	"github.com/praktiskt/mulprox/internal/util"
	"golang.org/x/net/proxy"
)

const (
	maxRetries            = 3
	maxTransportCacheSize = 50
	// circuitBreakerStrikes: relay goes offline after this many consecutive
	// request-level failures; health checker handles recovery.
	circuitBreakerStrikes = 2
)

const indexResponse = "Mullvad Proxy Server\nUsage: Set HTTP_PROXY environment variable to point to this server"

type roundTripResult struct {
	resp     *http.Response
	remoteID string
	sent     int64
	err      error
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

type Handler struct {
	logger         *slog.Logger
	timeout        time.Duration
	mullvad        mullvad.ServerProvider
	httpsOnly      bool
	stats          stats.Store
	baseFilter     mullvad.Filter
	transportCache *util.LRUCache[*http.Transport]
	upstreamSOCKS5 string
}

func New(logger *slog.Logger, timeout time.Duration, mullvad mullvad.ServerProvider, httpsOnly bool, statsStore stats.Store, baseFilter mullvad.Filter) *Handler {
	return NewWithUpstream(logger, timeout, mullvad, httpsOnly, statsStore, baseFilter, "")
}

func NewWithUpstream(logger *slog.Logger, timeout time.Duration, mullvad mullvad.ServerProvider, httpsOnly bool, statsStore stats.Store, baseFilter mullvad.Filter, upstreamSOCKS5 string) *Handler {
	return &Handler{
		logger:         logger,
		timeout:        timeout,
		mullvad:        mullvad,
		httpsOnly:      httpsOnly,
		stats:          statsStore,
		baseFilter:     baseFilter,
		upstreamSOCKS5: upstreamSOCKS5,
		transportCache: util.NewLRUCacheWithEvict[*http.Transport](maxTransportCacheSize, func(tr *http.Transport) {
			if tr != nil {
				tr.CloseIdleConnections()
			}
		}),
	}
}

// ServeHTTP routes to CONNECT tunnel or HTTP proxy.
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

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()

	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if targetURL == "/" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(indexResponse))
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

	h.proxyHTTP(r.Context(), w, r, targetURL)
}

// proxyHTTP retries on transient errors; <=10MB body buffered for replay.
func (h *Handler) proxyHTTP(parentCtx context.Context, w http.ResponseWriter, r *http.Request, targetURL string) {
	bodyBuf, err := h.readBody(r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			result := h.roundTrip(parentCtx, r, targetURL, r.Body, r.ContentLength, nil)
			if result.err != nil {
				h.logAndRespond(w, result.remoteID, result.err, isRelayFailure(result.err))
				return
			}
			defer result.resp.Body.Close()
			h.writeResponse(w, result.resp, result.remoteID, result.sent)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var reqBody io.Reader
	var bodyLen int64
	if bodyBuf != nil {
		reqBody = bytes.NewReader(bodyBuf)
		bodyLen = int64(len(bodyBuf))
	}

	var lastResult *roundTripResult
	excluded := make(map[string]bool)

	for attempt := 0; attempt < maxRetries; attempt++ {
		if bodyBuf != nil {
			reqBody = bytes.NewReader(bodyBuf)
		}
		result := h.roundTrip(parentCtx, r, targetURL, reqBody, bodyLen, excluded)

		if result.err != nil {
			if result.resp != nil && result.resp.Body != nil {
				result.resp.Body.Close()
			}
			if result.remoteID != "" {
				excluded[result.remoteID] = true
			}
			if !isRetryable(result.err) {
				h.logAndRespond(w, result.remoteID, result.err, isRelayFailure(result.err))
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
	h.logAndRespond(w, lastResult.remoteID, lastResult.err, isRelayFailure(lastResult.err))
}

// roundTrip: resolve SOCKS5 -> build transport -> execute request.
func (h *Handler) roundTrip(ctx context.Context, r *http.Request, targetURL string, body io.Reader, bodyLen int64, exclude map[string]bool) *roundTripResult {
	var tr *http.Transport
	var remoteID string

	if strings.HasPrefix(h.upstreamSOCKS5, "direct://") {
		upstream := strings.TrimPrefix(h.upstreamSOCKS5, "direct://")
		remoteID = upstream
		tr = h.getTransport(h.upstreamSOCKS5)
		if tr == nil {
			dialer, err := proxy.SOCKS5("tcp", upstream, nil, &net.Dialer{Timeout: h.timeout})
			if err != nil {
				return &roundTripResult{remoteID: remoteID, err: err}
			}
			tr = h.createAndCacheTransport(h.upstreamSOCKS5, dialer)
		}
	} else {
		socksAddr, resolvedID, err := h.resolveSOCKS5(ctx, r, exclude)
		if err != nil {
			return &roundTripResult{err: err}
		}
		remoteID = resolvedID

		cacheKey := socksAddr
		if h.upstreamSOCKS5 != "" {
			cacheKey = socksAddr + "|" + h.upstreamSOCKS5
		}

		tr = h.getTransport(cacheKey)
		if tr == nil {
			socksDialer, err := h.mullvad.SOCKS5DialerFromAddr(ctx, socksAddr, h.timeout)
			if err != nil {
				return &roundTripResult{remoteID: remoteID, err: err}
			}
			if h.upstreamSOCKS5 != "" {
				socksDialer, err = proxy.SOCKS5("tcp", h.upstreamSOCKS5, nil, socksDialer)
				if err != nil {
					return &roundTripResult{remoteID: remoteID, err: err}
				}
			}
			tr = h.createAndCacheTransport(cacheKey, socksDialer)
		}
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, body)
	if err != nil {
		return &roundTripResult{remoteID: remoteID, err: err}
	}
	for key, values := range r.Header {
		req.Header[key] = values
	}
	req.ContentLength = r.ContentLength
	req.TransferEncoding = append([]string(nil), r.TransferEncoding...)
	req.Close = r.Close
	for k, v := range r.Trailer {
		req.Trailer[k] = v
	}

	sent := httpRequestSize(req, bodyLen)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return &roundTripResult{remoteID: remoteID, err: err}
	}
	return &roundTripResult{resp: resp, remoteID: remoteID, sent: sent}
}

// httpRequestSize estimates wire bytes (line + headers + body).
func httpRequestSize(req *http.Request, bodyLen int64) int64 {
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
	size += bodyLen
	return size
}

const statsBatchThreshold = 256 * 1024

type countingWriter struct {
	http.ResponseWriter
	remoteID string
	stats    stats.Store
	sent     int64
	pending  int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	if c.stats != nil && c.remoteID != "" && n > 0 {
		c.sent += int64(n)
		c.pending += int64(n)
		if c.pending >= statsBatchThreshold {
			c.stats.RecordBytes(c.remoteID, 0, c.pending)
			c.pending = 0
		}
	}
	return n, err
}

func (c *countingWriter) Flush() {
	if c.stats != nil && c.remoteID != "" && c.pending > 0 {
		c.stats.RecordBytes(c.remoteID, 0, c.pending)
		c.pending = 0
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// mulproxHeaders builds X-Mulprox-* headers for a relay. Empty when the relay
// is unknown (direct:// upstream, no metadata) or stats store is nil.
func (h *Handler) mulproxHeaders(remoteID string) http.Header {
	hd := make(http.Header)
	if h.stats == nil || remoteID == "" {
		return hd
	}
	hostname, country, city, egressIP := h.stats.GetRemoteInfo(remoteID)
	if hostname == "" {
		return hd
	}
	// Direct map assignment: preserves exact key spelling (X-Mulprox-Egress-IP)
	// instead of http.CanonicalHeaderKey (which lowercases IP -> Ip).
	hd["X-Mulprox-Relay"] = []string{remoteID}
	if country != "" {
		hd["X-Mulprox-Country"] = []string{country}
	}
	if city != "" {
		hd["X-Mulprox-City"] = []string{city}
	}
	if egressIP != "" {
		hd["X-Mulprox-Egress-IP"] = []string{egressIP}
	}
	return hd
}

// connectResponse renders the CONNECT 200 line plus X-Mulprox-* headers.
func (h *Handler) connectResponse(remoteID string) []byte {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 Connection established\r\n")
	for k, v := range h.mulproxHeaders(remoteID) {
		for _, vv := range v {
			buf.WriteString(k + ": " + vv + "\r\n")
		}
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// writeResponse copies upstream response to client, records stats.
func (h *Handler) writeResponse(w http.ResponseWriter, resp *http.Response, remoteID string, sentBytes int64) {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	for k, v := range h.mulproxHeaders(remoteID) {
		w.Header()[k] = v
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

	buf := util.BufferPool.Get().([]byte)
	defer util.BufferPool.Put(buf)
	if _, err := io.CopyBuffer(cw, resp.Body, buf); err != nil {
		h.logger.Debug("error copying response body", slog.String("error", err.Error()))
	}
	cw.Flush()
}

// handleConnect tunnels via SOCKS5; retries on transient errors.
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

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	if strings.HasPrefix(h.upstreamSOCKS5, "direct://") {
		h.handleConnectDirect(w, r, host, hij)
		return
	}

	socksAddr, remoteID, err := h.resolveWithDNS(r.Context(), r, nil)
	if err != nil {
		http.Error(w, "no relay DNS reachable", http.StatusBadGateway)
		return
	}

	clientConn, _, err := hij.Hijack()
	if err != nil {
		h.logger.Debug("client disconnected before hijack", slog.String("error", err.Error()))
		return
	}

	var lastErr error
	var lastRemoteID string
	lastRemoteID = remoteID
	excluded := make(map[string]bool)

	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), h.timeout)

		dialer, err := h.mullvad.SOCKS5DialerFromResolved(ctx, socksAddr, h.timeout)
		if err != nil {
			cancel()
			h.logger.Debug("SOCKS5 to relay failed, retrying", slog.String("error", err.Error()))
			lastErr = err
			excluded[remoteID] = true
			if isRelayFailure(err) {
				h.markRemoteUnhealthy(remoteID)
			}
			socksAddr, remoteID, err = h.resolveWithDNS(ctx, r, excluded)
			if err != nil {
				h.logger.Debug("relay DNS failed in retry", slog.String("error", err.Error()))
				continue
			}
			lastRemoteID = remoteID
			continue
		}

		if h.upstreamSOCKS5 != "" {
			dialer, err = proxy.SOCKS5("tcp", h.upstreamSOCKS5, nil, dialer)
			if err != nil {
				cancel()
				h.logger.Debug("upstream SOCKS5 failed, retrying", slog.String("error", err.Error()))
				lastErr = err
				continue
			}
		}

		targetConn, err := dialer.Dial("tcp", host)
		if err != nil {
			cancel()
			h.logger.Debug("target connect failed, retrying", slog.String("error", err.Error()))
			lastErr = err
			excluded[remoteID] = true
			if isRelayFailure(err) {
				h.markRemoteUnhealthy(remoteID)
			}
			socksAddr, remoteID, err = h.resolveWithDNS(ctx, r, excluded)
			if err != nil {
				h.logger.Debug("relay DNS failed in retry", slog.String("error", err.Error()))
				continue
			}
			lastRemoteID = remoteID
			continue
		}
		cancel()

		if _, err := clientConn.Write(h.connectResponse(remoteID)); err != nil {
			clientConn.Close()
			targetConn.Close()
			h.logger.Debug("client disconnected")
			if h.stats != nil && lastRemoteID != "" {
				h.stats.RecordError(lastRemoteID)
			}
			return
		}

		if h.stats != nil && remoteID != "" {
			h.stats.RecordRequest(remoteID)
		}

		util.Tunnel(clientConn, targetConn, remoteID, h.stats, h.logger)
		return
	}

	h.logger.Error("CONNECT exhausted retries",
		slog.String("error", lastErr.Error()),
		slog.Int("attempts", maxRetries))
	if h.stats != nil && lastRemoteID != "" {
		h.stats.RecordError(lastRemoteID)
	}
	clientConn.Close()
}

// handleConnectDirect bypasses Mullvad, dials upstream SOCKS5 directly.
func (h *Handler) handleConnectDirect(w http.ResponseWriter, r *http.Request, host string, hij http.Hijacker) {
	upstream := strings.TrimPrefix(h.upstreamSOCKS5, "direct://")
	remoteID := upstream

	clientConn, _, err := hij.Hijack()
	if err != nil {
		h.logger.Debug("client disconnected before hijack", slog.String("error", err.Error()))
		return
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		dialer, err := proxy.SOCKS5("tcp", upstream, nil, &net.Dialer{Timeout: h.timeout})
		if err != nil {
			lastErr = err
			continue
		}

		targetConn, err := dialer.Dial("tcp", host)
		if err != nil {
			h.logger.Debug("direct upstream dial failed, retrying", slog.String("error", err.Error()))
			lastErr = err
			continue
		}

		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			clientConn.Close()
			targetConn.Close()
			h.logger.Debug("client disconnected")
			return
		}

		if h.stats != nil && remoteID != "" {
			h.stats.RecordRequest(remoteID)
		}

		util.Tunnel(clientConn, targetConn, remoteID, h.stats, h.logger)
		return
	}

	h.logger.Error("CONNECT direct exhausted retries",
		slog.String("error", lastErr.Error()),
		slog.Int("attempts", maxRetries))
	if h.stats != nil && remoteID != "" {
		h.stats.RecordError(remoteID)
	}
	clientConn.Close()
}

func (h *Handler) resolveSOCKS5(ctx context.Context, r *http.Request, exclude map[string]bool) (addr, remoteID string, err error) {
	filter := h.baseFilter.Clone()

	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		auth, err := parseProxyAuthHeader(v)
		if err != nil {
			return "", "", fmt.Errorf("invalid Proxy-Authorization: %w", err)
		}
		auth.ApplyTo(&filter)
	}

	isOnline := func(hostname string) bool {
		if exclude[hostname] {
			return false
		}
		if h.stats == nil {
			return true
		}
		health, ok := h.stats.PeekHealth(hostname)
		return !ok || health.Online
	}

	server, err := h.mullvad.GetFilteredServerWithHealth(ctx, filter, isOnline)
	if err == nil {
		if h.stats != nil {
			h.stats.SetRemoteMetadataSync(server.Hostname, server.Hostname, server.Country, server.City)
		}
		return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), server.Hostname, nil
	}

	h.logger.Debug("no healthy server found, falling back to any server", slog.String("error", err.Error()))

	server, err = h.pickFallbackServer(ctx, filter, exclude)
	if err != nil {
		return "", "", err
	}

	if h.stats != nil {
		h.stats.SetRemoteMetadataSync(server.Hostname, server.Hostname, server.Country, server.City)
	}
	return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), server.Hostname, nil
}

// pickFallbackServer picks a random relay when no healthy match exists;
// prefers relays with unknown or healthy state over known-dead ones.
func (h *Handler) pickFallbackServer(ctx context.Context, filter mullvad.Filter, exclude map[string]bool) (mullvad.Server, error) {
	servers, err := h.mullvad.GetFilteredServers(ctx, filter)
	if err != nil {
		return mullvad.Server{}, err
	}

	var preferred, dead []mullvad.Server
	for _, s := range servers {
		if exclude[s.Hostname] {
			continue
		}
		if h.stats == nil {
			preferred = append(preferred, s)
			continue
		}
		if health, ok := h.stats.PeekHealth(s.Hostname); !ok || health.Online {
			preferred = append(preferred, s)
		} else {
			dead = append(dead, s)
		}
	}

	pool := preferred
	if len(pool) == 0 {
		pool = dead
	}
	if len(pool) == 0 {
		return mullvad.Server{}, fmt.Errorf("no servers match filter")
	}
	return pool[rand.IntN(len(pool))], nil
}

func (h *Handler) resolveWithDNS(ctx context.Context, r *http.Request, exclude map[string]bool) (resolvedAddr, remoteID string, err error) {
	socksAddr, rid, err := h.resolveSOCKS5(ctx, r, exclude)
	if err != nil {
		return "", "", err
	}
	resolved, err := h.mullvad.ResolveRelayAddr(ctx, socksAddr)
	if err != nil {
		return "", "", fmt.Errorf("resolve relay %s: %w", socksAddr, err)
	}
	return resolved, rid, nil
}

// parseProxyAuthHeader decodes "Basic <base64>" header into ProxyAuth.
func parseProxyAuthHeader(header string) (*ProxyAuth, error) {
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
	connStr = strings.TrimSuffix(connStr, ":")

	return ParseProxyAuth(connStr)
}

func (h *Handler) getTransport(key string) *http.Transport {
	if tr, ok := h.transportCache.Get(key); ok {
		return tr
	}
	return nil
}

// createAndCacheTransport creates http.Transport with SOCKS5 dialer, caches in LRU.
func (h *Handler) createAndCacheTransport(key string, dialer proxy.Dialer) *http.Transport {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			type result struct {
				conn net.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() {
				conn, err := dialer.Dial(network, addr)
				done <- result{conn, err}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-done:
				return r.conn, r.err
			}
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   100,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	h.transportCache.Set(key, tr)
	return tr
}

const maxBodySize = 10 * 1024 * 1024 // 10MB

var errBodyTooLarge = errors.New("request body too large")

func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBodySize {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// markRemoteUnhealthy records a request-level relay failure. Relay goes
// offline after circuitBreakerStrikes consecutive failures; recovery happens
// via the health checker.
func (h *Handler) markRemoteUnhealthy(remoteID string) {
	if h.stats == nil || remoteID == "" {
		return
	}
	h.stats.RecordRemoteFailure(remoteID, circuitBreakerStrikes)
}

func (h *Handler) logAndRespond(w http.ResponseWriter, remoteID string, err error, markUnhealthy bool) {
	h.logger.Error("proxy request failed", slog.String("error", err.Error()))
	if h.stats != nil && remoteID != "" {
		h.stats.RecordError(remoteID)
		if markUnhealthy {
			h.markRemoteUnhealthy(remoteID)
		}
	}
	http.Error(w, "failed to reach target", http.StatusBadGateway)
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

// isRelayFailure reports whether err is attributed to the relay itself
// (dial/connect to relay failed or relay dropped the connection), as opposed
// to the target rejecting the connection.
func isRelayFailure(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
