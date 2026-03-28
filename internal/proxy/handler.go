package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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
	"golang.org/x/net/proxy"
)

const (
	maxRetries  = 3
	copyBufSize = 32 * 1024
)

type ProxyAuth struct {
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Seed     int64  `json:"seed,omitempty"`
	Owned    *bool  `json:"owned,omitempty"`
	Provider string `json:"provider,omitempty"`
	MinSpeed int    `json:"speed,omitempty"`
	Multihop bool   `json:"multihop,omitempty"`
}

func (p *ProxyAuth) Apply(filter *mullvad.Filter) {
	if p.Country != "" {
		filter.Country = p.Country
	}
	if p.City != "" {
		filter.City = p.City
	}
	if p.Seed != 0 {
		filter.Seed = p.Seed
	}
	if p.Owned != nil {
		filter.Owned = p.Owned
	}
	if p.Provider != "" {
		filter.Provider = p.Provider
	}
	if p.MinSpeed > 0 {
		filter.MinSpeed = p.MinSpeed
	}
	if p.Multihop {
		filter.Multihop = p.Multihop
	}
}

var transportPool = sync.Pool{
	New: func() interface{} {
		return &http.Transport{}
	},
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, copyBufSize)
	},
}

type Handler struct {
	logger    *slog.Logger
	timeout   time.Duration
	mullvad   *mullvad.Provider
	httpsOnly bool
	stats     stats.Store
}

func New(logger *slog.Logger, timeout time.Duration, mullvad *mullvad.Provider, httpsOnly bool, statsStore stats.Store) *Handler {
	return &Handler{
		logger:    logger,
		timeout:   timeout,
		mullvad:   mullvad,
		httpsOnly: httpsOnly,
		stats:     statsStore,
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

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	h.proxyHTTP(ctx, w, r, targetURL)
}

// proxyHTTP performs the HTTP proxy request with retries on transient errors.
func (h *Handler) proxyHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string) {
	body, err := h.readBody(r)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, remoteID, err := h.roundTrip(ctx, r, targetURL, body)
		if err != nil {
			if ctx.Err() != nil {
				return // context canceled or timed out; client already gone
			}
			if !isRetryable(err) {
				h.logAndRespond(w, remoteID, err)
				return
			}
			lastErr = err
			continue
		}

		defer resp.Body.Close()
		h.writeResponse(w, resp, remoteID)
		return
	}

	if ctx.Err() != nil {
		return
	}
	h.logger.Error("proxy request exhausted retries",
		slog.String("error", lastErr.Error()),
		slog.Int("attempts", maxRetries))
	http.Error(w, "failed to reach target", http.StatusBadGateway)
}

// roundTrip performs a single proxy attempt: resolves a SOCKS5 server, builds
// a transport, and executes the request.
func (h *Handler) roundTrip(ctx context.Context, r *http.Request, targetURL string, body []byte) (*http.Response, string, error) {
	socksAddr, remoteID, err := h.resolveSOCKS5(r)
	if err != nil {
		return nil, "", err
	}

	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, remoteID, err
	}

	tr := h.getTransport(socksDialer)
	defer h.putTransport(tr)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, reqBody)
	if err != nil {
		return nil, remoteID, err
	}
	for key, values := range r.Header {
		req.Header[key] = values
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, remoteID, err
	}
	return resp, remoteID, nil
}

// writeResponse copies the upstream response to the client and records stats.
func (h *Handler) writeResponse(w http.ResponseWriter, resp *http.Response, remoteID string) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if h.stats != nil && remoteID != "" {
		h.stats.RecordRequest(remoteID)
	}

	n, _ := io.Copy(w, resp.Body)
	if h.stats != nil && remoteID != "" && n > 0 {
		h.stats.RecordBytes(remoteID, 0, n)
	}
}

// handleConnect handles CONNECT requests by tunneling bytes between client
// and the upstream SOCKS5 target.
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

	socksAddr, remoteID, err := h.resolveSOCKS5(r)
	if err != nil {
		h.logger.Error("failed to get Mullvad server", slog.String("error", err.Error()))
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	dialer, err := h.mullvad.SOCKS5DialerFromAddr(socksAddr, h.timeout)
	if err != nil {
		h.logger.Error("failed to create Mullvad session", slog.String("error", err.Error()))
		if h.stats != nil && remoteID != "" {
			h.stats.RecordError(remoteID)
		}
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	targetConn, err := dialer.Dial("tcp", host)
	if err != nil {
		h.logger.Error("failed to connect to target", slog.String("error", err.Error()))
		if h.stats != nil && remoteID != "" {
			h.stats.RecordError(remoteID)
		}
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.Header().Set("Connection", "Keep-Alive")
	w.WriteHeader(http.StatusOK)

	if h.stats != nil && remoteID != "" {
		h.stats.RecordRequest(remoteID)
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hij.Hijack()
	if err != nil {
		h.logger.Error("failed to hijack connection", slog.String("error", err.Error()))
		return
	}

	h.tunnel(clientConn, targetConn)
}

// tunnel copies data bidirectionally between client and target connections.
func (h *Handler) tunnel(clientConn, targetConn net.Conn) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	errc := make(chan error, 2)

	go func() {
		_, err := io.CopyBuffer(targetConn, clientConn, buf)
		targetConn.Close()
		errc <- err
	}()

	go func() {
		_, err := io.CopyBuffer(clientConn, targetConn, buf)
		clientConn.Close()
		errc <- err
	}()

	<-errc
}

// resolveSOCKS5 picks a Mullvad SOCKS5 server based on the request's
// Proxy-Authorization header and returns its address and identifier.
func (h *Handler) resolveSOCKS5(r *http.Request) (addr, remoteID string, err error) {
	filter := mullvad.Filter{}

	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		var auth ProxyAuth
		if err := json.Unmarshal([]byte(v), &auth); err != nil {
			return "", "", fmt.Errorf("invalid Proxy-Authorization JSON: %w", err)
		}
		auth.Apply(&filter)
	}

	server, err := h.mullvad.GetFilteredServer(filter)
	if err != nil {
		return "", "", err
	}

	if h.stats != nil {
		h.stats.SetRemoteMetadata(server.Hostname, server.Hostname, server.Country, server.City)
	}

	return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), server.Hostname, nil
}

// getTransport returns a pooled http.Transport configured to dial through the
// given SOCKS5 proxy. Connections are not reused (DisableKeepAlives) so each
// request gets a fresh tunnel.
func (h *Handler) getTransport(dialer proxy.Dialer) *http.Transport {
	t := transportPool.Get().(*http.Transport)
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
	t.TLSHandshakeTimeout = h.timeout
	t.DisableKeepAlives = true
	return t
}

// putTransport flushes idle connections and returns the transport to the pool.
func (h *Handler) putTransport(t *http.Transport) {
	t.CloseIdleConnections()
	t.DialContext = nil
	transportPool.Put(t)
}

// readBody buffers the request body so it can be replayed across retries.
func (h *Handler) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(r.Body)
}

// logAndRespond logs a proxy error, records stats, and writes a 502 response.
func (h *Handler) logAndRespond(w http.ResponseWriter, remoteID string, err error) {
	h.logger.Error("proxy request failed", slog.String("error", err.Error()))
	if h.stats != nil && remoteID != "" {
		h.stats.RecordError(remoteID)
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
	return false
}
