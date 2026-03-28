package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"golang.org/x/net/proxy"
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
		return make([]byte, 32*1024)
	},
}

type Handler struct {
	logger    *slog.Logger
	timeout   time.Duration
	mullvad   *mullvad.Provider
	httpsOnly bool
}

func New(logger *slog.Logger, timeout time.Duration, mullvad *mullvad.Provider, httpsOnly bool) *Handler {
	return &Handler{
		logger:    logger,
		timeout:   timeout,
		mullvad:   mullvad,
		httpsOnly: httpsOnly,
	}
}

func (h *Handler) getTransport(socksDialer proxy.Dialer) *http.Transport {
	t := transportPool.Get().(*http.Transport)
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socksDialer.Dial(network, addr)
	}
	t.TLSHandshakeTimeout = h.timeout
	t.DisableKeepAlives = false
	t.MaxIdleConnsPerHost = 4
	return t
}

func (h *Handler) putTransport(t *http.Transport) {
	t.DialContext = nil
	transportPool.Put(t)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.httpsOnly && r.Method != http.MethodConnect {
		http.Error(w, "HTTPS only", http.StatusForbidden)
		return
	}

	h.logger.Debug("request", slog.String("method", r.Method), slog.String("url", r.URL.String()), slog.String("host", r.Host))

	if r.Method == http.MethodConnect {
		h.handleConnectHTTP(w, r)
		return
	}

	h.handleHTTP(w, r)
}

func (h *Handler) getSOCKS5AddrFromRequest(r *http.Request) (string, error) {
	filter := mullvad.Filter{}

	// Parse Proxy-Authorization header (JSON)
	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		var auth ProxyAuth
		if err := json.Unmarshal([]byte(v), &auth); err != nil {
			return "", fmt.Errorf("invalid Proxy-Authorization JSON: %w", err)
		}
		auth.Apply(&filter)
	}

	if filter.Country == "" && filter.City == "" && filter.Owned == nil &&
		filter.Provider == "" && filter.MinSpeed == 0 && !filter.Multihop && filter.Seed == 0 {
		return h.mullvad.RandomSOCKS5Addr()
	}

	server, err := h.mullvad.GetFilteredServer(filter)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", server.SOCKS5, server.SOCKSPort), nil
}

func (h *Handler) copyResponseBody(w http.ResponseWriter, body io.Reader) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(w, body, buf)
}

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()

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

	h.proxyRequestHTTP(ctx, w, r, targetURL)
}

func (h *Handler) proxyRequestHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string) {
	socksAddr, err := h.getSOCKS5AddrFromRequest(r)
	if err != nil {
		h.logger.Error("failed to get Mullvad server", slog.String("error", err.Error()))
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		h.logger.Error("failed to create SOCKS5 dialer", slog.String("error", err.Error()))
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	transport := h.getTransport(socksDialer)
	defer h.putTransport(transport)

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		h.logger.Error("failed to create request", slog.String("error", err.Error()))
		http.Error(w, "failed to create request", http.StatusBadRequest)
		return
	}
	for key, values := range r.Header {
		req.Header[key] = values
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		h.logger.Error("failed to proxy request", slog.String("error", err.Error()))
		http.Error(w, "failed to reach target", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	h.copyResponseBody(w, resp.Body)
}

func (h *Handler) handleConnectHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	h.logger.Debug("handling CONNECT", slog.String("host", host))

	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	socksAddr, err := h.getSOCKS5AddrFromRequest(r)
	if err != nil {
		h.logger.Error("failed to get Mullvad server", slog.String("error", err.Error()))
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	dialer, err := h.mullvad.SOCKS5DialerFromAddr(socksAddr, h.timeout)
	if err != nil {
		h.logger.Error("failed to create Mullvad session", slog.String("error", err.Error()))
		http.Error(w, "failed to create proxy session", http.StatusServiceUnavailable)
		return
	}

	targetConn, err := dialer.Dial("tcp", host)
	if err != nil {
		h.logger.Error("failed to connect to target", slog.String("error", err.Error()))
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.Header().Set("Connection", "Keep-Alive")
	w.WriteHeader(http.StatusOK)

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
