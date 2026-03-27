package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"golang.org/x/net/proxy"
)

const (
	HeaderCountry  = "X-Mulprox-Country"
	HeaderCity     = "X-Mulprox-City"
	HeaderSeed     = "X-Mulprox-Seed"
	HeaderOwned    = "X-Mulprox-Owned"
	HeaderProvider = "X-Mulprox-Provider"
	HeaderMinSpeed = "X-Mulprox-Speed"
	HeaderMultihop = "X-Mulprox-Multihop"
)

type Handler struct {
	logger  *slog.Logger
	timeout time.Duration
	mullvad *mullvad.Provider
}

func New(logger *slog.Logger, timeout time.Duration) *Handler {
	return &Handler{
		logger:  logger,
		timeout: timeout,
		mullvad: mullvad.New(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("request", slog.String("method", r.Method), slog.String("url", r.URL.String()), slog.String("host", r.Host))

	if r.Method == http.MethodConnect {
		h.handleConnectHTTP(w, r)
		return
	}

	h.handleHTTP(w, r)
}

func (h *Handler) getSOCKS5AddrFromRequest(r *http.Request) (string, error) {
	filter := mullvad.Filter{}

	if v := r.Header.Get(HeaderCountry); v != "" {
		filter.Country = v
	}
	if v := r.Header.Get(HeaderCity); v != "" {
		filter.City = v
	}
	if v := r.Header.Get(HeaderSeed); v != "" {
		seed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid seed: %w", err)
		}
		filter.Seed = seed
	}
	if v := r.Header.Get(HeaderOwned); v != "" {
		owned := strings.ToLower(v) == "true"
		filter.Owned = &owned
	}
	if v := r.Header.Get(HeaderProvider); v != "" {
		filter.Provider = v
	}
	if v := r.Header.Get(HeaderMinSpeed); v != "" {
		speed, err := strconv.Atoi(v)
		if err != nil {
			return "", fmt.Errorf("invalid speed: %w", err)
		}
		filter.MinSpeed = speed
	}
	if v := r.Header.Get(HeaderMultihop); v != "" {
		filter.Multihop = strings.ToLower(v) == "true"
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

func (h *Handler) stripProxyHeaders(headers http.Header) http.Header {
	prefix := "X-Mulprox-"
	for key := range headers {
		if strings.HasPrefix(key, prefix) {
			headers.Del(key)
		}
	}
	return headers
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

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		},
		TLSHandshakeTimeout: h.timeout,
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		h.logger.Error("failed to create request", slog.String("error", err.Error()))
		http.Error(w, "failed to create request", http.StatusBadRequest)
		return
	}
	req.Header = h.stripProxyHeaders(r.Header.Clone())

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
	io.Copy(w, resp.Body)
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
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, clientConn)
		targetConn.Close()
		errc <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, targetConn)
		clientConn.Close()
		errc <- err
	}()

	<-errc
}
