package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/praktiskt/mulprox/internal/mullvad"
	"golang.org/x/net/proxy"
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
	socksAddr, err := h.mullvad.RandomSOCKS5Addr()
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
	req.Header = r.Header.Clone()

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

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	dialer, err := h.mullvad.SOCKS5Dialer(ctx, h.timeout)
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
