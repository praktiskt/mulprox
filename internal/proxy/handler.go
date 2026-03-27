package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/praktiskt/mulprox/internal/mullvad"
	"github.com/sardanioss/httpcloak/client"
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

func (h *Handler) HandleRequest(c *gin.Context) {
	targetURL := c.Request.URL.String()

	if targetURL == "/" && c.Request.Method == http.MethodGet {
		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, "Mullvad Proxy Server\nUsage: Set HTTP_PROXY environment variable to point to this server")
		return
	}

	targetURL = strings.TrimPrefix(targetURL, "/")

	if targetURL == "" {
		targetURL = "/"
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	h.logger.Debug("proxying request", slog.String("url", targetURL), slog.String("method", c.Request.Method))

	ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
	defer cancel()

	h.proxyRequest(ctx, c, targetURL)
}

func (h *Handler) proxyRequest(ctx context.Context, c *gin.Context, targetURL string) {
	cclient, err := h.mullvad.Session(ctx, h.timeout)
	if err != nil {
		h.logger.Error("failed to create Mullvad session", slog.String("error", err.Error()))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to create proxy session"})
		return
	}
	defer cclient.Close()

	headers := make(map[string][]string)
	for key, values := range c.Request.Header {
		headers[key] = values
	}

	if _, ok := headers["User-Agent"]; !ok {
		headers["User-Agent"] = []string{"mulprox/1.0"}
	}

	req := &client.Request{
		Method:  c.Request.Method,
		URL:     targetURL,
		Headers: headers,
	}

	resp, err := cclient.Do(ctx, req)
	if err != nil {
		h.logger.Error("failed to proxy request", slog.String("error", err.Error()))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to reach target"})
		return
	}
	defer resp.Close()

	for key, values := range resp.Headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	c.Status(resp.StatusCode)

	if c.Request.Body != nil {
		c.Request.Body.Close()
	}
}
