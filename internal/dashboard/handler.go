package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/praktiskt/mulprox/internal/stats"
)

type Handler struct {
	store stats.Store
}

func New(store stats.Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	path = strings.TrimSuffix(path, "/")

	switch path {
	case "/dashboard":
		h.serveDashboard(w, r)
	case "/dashboard/stats":
		h.serveStats(w, r)
	case "/dashboard/stream":
		h.serveStream(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	var buf bytes.Buffer
	if err := DashboardTemplate.Execute(&buf, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (h *Handler) serveStats(w http.ResponseWriter, _ *http.Request) {
	agg := h.store.GetAggregatedStats()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(agg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (h *Handler) serveStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	enc := json.NewEncoder(w)

	// send initial state immediately
	snap := h.store.MakeSnapshot()
	writeSSE(w, enc, "stats", snap.Aggregated)
	writeSSE(w, enc, "proxies", snap.Proxies)
	flusher.Flush()

	// subscribe to ticker updates
	ch, err := h.store.Subscribe(r.Context())
	if err != nil {
		return
	}

	for snap := range ch {
		writeSSE(w, enc, "stats", snap.Aggregated)
		writeSSE(w, enc, "proxies", snap.Proxies)
		flusher.Flush()
	}
}

func writeSSE(w io.Writer, enc *json.Encoder, event string, data any) {
	io.WriteString(w, "event: ")
	io.WriteString(w, event)
	io.WriteString(w, "\ndata: ")
	enc.Encode(data)
	io.WriteString(w, "\n\n")
}
