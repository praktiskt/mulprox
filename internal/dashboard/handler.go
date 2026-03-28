package dashboard

import (
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
	case "/dashboard/proxies":
		h.serveProxies(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data := Data{
		Aggregated: h.store.GetAggregatedStats(),
		Remotes:    h.store.GetAllRemoteStats(),
	}
	if err := DashboardTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) serveStats(w http.ResponseWriter, r *http.Request) {
	agg := h.store.GetAggregatedStats()
	if err := StatsTemplate.Execute(w, agg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) serveProxies(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	remotes := h.store.GetAllRemoteStats()

	if query == "" {
		var used []*stats.RemoteStats
		for _, r := range remotes {
			if r.RequestCount > 0 {
				used = append(used, r)
			}
		}
		remotes = used
	} else {
		remotes = filterRemotes(remotes, query)
	}

	if err := ProxiesTableTemplate.Execute(w, remotes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func filterRemotes(remotes []*stats.RemoteStats, query string) []*stats.RemoteStats {
	query = strings.ToLower(query)
	var result []*stats.RemoteStats
	for _, r := range remotes {
		if strings.Contains(strings.ToLower(r.Hostname), query) ||
			strings.Contains(strings.ToLower(r.Country), query) ||
			strings.Contains(strings.ToLower(r.City), query) ||
			strings.Contains(strings.ToLower(r.EgressIP), query) {
			result = append(result, r)
		}
	}
	return result
}
