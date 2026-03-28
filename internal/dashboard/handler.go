package dashboard

import (
	"net/http"
	"sort"
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

type sortConfig struct {
	field string
	dir   string
}

func (h *Handler) serveProxies(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	sortField := r.URL.Query().Get("sort")
	sortDir := r.URL.Query().Get("dir")

	if sortDir == "" {
		sortDir = "desc"
	}

	remotes := h.store.GetAllRemoteStats()

	isSorting := sortField != ""
	isSearching := query != ""

	if !isSorting && !isSearching {
		var used []*stats.RemoteStats
		for _, r := range remotes {
			if r.RequestCount > 0 {
				used = append(used, r)
			}
		}
		remotes = used
	} else if isSearching {
		remotes = filterRemotes(remotes, query)
	}

	if sortField != "" {
		remotes = sortRemotes(remotes, sortField, sortDir)
	}

	data := ProxiesData{
		Remotes:   remotes,
		Sort:      sortConfig{field: sortField, dir: sortDir},
		Query:     query,
		IsSorting: isSorting,
	}

	ProxiesTableTemplate.Execute(w, data)
}

func sortRemotes(remotes []*stats.RemoteStats, field, dir string) []*stats.RemoteStats {
	sorted := make([]*stats.RemoteStats, len(remotes))
	copy(sorted, remotes)

	less := func(i, j int) bool {
		switch field {
		case "hostname":
			return sorted[i].Hostname < sorted[j].Hostname
		case "country":
			return sorted[i].Country < sorted[j].Country
		case "city":
			return sorted[i].City < sorted[j].City
		case "egress_ip":
			return sorted[i].EgressIP < sorted[j].EgressIP
		case "status":
			return sorted[i].Health.Online && !sorted[j].Health.Online
		case "latency":
			return sorted[i].Health.PingMean < sorted[j].Health.PingMean
		case "requests":
			return sorted[i].RequestCount < sorted[j].RequestCount
		case "errors":
			return sorted[i].ErrorCount < sorted[j].ErrorCount
		case "last_used":
			return sorted[i].LastUsed.Before(sorted[j].LastUsed)
		default:
			return sorted[i].RequestCount < sorted[j].RequestCount
		}
	}

	if dir == "asc" {
		sort.Slice(sorted, func(i, j int) bool { return less(i, j) })
	} else {
		sort.Slice(sorted, func(i, j int) bool { return less(j, i) })
	}

	return sorted
}

func (h *Handler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data := Data{
		Aggregated: h.store.GetAggregatedStats(),
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

type ProxiesData struct {
	Remotes   []*stats.RemoteStats
	Sort      sortConfig
	Query     string
	IsSorting bool
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
