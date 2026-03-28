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
		remotes = sortRemotes(remotes, "hostname", "asc")
	} else if isSearching {
		remotes = filterRemotes(remotes, query)
		remotes = sortRemotes(remotes, "hostname", "asc")
	} else if sortField != "" {
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
		var cmp int
		switch field {
		case "hostname":
			cmp = strings.Compare(sorted[i].Hostname, sorted[j].Hostname)
		case "country":
			cmp = strings.Compare(sorted[i].Country, sorted[j].Country)
		case "city":
			cmp = strings.Compare(sorted[i].City, sorted[j].City)
		case "egress_ip":
			cmp = strings.Compare(sorted[i].EgressIP, sorted[j].EgressIP)
		case "status":
			if sorted[i].Health.Online != sorted[j].Health.Online {
				return sorted[i].Health.Online && !sorted[j].Health.Online
			}
			cmp = 0
		case "latency":
			if sorted[i].Health.PingMean != sorted[j].Health.PingMean {
				return sorted[i].Health.PingMean < sorted[j].Health.PingMean
			}
			cmp = 0
		case "requests":
			if sorted[i].RequestCount != sorted[j].RequestCount {
				return sorted[i].RequestCount < sorted[j].RequestCount
			}
			cmp = 0
		case "errors":
			if sorted[i].ErrorCount != sorted[j].ErrorCount {
				return sorted[i].ErrorCount < sorted[j].ErrorCount
			}
			cmp = 0
		case "last_used":
			if !sorted[i].LastUsed.Equal(sorted[j].LastUsed) {
				return sorted[i].LastUsed.Before(sorted[j].LastUsed)
			}
			cmp = 0
		default:
			if sorted[i].RequestCount != sorted[j].RequestCount {
				return sorted[i].RequestCount < sorted[j].RequestCount
			}
			cmp = 0
		}
		if cmp == 0 {
			cmp = strings.Compare(sorted[i].Hostname, sorted[j].Hostname)
		}
		return cmp < 0
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
