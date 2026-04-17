package dashboard

import (
	"encoding/json"
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
			pingI := sorted[i].Health.PingMean
			pingJ := sorted[j].Health.PingMean
			onlineI := sorted[i].Health.Online
			onlineJ := sorted[j].Health.Online
			hasPingI := onlineI && pingI > 0
			hasPingJ := onlineJ && pingJ > 0
			if hasPingI != hasPingJ {
				return hasPingI
			}
			if hasPingI && pingI != pingJ {
				return pingI < pingJ
			}
			cmp = 0
		case "requests":
			if sorted[i].RequestCount.Load() != sorted[j].RequestCount.Load() {
				return sorted[i].RequestCount.Load() < sorted[j].RequestCount.Load()
			}
			cmp = 0
		case "errors":
			if sorted[i].ErrorCount.Load() != sorted[j].ErrorCount.Load() {
				return sorted[i].ErrorCount.Load() < sorted[j].ErrorCount.Load()
			}
			cmp = 0
		case "last_used":
			if !sorted[i].LastUsed.Equal(sorted[j].LastUsed) {
				return sorted[i].LastUsed.Before(sorted[j].LastUsed)
			}
			cmp = 0
		default:
			if sorted[i].RequestCount.Load() != sorted[j].RequestCount.Load() {
				return sorted[i].RequestCount.Load() < sorted[j].RequestCount.Load()
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

func (h *Handler) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	data := Data{
		Aggregated: h.store.GetAggregatedStats(),
	}
	if err := DashboardTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) serveStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agg := h.store.GetAggregatedStats()
	if err := json.NewEncoder(w).Encode(agg); err != nil {
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
