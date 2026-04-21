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
	less := func(i, j int) bool {
		var cmp int
		switch field {
		case "hostname":
			cmp = strings.Compare(remotes[i].Hostname, remotes[j].Hostname)
		case "country":
			cmp = strings.Compare(remotes[i].Country, remotes[j].Country)
		case "city":
			cmp = strings.Compare(remotes[i].City, remotes[j].City)
		case "egress_ip":
			cmp = strings.Compare(remotes[i].EgressIP, remotes[j].EgressIP)
		case "status":
			if remotes[i].Health.Online != remotes[j].Health.Online {
				return remotes[i].Health.Online && !remotes[j].Health.Online
			}
			cmp = 0
		case "latency":
			ingI := remotes[i].Health.PingMean
			ingJ := remotes[j].Health.PingMean
			onlineI := remotes[i].Health.Online
			onlineJ := remotes[j].Health.Online
			hasPingI := onlineI && ingI > 0
			hasPingJ := onlineJ && ingJ > 0
			if hasPingI != hasPingJ {
				return hasPingI
			}
			if hasPingI && ingI != ingJ {
				return ingI < ingJ
			}
			cmp = 0
		case "requests":
			if remotes[i].RequestCount.Load() != remotes[j].RequestCount.Load() {
				return remotes[i].RequestCount.Load() < remotes[j].RequestCount.Load()
			}
			cmp = 0
		case "errors":
			if remotes[i].ErrorCount.Load() != remotes[j].ErrorCount.Load() {
				return remotes[i].ErrorCount.Load() < remotes[j].ErrorCount.Load()
			}
			cmp = 0
		case "last_used":
			if !remotes[i].LastUsed.Equal(remotes[j].LastUsed) {
				return remotes[i].LastUsed.Before(remotes[j].LastUsed)
			}
			cmp = 0
		default:
			if remotes[i].RequestCount.Load() != remotes[j].RequestCount.Load() {
				return remotes[i].RequestCount.Load() < remotes[j].RequestCount.Load()
			}
			cmp = 0
		}
		if cmp == 0 {
			cmp = strings.Compare(remotes[i].Hostname, remotes[j].Hostname)
		}
		return cmp < 0
	}

	if dir == "asc" {
		sort.Slice(remotes, func(i, j int) bool { return less(i, j) })
	} else {
		sort.Slice(remotes, func(i, j int) bool { return less(j, i) })
	}

	return remotes
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
