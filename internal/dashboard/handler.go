package dashboard

import (
	"bytes"
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

	var buf bytes.Buffer
	if err := ProxiesTableTemplate.Execute(&buf, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func compareRemotes(a, b *stats.RemoteStats, field string) int {
	switch field {
	case "hostname":
		return strings.Compare(a.Hostname, b.Hostname)
	case "country":
		return strings.Compare(a.Country, b.Country)
	case "city":
		return strings.Compare(a.City, b.City)
	case "egress_ip":
		return strings.Compare(a.EgressIP, b.EgressIP)
	case "status":
		if a.Health.Online != b.Health.Online {
			if a.Health.Online {
				return -1
			}
			return 1
		}
		return 0
	case "latency":
		ingA := a.Health.PingMean
		ingB := b.Health.PingMean
		onlineA := a.Health.Online
		onlineB := b.Health.Online
		hasPingA := onlineA && ingA > 0
		hasPingB := onlineB && ingB > 0
		if hasPingA != hasPingB {
			if hasPingA {
				return -1
			}
			return 1
		}
		if hasPingA {
			if ingA < ingB {
				return -1
			}
			if ingA > ingB {
				return 1
			}
		}
		return 0
	case "requests":
		ra := a.RequestCount.Load()
		rb := b.RequestCount.Load()
		if ra < rb {
			return -1
		}
		if ra > rb {
			return 1
		}
		return 0
	case "errors":
		ea := a.ErrorCount.Load()
		eb := b.ErrorCount.Load()
		if ea < eb {
			return -1
		}
		if ea > eb {
			return 1
		}
		return 0
	case "last_used":
		if a.LastUsed.Before(b.LastUsed) {
			return -1
		}
		if a.LastUsed.After(b.LastUsed) {
			return 1
		}
		return 0
	default:
		ra := a.RequestCount.Load()
		rb := b.RequestCount.Load()
		if ra < rb {
			return -1
		}
		if ra > rb {
			return 1
		}
		return 0
	}
}

func sortRemotes(remotes []*stats.RemoteStats, field, dir string) []*stats.RemoteStats {
	less := func(i, j int) bool {
		cmp := compareRemotes(remotes[i], remotes[j], field)
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
	var buf bytes.Buffer
	if err := DashboardTemplate.Execute(&buf, data); err != nil {
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
