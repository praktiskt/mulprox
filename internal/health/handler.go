package health

import (
	"encoding/json"
	"net/http"

	"github.com/praktiskt/mulprox/internal/stats"
)

type Handler struct {
	store stats.Store
}

func New(store stats.Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) Livez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	agg := h.store.GetAggregatedStats()

	w.Header().Set("Content-Type", "application/json")

	resp := map[string]any{
		"active_remotes": agg.ActiveRemotes,
		"online_remotes": agg.OnlineRemotes,
		"total_remotes":  agg.TotalRemotes,
	}

	if agg.OnlineRemotes >= 1 {
		resp["status"] = "ok"
		w.WriteHeader(http.StatusOK)
	} else {
		resp["status"] = "not_ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(resp)
}
