package health

import (
	"encoding/json"
	"net/http"

	"github.com/praktiskt/mulprox/internal/stats"
)

const livezResponse = `{"status":"ok"}` + "\n"

type Handler struct {
	store stats.Store
}

func New(store stats.Store) *Handler {
	return &Handler{store: store}
}

func (*Handler) Livez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(livezResponse)); err != nil {
		_ = err
	}
}

type readyzResp struct {
	Status        string `json:"status"`
	ActiveRemotes int    `json:"active_remotes"`
	OnlineRemotes int    `json:"online_remotes"`
	TotalRemotes  int    `json:"total_remotes"`
}

func (h *Handler) Readyz(w http.ResponseWriter, _ *http.Request) {
	agg := h.store.GetAggregatedStats()

	w.Header().Set("Content-Type", "application/json")

	resp := readyzResp{
		ActiveRemotes: agg.ActiveRemotes,
		OnlineRemotes: agg.OnlineRemotes,
		TotalRemotes:  agg.TotalRemotes,
	}

	if agg.OnlineRemotes >= 1 {
		resp.Status = "ok"
		w.WriteHeader(http.StatusOK)
	} else {
		resp.Status = "not_ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		_ = err
	}
}
