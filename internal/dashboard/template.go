package dashboard

import (
	"embed"
	"html/template"
	"time"

	"github.com/praktiskt/mulprox/internal/stats"
	"github.com/praktiskt/mulprox/internal/util"
)

//go:embed templates/*.html
var templatesFS embed.FS

var (
	DashboardTemplate    *template.Template
	ProxiesTableTemplate *template.Template
)

func init() {
	funcs := template.FuncMap{
		"formatBytes":   util.FormatBytesUint,
		"formatLatency": util.FormatLatency,
		"formatTime":    formatTime,
		"latencyClass":  util.LatencyClass,
		"sortIcon":      sortIcon,
	}

	dashboardContent, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		panic(err)
	}
	proxiesContent, err := templatesFS.ReadFile("templates/proxies.html")
	if err != nil {
		panic(err)
	}

	DashboardTemplate = template.Must(template.New("dashboard").Funcs(funcs).Parse(string(dashboardContent)))
	ProxiesTableTemplate = template.Must(template.New("proxies").Funcs(funcs).Parse(string(proxiesContent)))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("15:04:05")
}

func sortIcon(field string, cfg sortConfig) string {
	if cfg.field != field {
		return ""
	}
	if cfg.dir == "asc" {
		return "▲"
	}
	return "▼"
}

type Data struct {
	Aggregated stats.AggregatedStats
}
