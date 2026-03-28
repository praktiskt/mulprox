package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"time"

	"github.com/praktiskt/mulprox/internal/stats"
)

//go:embed templates/*.html
var templatesFS embed.FS

var DashboardTemplate *template.Template
var StatsTemplate *template.Template
var ProxiesTableTemplate *template.Template

func init() {
	funcs := template.FuncMap{
		"formatBytes":   formatBytes,
		"formatLatency": formatLatency,
		"formatTime":    formatTime,
		"latencyClass":  latencyClass,
	}

	dashboardContent, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		panic(err)
	}
	statsContent, err := templatesFS.ReadFile("templates/stats.html")
	if err != nil {
		panic(err)
	}
	proxiesContent, err := templatesFS.ReadFile("templates/proxies.html")
	if err != nil {
		panic(err)
	}

	DashboardTemplate = template.Must(template.New("dashboard").Funcs(funcs).Parse(string(dashboardContent)))
	StatsTemplate = template.Must(template.New("stats").Funcs(funcs).Parse(string(statsContent)))
	ProxiesTableTemplate = template.Must(template.New("proxies").Funcs(funcs).Parse(string(proxiesContent)))
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatLatency(ms float64) string {
	if ms < 1 {
		return "—"
	}
	return fmt.Sprintf("%.0fms", ms)
}

func latencyClass(ms float64) string {
	if ms < 0 {
		return ""
	}
	if ms < 100 {
		return "latency-good"
	}
	if ms < 300 {
		return "latency-ok"
	}
	return "latency-bad"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("15:04:05")
}

type Data struct {
	Aggregated stats.AggregatedStats
	Remotes    []*stats.RemoteStats
	Query      string
}
