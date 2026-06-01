package dashboard

import (
	"embed"
	"html/template"
)

//go:embed templates/dashboard.html
var templatesFS embed.FS

var DashboardTemplate *template.Template

func init() {
	dashboardContent, err := templatesFS.ReadFile("templates/dashboard.html")
	if err != nil {
		panic(err)
	}

	DashboardTemplate = template.Must(template.New("dashboard").Parse(string(dashboardContent)))
}
