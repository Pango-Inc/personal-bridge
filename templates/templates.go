package templates

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

//go:embed templates/*.template.html
var templatesFS embed.FS

var templates *template.Template

func init() {
	var err error
	templates, err = template.New("").Funcs(template.FuncMap{
		"format_time": func(ts time.Time) string {
			tsStr := ts.Format("2006-01-02 15:04:05")
			d := time.Since(ts).Round(time.Second)
			if d > 0 {
				tsStr += fmt.Sprintf(" (%s ago)", d)
			} else {
				tsStr += fmt.Sprintf(" (in %s)", -d)
			}
			return tsStr
		},
	}).ParseFS(templatesFS, "templates/*.template.html")
	if err != nil {
		panic(err)
	}
}

func RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		slog.Error("failed to render template", slog.String("template", name), slog.Any("err", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
