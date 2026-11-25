package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var assets embed.FS

func Handler() http.Handler {
	f, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	if _, err := fs.Stat(f, "index.html"); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Dashboard not built. Run npm install and npm run build in web/, then rebuild Go.", http.StatusServiceUnavailable)
		})
	}
	return http.FileServer(http.FS(f))
}
