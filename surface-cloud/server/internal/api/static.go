package api

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// WithStatic serves the built client from dir for every request that isn't
// an API route. Unknown paths fall back to index.html so client-side routing
// works.
func WithStatic(apiHandler http.Handler, dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	index := filepath.Join(dir, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			apiHandler.ServeHTTP(w, r)
			return
		}

		p := path.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err == nil && !info.IsDir() {
			if strings.HasPrefix(p, "/assets/") {
				// Vite fingerprints everything under assets/.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	})
}
