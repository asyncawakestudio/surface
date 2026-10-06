package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithStatic(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>index</html>"), 0o644))
	must(t, os.MkdirAll(filepath.Join(dir, "assets"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o644))

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api"))
	})
	h := WithStatic(apiHandler, dir)

	tests := []struct {
		path, wantBody, wantCache string
	}{
		{"/api/scans", "api", ""},
		{"/healthz", "api", ""},
		{"/", "index", "no-cache"},
		{"/scans/42", "index", "no-cache"},
		{"/assets/app.js", "console.log", "immutable"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.Path = tt.path
			h.ServeHTTP(rec, req)
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
			if !strings.Contains(rec.Header().Get("Cache-Control"), tt.wantCache) {
				t.Fatalf("Cache-Control = %q, want %q", rec.Header().Get("Cache-Control"), tt.wantCache)
			}
		})
	}
}

func TestWithStaticBlocksTraversal(t *testing.T) {
	parent := t.TempDir()
	must(t, os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("top-secret"), 0o644))
	dir := filepath.Join(parent, "public")
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("index"), 0o644))

	h := WithStatic(http.NotFoundHandler(), dir)
	for _, p := range []string{"/../secret.txt", "/assets/../../secret.txt"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = p
		h.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), "top-secret") {
			t.Fatalf("%s served a file outside the static dir", p)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
