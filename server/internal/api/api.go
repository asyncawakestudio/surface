// Package api exposes the scanner over HTTP.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"surface/internal/asm"
	"surface/internal/store"
)

// Scanner is the attack surface pipeline (implemented by *asm.Scanner).
type Scanner interface {
	Run(ctx context.Context, domain string, progress asm.ProgressFunc) (*asm.Result, error)
}

// Store is the persistence layer (implemented by *store.Store).
type Store interface {
	Ping(ctx context.Context) error
	CreateScan(ctx context.Context, domain string) (*store.Scan, error)
	MarkRunning(ctx context.Context, id int64) error
	SetStage(ctx context.Context, id int64, stage string) error
	MarkFailed(ctx context.Context, id int64, msg string) error
	SaveResult(ctx context.Context, id int64, res *asm.Result) error
	ListScans(ctx context.Context, limit int) ([]store.Scan, error)
	GetScan(ctx context.Context, id int64) (*store.ScanDetail, error)
	DeleteScan(ctx context.Context, id int64) error
}

type API struct {
	store  Store
	jobs   *Jobs
	logger *slog.Logger
}

func New(st Store, jobs *Jobs, logger *slog.Logger) *API {
	return &API{store: st, jobs: jobs, logger: logger}
}

// Handler returns the routed HTTP handler.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /api/scans", a.createScan)
	mux.HandleFunc("GET /api/scans", a.listScans)
	mux.HandleFunc("GET /api/scans/{id}", a.getScan)
	mux.HandleFunc("DELETE /api/scans/{id}", a.deleteScan)
	return logRequests(a.logger, mux)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createScanRequest struct {
	Domain string `json:"domain"`
}

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	domain, err := asm.NormalizeDomain(req.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}

	scan, err := a.store.CreateScan(r.Context(), domain)
	if err != nil {
		a.internalError(w, "create scan", err)
		return
	}
	a.jobs.Submit(scan.ID, domain)
	writeJSON(w, http.StatusAccepted, scan)
}

func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	scans, err := a.store.ListScans(r.Context(), limit)
	if err != nil {
		a.internalError(w, "list scans", err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	scan, err := a.store.GetScan(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		a.internalError(w, "get scan", err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (a *API) deleteScan(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if a.jobs.Active(id) {
		writeError(w, http.StatusConflict, "scan is still running")
		return
	}
	err := a.store.DeleteScan(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		a.internalError(w, "delete scan", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) internalError(w http.ResponseWriter, op string, err error) {
	a.logger.Error(op, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid scan id")
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
		)
	})
}
