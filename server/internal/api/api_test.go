package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"surface/internal/asm"
	"surface/internal/store"
)

type fakeStore struct {
	mu     sync.Mutex
	nextID int64
	scans  map[int64]*store.ScanDetail
}

func newFakeStore() *fakeStore {
	return &fakeStore{scans: map[int64]*store.ScanDetail{}}
}

func (f *fakeStore) Ping(context.Context) error { return nil }

func (f *fakeStore) CreateScan(_ context.Context, domain string) (*store.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	sc := store.Scan{ID: f.nextID, Domain: domain, Status: store.StatusQueued, CreatedAt: time.Now()}
	f.scans[sc.ID] = &store.ScanDetail{Scan: sc}
	return &sc, nil
}

func (f *fakeStore) update(id int64, fn func(*store.ScanDetail)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.scans[id]
	if !ok {
		return store.ErrNotFound
	}
	fn(d)
	return nil
}

func (f *fakeStore) MarkRunning(_ context.Context, id int64) error {
	return f.update(id, func(d *store.ScanDetail) { d.Status = store.StatusRunning })
}

func (f *fakeStore) SetStage(_ context.Context, id int64, stage string) error {
	return f.update(id, func(d *store.ScanDetail) { d.Stage = &stage })
}

func (f *fakeStore) MarkFailed(_ context.Context, id int64, msg string) error {
	return f.update(id, func(d *store.ScanDetail) { d.Status = store.StatusFailed; d.Error = &msg })
}

func (f *fakeStore) SaveResult(_ context.Context, id int64, res *asm.Result) error {
	return f.update(id, func(d *store.ScanDetail) {
		d.Status = store.StatusCompleted
		d.Subdomains, d.DNSRecords, d.TLSCerts = res.Subdomains, res.DNSRecords, res.TLSCerts
	})
}

func (f *fakeStore) ListScans(context.Context, int) ([]store.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.Scan{}
	for _, d := range f.scans {
		out = append(out, d.Scan)
	}
	return out, nil
}

func (f *fakeStore) GetScan(_ context.Context, id int64) (*store.ScanDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.scans[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (f *fakeStore) DeleteScan(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.scans[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.scans, id)
	return nil
}

type fakeScanner struct {
	err error
}

func (f fakeScanner) Run(_ context.Context, domain string, progress asm.ProgressFunc) (*asm.Result, error) {
	progress(asm.StageSubdomains)
	if f.err != nil {
		return nil, f.err
	}
	return &asm.Result{
		Domain:     domain,
		Subdomains: []asm.Subdomain{{Host: "www." + domain, Sources: []string{"crtsh"}}},
		DNSRecords: []asm.DNSRecord{{Host: "www." + domain, Type: "A", Value: "192.0.2.1"}},
	}, nil
}

func newTestAPI(t *testing.T, sc Scanner) (*fakeStore, *Jobs, http.Handler) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := newFakeStore()
	jobs := NewJobs(st, sc, logger, 2, time.Minute)
	t.Cleanup(jobs.Shutdown)
	return st, jobs, New(st, jobs, logger).Handler()
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestCreateScanRunsToCompletion(t *testing.T) {
	st, jobs, h := newTestAPI(t, fakeScanner{})

	rec := do(h, http.MethodPost, "/api/scans", `{"domain":"https://Example.com/"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var created store.Scan
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Domain != "example.com" {
		t.Fatalf("domain = %q, want normalized example.com", created.Domain)
	}

	jobs.wg.Wait()

	d, _ := st.GetScan(context.Background(), created.ID)
	if d.Status != store.StatusCompleted || len(d.Subdomains) != 1 {
		t.Fatalf("scan = %+v, want completed with 1 subdomain", d)
	}

	rec = do(h, http.MethodGet, "/api/scans/1", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "www.example.com") {
		t.Fatalf("get: status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestScanFailureIsRecorded(t *testing.T) {
	st, jobs, h := newTestAPI(t, fakeScanner{err: errors.New("boom")})

	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()

	d, _ := st.GetScan(context.Background(), 1)
	if d.Status != store.StatusFailed || d.Error == nil || *d.Error != "boom" {
		t.Fatalf("scan = %+v, want failed with error boom", d.Scan)
	}
}

func TestValidation(t *testing.T) {
	_, _, h := newTestAPI(t, fakeScanner{})

	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"bad json", http.MethodPost, "/api/scans", `{`, http.StatusBadRequest},
		{"bad domain", http.MethodPost, "/api/scans", `{"domain":"not a domain"}`, http.StatusBadRequest},
		{"bad id", http.MethodGet, "/api/scans/abc", "", http.StatusBadRequest},
		{"missing scan", http.MethodGet, "/api/scans/999", "", http.StatusNotFound},
		{"bad limit", http.MethodGet, "/api/scans?limit=0", "", http.StatusBadRequest},
		{"delete missing", http.MethodDelete, "/api/scans/999", "", http.StatusNotFound},
		{"health", http.MethodGet, "/healthz", "", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := do(h, tt.method, tt.path, tt.body); rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body)
			}
		})
	}
}
