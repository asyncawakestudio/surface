package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	for _, d := range f.scans {
		if d.Domain == domain && (d.Status == store.StatusQueued || d.Status == store.StatusRunning) {
			return nil, store.ErrConflict
		}
	}
	f.nextID++
	// IDs order creation, standing in for created_at.
	sc := store.Scan{ID: f.nextID, Domain: domain, Status: store.StatusQueued, CreatedAt: time.Unix(f.nextID, 0)}
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

func (f *fakeStore) MarkPaused(_ context.Context, id int64) error {
	return f.update(id, func(d *store.ScanDetail) { d.Status = store.StatusPaused })
}

func (f *fakeStore) SaveResult(_ context.Context, id int64, res *asm.Result) error {
	return f.update(id, func(d *store.ScanDetail) {
		d.Status = store.StatusCompleted
		d.Subdomains, d.DNSRecords, d.TLSCerts = res.Subdomains, res.DNSRecords, res.TLSCerts
	})
}

func (f *fakeStore) ListScans(_ context.Context, domain string, _ int) ([]store.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.Scan{}
	for _, d := range f.scans {
		if domain == "" || d.Domain == domain {
			out = append(out, d.Scan)
		}
	}
	slices.SortFunc(out, func(a, b store.Scan) int { return int(b.ID - a.ID) })
	return out, nil
}

func (f *fakeStore) ListDomains(context.Context) ([]store.Domain, error) {
	all, _ := f.ListScans(context.Background(), "", 0)
	byDomain := map[string]*store.Domain{}
	var out []store.Domain
	for _, sc := range all { // newest first
		if d, ok := byDomain[sc.Domain]; ok {
			d.ScanCount++
			continue
		}
		out = append(out, store.Domain{Domain: sc.Domain, ScanCount: 1, Latest: sc})
		byDomain[sc.Domain] = &out[len(out)-1]
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

func (f *fakeStore) PreviousCompleted(ctx context.Context, id int64) (*store.ScanDetail, error) {
	cur, err := f.GetScan(ctx, id)
	if err != nil {
		return nil, err
	}
	for prevID := id - 1; prevID > 0; prevID-- {
		if p, err := f.GetScan(ctx, prevID); err == nil && p.Domain == cur.Domain && p.Status == store.StatusCompleted {
			return p, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) KnownSubdomains(_ context.Context, domain string) ([]asm.Subdomain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []asm.Subdomain
	for _, d := range f.scans {
		if d.Domain != domain || d.Status != store.StatusCompleted {
			continue
		}
		for _, sd := range d.Subdomains {
			if !seen[sd.Host] {
				seen[sd.Host] = true
				out = append(out, sd)
			}
		}
	}
	return out, nil
}

func (f *fakeStore) status(id int64) store.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.scans[id]; ok {
		return d.Status
	}
	return ""
}

type fakeScanner struct {
	err error
	// results are returned by successive runs; after they run out a default
	// single-subdomain result is used.
	mu      sync.Mutex
	results []*asm.Result
	// block makes Run wait for cancellation; started is signalled first.
	block   atomic.Bool
	started chan struct{}
	// targets records what each run was given.
	targets []asm.Target
}

func (f *fakeScanner) Run(ctx context.Context, target asm.Target, progress asm.ProgressFunc) (*asm.Result, error) {
	domain := target.Domain
	f.mu.Lock()
	f.targets = append(f.targets, target)
	f.mu.Unlock()
	progress(asm.StageSubdomains)
	if f.block.Load() {
		f.started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) > 0 {
		r := f.results[0]
		f.results = f.results[1:]
		return r, nil
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
	st, jobs, h := newTestAPI(t, &fakeScanner{})

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
	st, jobs, h := newTestAPI(t, &fakeScanner{err: errors.New("boom")})

	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()

	d, _ := st.GetScan(context.Background(), 1)
	if d.Status != store.StatusFailed || d.Error == nil || *d.Error != "boom" {
		t.Fatalf("scan = %+v, want failed with error boom", d.Scan)
	}
}

func TestValidation(t *testing.T) {
	_, _, h := newTestAPI(t, &fakeScanner{})

	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"bad json", http.MethodPost, "/api/scans", `{`, http.StatusBadRequest},
		{"bad domain", http.MethodPost, "/api/scans", `{"domain":"not a domain"}`, http.StatusBadRequest},
		{"bad id", http.MethodGet, "/api/scans/abc", "", http.StatusBadRequest},
		{"missing scan", http.MethodGet, "/api/scans/999", "", http.StatusNotFound},
		{"bad limit", http.MethodGet, "/api/scans?limit=0", "", http.StatusBadRequest},
		{"bad domain filter", http.MethodGet, "/api/scans?domain=not%20a%20domain", "", http.StatusBadRequest},
		{"pause missing", http.MethodPost, "/api/scans/999/pause", "", http.StatusNotFound},
		{"diff missing", http.MethodGet, "/api/scans/999/diff", "", http.StatusNotFound},
		{"no delete", http.MethodDelete, "/api/scans/1", "", http.StatusMethodNotAllowed},
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

// startBlockedScan creates a scan of example.com that runs until cancelled.
func startBlockedScan(t *testing.T) (*fakeStore, *fakeScanner, *Jobs, http.Handler) {
	t.Helper()
	sc := &fakeScanner{started: make(chan struct{}, 1)}
	sc.block.Store(true)
	st, jobs, h := newTestAPI(t, sc)
	if rec := do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("create: status = %d", rec.Code)
	}
	select {
	case <-sc.started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan never started")
	}
	return st, sc, jobs, h
}

func TestOneActiveScanPerDomain(t *testing.T) {
	_, _, _, h := startBlockedScan(t)

	if rec := do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second scan of same domain: status = %d, want 409", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/scans", `{"domain":"other.example.org"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("scan of another domain: status = %d, want 202", rec.Code)
	}
}

func TestPauseThenScanAgain(t *testing.T) {
	st, sc, jobs, h := startBlockedScan(t)

	rec := do(h, http.MethodPost, "/api/scans/1/pause", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"paused"`) {
		t.Fatalf("pause: status = %d, body = %s", rec.Code, rec.Body)
	}
	if jobs.Active(1) {
		t.Fatal("job still active after pause")
	}
	if rec := do(h, http.MethodPost, "/api/scans/1/pause", ""); rec.Code != http.StatusConflict {
		t.Fatalf("second pause: status = %d, want 409", rec.Code)
	}

	// Scanning again creates a new scan; the paused one stays in history.
	sc.block.Store(false)
	if rec := do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("scan again: status = %d, body = %s", rec.Code, rec.Body)
	}
	jobs.wg.Wait()
	if st.status(1) != store.StatusPaused || st.status(2) != store.StatusCompleted {
		t.Fatalf("statuses = %q, %q; want paused, completed", st.status(1), st.status(2))
	}

	rec = do(h, http.MethodGet, "/api/domains", "")
	if !strings.Contains(rec.Body.String(), `"scan_count":2`) {
		t.Fatalf("domains: %s", rec.Body)
	}
}

func TestPauseQueuedScan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := &fakeScanner{started: make(chan struct{}, 1)}
	sc.block.Store(true)
	st := newFakeStore()
	jobs := NewJobs(st, sc, logger, 1, time.Minute) // one slot: second scan queues
	t.Cleanup(jobs.Shutdown)
	h := New(st, jobs, logger).Handler()

	do(h, http.MethodPost, "/api/scans", `{"domain":"one.example.com"}`)
	<-sc.started
	do(h, http.MethodPost, "/api/scans", `{"domain":"two.example.com"}`)

	if rec := do(h, http.MethodPost, "/api/scans/2/pause", ""); rec.Code != http.StatusOK {
		t.Fatalf("pause queued: status = %d", rec.Code)
	}
	if got := st.status(2); got != store.StatusPaused {
		t.Fatalf("queued scan status = %q, want paused", got)
	}
	if got := st.status(1); got != store.StatusRunning {
		t.Fatalf("running scan status = %q, want running", got)
	}
}

func TestDiff(t *testing.T) {
	sc := &fakeScanner{results: []*asm.Result{
		{Subdomains: []asm.Subdomain{{Host: "a.example.com"}, {Host: "old.example.com"}}},
		{Subdomains: []asm.Subdomain{{Host: "a.example.com"}, {Host: "new.example.com"}}},
	}}
	_, jobs, h := newTestAPI(t, sc)

	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()

	// First scan of a domain has nothing to compare against.
	rec := do(h, http.MethodGet, "/api/scans/1/diff", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"base":null`) {
		t.Fatalf("first diff: status = %d, body = %s", rec.Code, rec.Body)
	}

	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()

	rec = do(h, http.MethodGet, "/api/scans/2/diff", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("diff: status = %d, body = %s", rec.Code, rec.Body)
	}
	var got struct {
		Base *store.Scan `json:"base"`
		asm.Diff
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Base == nil || got.Base.ID != 1 {
		t.Fatalf("base = %+v, want scan 1", got.Base)
	}
	if len(got.Subdomains.Added) != 1 || got.Subdomains.Added[0].Host != "new.example.com" ||
		len(got.Subdomains.Removed) != 1 || got.Subdomains.Removed[0].Host != "old.example.com" {
		t.Fatalf("subdomain diff = %+v", got.Subdomains)
	}
}

func TestDiffRequiresCompletedScan(t *testing.T) {
	_, _, _, h := startBlockedScan(t)
	if rec := do(h, http.MethodGet, "/api/scans/1/diff", ""); rec.Code != http.StatusConflict {
		t.Fatalf("diff of running scan: status = %d, want 409", rec.Code)
	}
}

func TestKnownSubdomainsArePassedToNextScan(t *testing.T) {
	sc := &fakeScanner{results: []*asm.Result{
		{Subdomains: []asm.Subdomain{{Host: "a.example.com", Sources: []string{"crtsh"}}}},
		{Subdomains: []asm.Subdomain{{Host: "b.example.com"}}},
	}}
	_, jobs, h := newTestAPI(t, sc)

	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()
	do(h, http.MethodPost, "/api/scans", `{"domain":"example.com"}`)
	jobs.wg.Wait()

	if len(sc.targets) != 2 {
		t.Fatalf("runs = %d, want 2", len(sc.targets))
	}
	if n := len(sc.targets[0].KnownSubdomains); n != 0 {
		t.Fatalf("first scan got %d known subdomains, want 0", n)
	}
	known := sc.targets[1].KnownSubdomains
	if len(known) != 1 || known[0].Host != "a.example.com" || known[0].Sources[0] != "crtsh" {
		t.Fatalf("second scan known subdomains = %+v", known)
	}
}
