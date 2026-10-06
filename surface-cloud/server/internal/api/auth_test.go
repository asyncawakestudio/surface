package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"surface-cloud/internal/store"
	"surface/asm"
)

// fakeAuthStore is an in-memory AuthStore.
type fakeAuthStore struct {
	mu       sync.Mutex
	codes    map[string]string // email -> codeHash
	users    map[string]*store.User
	sessions map[string]int64 // tokenHash -> userID
	nextID   int64
}

func newFakeAuth() *fakeAuthStore {
	return &fakeAuthStore{codes: map[string]string{}, users: map[string]*store.User{}, sessions: map[string]int64{}}
}

func (f *fakeAuthStore) PutLoginCode(_ context.Context, email, codeHash string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[email] = codeHash
	return nil
}
func (f *fakeAuthStore) LoginCodeAge(_ context.Context, email string) (time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.codes[email]
	return time.Hour, ok, nil // old enough to never throttle in tests
}
func (f *fakeAuthStore) CheckLoginCode(_ context.Context, email, codeHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codes[email] != codeHash {
		return store.ErrCodeInvalid
	}
	delete(f.codes, email)
	return nil
}
func (f *fakeAuthStore) UpsertUser(_ context.Context, email string) (*store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	f.nextID++
	u := &store.User{ID: f.nextID, Email: email, CreatedAt: time.Now()}
	f.users[email] = u
	return u, nil
}
func (f *fakeAuthStore) CreateSession(_ context.Context, tokenHash string, userID int64, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[tokenHash] = userID
	return nil
}
func (f *fakeAuthStore) SessionUser(_ context.Context, tokenHash string) (*store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.sessions[tokenHash]
	if !ok {
		return nil, store.ErrNotFound
	}
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, store.ErrNotFound
}
func (f *fakeAuthStore) DeleteSession(_ context.Context, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, tokenHash)
	return nil
}

type captureMailer struct {
	mu   sync.Mutex
	body string
}

func (m *captureMailer) Send(_ context.Context, _, _, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = body
	return nil
}
func (m *captureMailer) code() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return regexp.MustCompile(`\d{6}`).FindString(m.body)
}

func newAuthAPI(t *testing.T) (*captureMailer, http.Handler) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := newFakeStore()
	jobs := NewJobs(st, func(asm.Options) Scanner { return &fakeScanner{} }, asm.Options{}, logger, 2, time.Minute)
	t.Cleanup(jobs.Shutdown)
	mailer := &captureMailer{}
	h := New(st, jobs, logger, WithAuth(newFakeAuth(), mailer, AuthConfig{})).Handler()
	return mailer, h
}

func TestAuthFlow(t *testing.T) {
	mailer, h := newAuthAPI(t)

	// Protected route without a session -> 401.
	if rec := do(h, http.MethodGet, "/api/domains", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed /api/domains = %d, want 401", rec.Code)
	}
	// Auth routes are open.
	if rec := do(h, http.MethodGet, "/api/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me without session = %d, want 401", rec.Code)
	}

	// Request a code.
	if rec := do(h, http.MethodPost, "/api/auth/request", `{"email":"User@Example.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("request code = %d, body %s", rec.Code, rec.Body)
	}
	code := mailer.code()
	if code == "" {
		t.Fatal("no code in email body")
	}

	// Wrong code -> 401.
	if rec := do(h, http.MethodPost, "/api/auth/verify", `{"email":"user@example.com","code":"000000"}`); rec.Code != http.StatusUnauthorized && code != "000000" {
		// (ignore the 1-in-a-million case where the real code is 000000)
		t.Fatalf("wrong code = %d, want 401", rec.Code)
	}

	// Correct code -> 200 + session cookie.
	rec := do(h, http.MethodPost, "/api/auth/verify", `{"email":"user@example.com","code":"`+code+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, body %s", rec.Code, rec.Body)
	}
	cookie := rec.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != sessionCookie || cookie[0].Value == "" {
		t.Fatalf("no session cookie set: %+v", cookie)
	}
	session := cookie[0]

	// Authenticated requests now succeed.
	for _, path := range []string{"/api/auth/me", "/api/domains"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(session)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("authed %s = %d, want 200", path, w.Code)
		}
	}

	// Logout clears the session.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(session)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(session)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", w.Code)
	}
}

func TestAuthDisabledByDefault(t *testing.T) {
	// Without WithAuth, routes are open (back-compat) and no /api/auth/* exists.
	_, _, h := newTestAPI(t, &fakeScanner{})
	if rec := do(h, http.MethodGet, "/api/domains", ""); rec.Code == http.StatusUnauthorized {
		t.Fatal("auth should be disabled without WithAuth")
	}
	if rec := do(h, http.MethodGet, "/api/auth/me", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("auth route present without WithAuth: %d", rec.Code)
	}
}
