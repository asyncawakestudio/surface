package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"surface-cloud/internal/email"
	"surface-cloud/internal/store"
)

// AuthStore is the persistence auth needs (implemented by *store.Store).
type AuthStore interface {
	PutLoginCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error
	LoginCodeAge(ctx context.Context, email string) (time.Duration, bool, error)
	CheckLoginCode(ctx context.Context, email, codeHash string) error
	UpsertUser(ctx context.Context, email string) (*store.User, error)
	CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error
	SessionUser(ctx context.Context, tokenHash string) (*store.User, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

// AuthConfig tunes the OTP login flow.
type AuthConfig struct {
	Secure         bool          // set the Secure flag on the session cookie (prod/HTTPS)
	AppName        string        // used in the email subject/body
	CodeTTL        time.Duration // how long a login code is valid
	SessionTTL     time.Duration // how long a session lasts
	ResendInterval time.Duration // minimum time between code requests per email
}

func (c AuthConfig) withDefaults() AuthConfig {
	if c.AppName == "" {
		c.AppName = "Surface"
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = 10 * time.Minute
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 30 * 24 * time.Hour
	}
	if c.ResendInterval <= 0 {
		c.ResendInterval = 60 * time.Second
	}
	return c
}

type authState struct {
	store  AuthStore
	mailer email.Sender
	cfg    AuthConfig
}

const sessionCookie = "surface_session"

// Option configures an API.
type Option func(*API)

// WithAuth enables email-OTP authentication: /api/auth/* routes plus a
// middleware that protects every other /api route.
func WithAuth(as AuthStore, mailer email.Sender, cfg AuthConfig) Option {
	return func(a *API) {
		a.auth = &authState{store: as, mailer: mailer, cfg: cfg.withDefaults()}
	}
}

type ctxKey int

const userKey ctxKey = 0

func userFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userKey).(*store.User)
	return u
}

// requireAuth rejects requests without a valid session cookie.
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.sessionUser(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

func (a *API) sessionUser(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, errors.New("no session")
	}
	return a.auth.store.SessionUser(r.Context(), hashToken(c.Value))
}

type requestCodeBody struct {
	Email string `json:"email"`
}

func (a *API) authRequest(w http.ResponseWriter, r *http.Request) {
	var body requestCodeBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	addr, err := normalizeEmail(body.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	// Throttle resends.
	if age, exists, err := a.auth.store.LoginCodeAge(r.Context(), addr); err == nil && exists && age < a.auth.cfg.ResendInterval {
		writeError(w, http.StatusTooManyRequests, "a code was just sent; please wait before requesting another")
		return
	}

	code, err := generateCode()
	if err != nil {
		a.internalError(w, "generate code", err)
		return
	}
	if err := a.auth.store.PutLoginCode(r.Context(), addr, hashToken(code), time.Now().Add(a.auth.cfg.CodeTTL)); err != nil {
		a.internalError(w, "store code", err)
		return
	}

	mins := int(a.auth.cfg.CodeTTL.Minutes())
	subject := fmt.Sprintf("%s login code: %s", a.auth.cfg.AppName, code)
	bodyText := fmt.Sprintf("Your %s login code is:\n\n    %s\n\nIt expires in %d minutes. If you didn't request it, ignore this email.",
		a.auth.cfg.AppName, code, mins)
	if err := a.auth.mailer.Send(r.Context(), addr, subject, bodyText); err != nil {
		a.internalError(w, "send email", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true, "expires_in_minutes": mins})
}

type verifyBody struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (a *API) authVerify(w http.ResponseWriter, r *http.Request) {
	var body verifyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	addr, err := normalizeEmail(body.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	code := strings.TrimSpace(body.Code)
	if err := a.auth.store.CheckLoginCode(r.Context(), addr, hashToken(code)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired code")
		return
	}

	user, err := a.auth.store.UpsertUser(r.Context(), addr)
	if err != nil {
		a.internalError(w, "upsert user", err)
		return
	}
	token, err := generateToken()
	if err != nil {
		a.internalError(w, "generate token", err)
		return
	}
	expires := time.Now().Add(a.auth.cfg.SessionTTL)
	if err := a.auth.store.CreateSession(r.Context(), hashToken(token), user.ID, expires); err != nil {
		a.internalError(w, "create session", err)
		return
	}
	http.SetCookie(w, a.cookie(token, expires))
	writeJSON(w, http.StatusOK, user)
}

func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	u, err := a.sessionUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (a *API) authLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = a.auth.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, a.cookie("", time.Unix(0, 0)))
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) cookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.auth.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	// ParseAddress accepts "Name <a@b>"; require a bare address.
	if addr.Name != "" || addr.Address != s {
		return "", errors.New("invalid email")
	}
	return addr.Address, nil
}

// generateCode returns a random 6-digit numeric code.
func generateCode() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

// generateToken returns a URL-safe random session token.
func generateToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
