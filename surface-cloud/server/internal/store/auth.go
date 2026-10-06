package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// User is an authenticated account, identified by email.
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// ErrCodeInvalid is returned when a login code is wrong, expired, or missing.
var ErrCodeInvalid = errors.New("invalid or expired code")

// PutLoginCode stores (replacing any existing) the pending code for an email.
func (s *Store) PutLoginCode(ctx context.Context, email, codeHash string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO login_codes (email, code_hash, attempts, created_at, expires_at)
		 VALUES ($1, $2, 0, now(), $3)
		 ON CONFLICT (email) DO UPDATE SET code_hash = $2, attempts = 0, created_at = now(), expires_at = $3`,
		email, codeHash, expiresAt)
	return err
}

// LoginCodeAge returns how long ago the pending code for email was created,
// and whether one exists. Used to rate-limit resends.
func (s *Store) LoginCodeAge(ctx context.Context, email string) (time.Duration, bool, error) {
	var created time.Time
	err := s.pool.QueryRow(ctx, `SELECT created_at FROM login_codes WHERE email = $1`, email).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return time.Since(created), true, nil
}

const maxCodeAttempts = 5

// CheckLoginCode validates codeHash for email. On success the code is consumed
// (deleted) and nil is returned. On failure it increments the attempt counter
// and returns ErrCodeInvalid; after maxCodeAttempts the code is discarded.
func (s *Store) CheckLoginCode(ctx context.Context, email, codeHash string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) // no-op once committed

	var stored string
	var attempts int
	var expires time.Time
	err = tx.QueryRow(ctx,
		`SELECT code_hash, attempts, expires_at FROM login_codes WHERE email = $1 FOR UPDATE`, email).
		Scan(&stored, &attempts, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCodeInvalid
	}
	if err != nil {
		return err
	}

	// On a failed/expired attempt we must commit the state change (counter
	// bump or deletion) before returning the sentinel error, so a wrapping
	// rollback can't undo the lockout progress.
	switch {
	case time.Now().After(expires) || attempts >= maxCodeAttempts:
		if _, err := tx.Exec(ctx, `DELETE FROM login_codes WHERE email = $1`, email); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return ErrCodeInvalid
	case subtleMismatch(stored, codeHash):
		if _, err := tx.Exec(ctx, `UPDATE login_codes SET attempts = attempts + 1 WHERE email = $1`, email); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return ErrCodeInvalid
	default:
		if _, err := tx.Exec(ctx, `DELETE FROM login_codes WHERE email = $1`, email); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
}

// UpsertUser creates the user if needed, records the login time, and returns it.
func (s *Store) UpsertUser(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, last_login_at) VALUES ($1, now())
		 ON CONFLICT (email) DO UPDATE SET last_login_at = now()
		 RETURNING id, email, created_at, last_login_at`, email).
		Scan(&u.ID, &u.Email, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateSession stores a session for userID keyed by tokenHash.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expiresAt)
	return err
}

// SessionUser returns the user for a valid, unexpired session token hash.
func (s *Store) SessionUser(ctx context.Context, tokenHash string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.created_at, u.last_login_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash).
		Scan(&u.ID, &u.Email, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// subtleMismatch compares two equal-length hex hashes in constant time; it
// reports true when they differ.
func subtleMismatch(a, b string) bool {
	if len(a) != len(b) {
		return true
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v != 0
}
