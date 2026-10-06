//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthFlow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const email = "user@example.com"

	// Store a code, wrong code increments attempts, right code consumes it.
	must(t, s.PutLoginCode(ctx, email, "goodhash", time.Now().Add(10*time.Minute)))
	if age, ok, err := s.LoginCodeAge(ctx, email); err != nil || !ok || age > time.Minute {
		t.Fatalf("code age = %v ok=%v err=%v", age, ok, err)
	}
	if err := s.CheckLoginCode(ctx, email, "badhash"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("bad code = %v, want ErrCodeInvalid", err)
	}
	if err := s.CheckLoginCode(ctx, email, "goodhash"); err != nil {
		t.Fatalf("good code = %v, want nil", err)
	}
	// Consumed: a second check fails.
	if err := s.CheckLoginCode(ctx, email, "goodhash"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("consumed code = %v, want ErrCodeInvalid", err)
	}

	// Expired code is rejected.
	must(t, s.PutLoginCode(ctx, email, "h", time.Now().Add(-time.Second)))
	if err := s.CheckLoginCode(ctx, email, "h"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("expired code = %v, want ErrCodeInvalid", err)
	}

	// Attempt lockout.
	must(t, s.PutLoginCode(ctx, email, "h", time.Now().Add(time.Minute)))
	for i := 0; i < maxCodeAttempts; i++ {
		_ = s.CheckLoginCode(ctx, email, "wrong")
	}
	if err := s.CheckLoginCode(ctx, email, "h"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("after lockout correct code = %v, want ErrCodeInvalid", err)
	}

	// User + session lifecycle.
	u, err := s.UpsertUser(ctx, email)
	must(t, err)
	if u.ID == 0 || u.Email != email || u.LastLoginAt == nil {
		t.Fatalf("user = %+v", u)
	}
	u2, err := s.UpsertUser(ctx, email) // idempotent
	must(t, err)
	if u2.ID != u.ID {
		t.Fatalf("upsert created a second user: %d vs %d", u2.ID, u.ID)
	}

	must(t, s.CreateSession(ctx, "tok-hash", u.ID, time.Now().Add(time.Hour)))
	got, err := s.SessionUser(ctx, "tok-hash")
	must(t, err)
	if got.ID != u.ID {
		t.Fatalf("session user = %d, want %d", got.ID, u.ID)
	}
	must(t, s.DeleteSession(ctx, "tok-hash"))
	if _, err := s.SessionUser(ctx, "tok-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after logout = %v, want ErrNotFound", err)
	}

	// Expired session is not returned.
	must(t, s.CreateSession(ctx, "old", u.ID, time.Now().Add(-time.Hour)))
	if _, err := s.SessionUser(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session = %v, want ErrNotFound", err)
	}
}
