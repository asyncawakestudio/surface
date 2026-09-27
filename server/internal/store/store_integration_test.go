//go:build integration

// Runs against a real, disposable database:
//
//	TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/store
package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"surface/internal/asm"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(ctx, `TRUNCATE scans RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	s := openTestStore(t)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("schema_migrations rows = %d, want 3", n)
	}
}

func TestScanHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScan(ctx, "example.com"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate active scan: err = %v, want ErrConflict", err)
	}
	must(t, s.MarkRunning(ctx, first.ID))
	must(t, s.SetStage(ctx, first.ID, "dns"))
	must(t, s.SaveResult(ctx, first.ID, &asm.Result{
		Subdomains: []asm.Subdomain{{Host: "a.example.com", Sources: []string{"crtsh"}}},
		DNSRecords: []asm.DNSRecord{{Host: "a.example.com", Type: "A", Value: "192.0.2.1"}},
		TLSCerts: []asm.TLSCert{{
			Host: "a.example.com", IP: "192.0.2.1", Port: 443, SANs: []string{"a.example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			FingerprintSHA256: "aaa",
		}},
	}))

	// A second scan of the same domain is allowed once the first finished.
	time.Sleep(10 * time.Millisecond) // distinct created_at
	paused, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.MarkPaused(ctx, paused.ID))

	time.Sleep(10 * time.Millisecond)
	latest, err := s.CreateScan(ctx, "example.com")
	if err != nil {
		t.Fatalf("scan after pause: %v", err)
	}
	must(t, s.SaveResult(ctx, latest.ID, &asm.Result{}))

	other, err := s.CreateScan(ctx, "other.example.org")
	if err != nil {
		t.Fatal(err)
	}

	// Previous completed skips the paused scan.
	prev, err := s.PreviousCompleted(ctx, latest.ID)
	if err != nil {
		t.Fatal(err)
	}
	if prev.ID != first.ID || len(prev.Subdomains) != 1 || len(prev.TLSCerts) != 1 || prev.TLSCerts[0].SANs[0] != "a.example.com" {
		t.Fatalf("previous = %+v", prev)
	}
	if prev.Counts.Subdomains != 1 || prev.Counts.ResolvedHosts != 1 || prev.Counts.TLSCerts != 1 {
		t.Fatalf("counts = %+v", prev.Counts)
	}
	if _, err := s.PreviousCompleted(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("previous of first scan: err = %v, want ErrNotFound", err)
	}

	domains, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].Domain != "other.example.org" || domains[1].ScanCount != 3 ||
		domains[1].Latest.ID != latest.ID {
		t.Fatalf("domains = %+v", domains)
	}

	scans, err := s.ListScans(ctx, "example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 || scans[0].ID != latest.ID {
		t.Fatalf("scans = %+v", scans)
	}
	all, _ := s.ListScans(ctx, "", 10)
	if len(all) != 4 || all[0].ID != other.ID {
		t.Fatalf("all scans = %d, first = %d", len(all), all[0].ID)
	}

	n, err := s.FailInterrupted(ctx)
	if err != nil || n != 1 {
		t.Fatalf("FailInterrupted = %d, %v; want 1", n, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
