// Package store persists scans and their results in Postgres.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"surface/internal/asm"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	// ErrNotFound is returned when a scan does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a scan is in the wrong state for an action.
	ErrConflict = errors.New("conflict")
)

type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusPaused    Status = "paused"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Scan is a row of the scans table plus per-table result counts.
type Scan struct {
	ID         int64      `json:"id"`
	Domain     string     `json:"domain"`
	Status     Status     `json:"status"`
	Stage      *string    `json:"stage"`
	Error      *string    `json:"error"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Counts     Counts     `json:"counts"`
}

type Counts struct {
	Subdomains    int `json:"subdomains"`
	ResolvedHosts int `json:"resolved_hosts"`
	DNSRecords    int `json:"dns_records"`
	TLSCerts      int `json:"tls_certs"`
}

// ScanDetail is a scan with its full results.
type ScanDetail struct {
	Scan
	Subdomains []asm.Subdomain `json:"subdomains"`
	DNSRecords []asm.DNSRecord `json:"dns_records"`
	TLSCerts   []asm.TLSCert   `json:"tls_certs"`
}

// Result returns the scan's results in the scanner's format.
func (d *ScanDetail) Result() *asm.Result {
	return &asm.Result{Domain: d.Domain, Subdomains: d.Subdomains, DNSRecords: d.DNSRecords, TLSCerts: d.TLSCerts}
}

type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and applies migrations.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.waitForDB(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// waitForDB retries the initial connection for a short while so the API can
// start alongside the database container.
func (s *Store) waitForDB(ctx context.Context) error {
	var err error
	for range 30 {
		if err = s.pool.Ping(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("database unreachable: %w", err)
}

// migrate applies each embedded migration once, in filename order, recording
// applied versions in schema_migrations.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(files)
	for _, f := range files {
		version := path.Base(f)
		sql, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, version)
			if err != nil || tag.RowsAffected() == 0 {
				return err // already applied
			}
			_, err = tx.Exec(ctx, string(sql))
			return err
		})
		if err != nil {
			return fmt.Errorf("%s: %w", version, err)
		}
	}
	return nil
}

// CreateScan inserts a queued scan for domain. It returns ErrConflict if
// the domain already has a queued or running scan.
func (s *Store) CreateScan(ctx context.Context, domain string) (*Scan, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO scans (domain) VALUES ($1) RETURNING `+scanColumns, domain)
	sc, err := scanRow(row)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
		pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "scans_one_active_per_domain" {
		return nil, ErrConflict
	}
	return sc, err
}

// MarkRunning moves a scan into the running state.
func (s *Store) MarkRunning(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = 'running', started_at = now() WHERE id = $1`, id)
	return err
}

// SetStage records which pipeline stage a running scan is in.
func (s *Store) SetStage(ctx context.Context, id int64, stage string) error {
	_, err := s.pool.Exec(ctx, `UPDATE scans SET stage = $2 WHERE id = $1`, id, stage)
	return err
}

// MarkFailed finishes a scan with an error message.
func (s *Store) MarkFailed(ctx context.Context, id int64, msg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, id, msg)
	return err
}

// MarkPaused stops a scan without an error. The stage it was in is kept so
// the UI can show where it stopped.
func (s *Store) MarkPaused(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = 'paused', finished_at = now() WHERE id = $1`, id)
	return err
}

// FailInterrupted marks scans left queued/running by a previous process as
// failed. Call once at startup.
func (s *Store) FailInterrupted(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE scans SET status = 'failed', error = 'interrupted by server restart', finished_at = now()
		 WHERE status IN ('queued', 'running')`)
	return tag.RowsAffected(), err
}

// SaveResult stores all results for a scan and marks it completed, atomically.
func (s *Store) SaveResult(ctx context.Context, id int64, res *asm.Result) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"subdomains"},
			[]string{"scan_id", "host", "sources", "carried_over"},
			pgx.CopyFromSlice(len(res.Subdomains), func(i int) ([]any, error) {
				sd := res.Subdomains[i]
				return []any{id, sd.Host, nonNil(sd.Sources), sd.CarriedOver}, nil
			})); err != nil {
			return fmt.Errorf("insert subdomains: %w", err)
		}

		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"dns_records"},
			[]string{"scan_id", "host", "record_type", "value"},
			pgx.CopyFromSlice(len(res.DNSRecords), func(i int) ([]any, error) {
				r := res.DNSRecords[i]
				return []any{id, r.Host, r.Type, r.Value}, nil
			})); err != nil {
			return fmt.Errorf("insert dns records: %w", err)
		}

		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tls_certificates"},
			[]string{"scan_id", "host", "ip", "port", "tls_version", "cipher", "subject_cn",
				"subject_org", "sans", "issuer_cn", "issuer_org", "serial", "not_before",
				"not_after", "expired", "self_signed", "mismatched", "wildcard", "fingerprint_sha256"},
			pgx.CopyFromSlice(len(res.TLSCerts), func(i int) ([]any, error) {
				c := res.TLSCerts[i]
				return []any{id, c.Host, c.IP, c.Port, c.TLSVersion, c.Cipher, c.SubjectCN,
					nonNil(c.SubjectOrg), nonNil(c.SANs), c.IssuerCN, nonNil(c.IssuerOrg), c.Serial,
					c.NotBefore, c.NotAfter, c.Expired, c.SelfSigned, c.Mismatched, c.Wildcard,
					c.FingerprintSHA256}, nil
			})); err != nil {
			return fmt.Errorf("insert tls certificates: %w", err)
		}

		_, err := tx.Exec(ctx,
			`UPDATE scans SET status = 'completed', stage = NULL, finished_at = now() WHERE id = $1`, id)
		return err
	})
}

// ListScans returns the most recent scans, newest first, optionally only
// those of one domain.
func (s *Store) ListScans(ctx context.Context, domain string, limit int) ([]Scan, error) {
	return s.queryScans(ctx,
		`SELECT `+scanColumns+` FROM scans
		 WHERE $1 = '' OR domain = $1
		 ORDER BY created_at DESC LIMIT $2`, domain, limit)
}

// Domain summarizes every scan of one domain.
type Domain struct {
	Domain    string `json:"domain"`
	ScanCount int    `json:"scan_count"`
	Latest    Scan   `json:"latest"`
}

// ListDomains returns each scanned domain with its latest scan, most
// recently scanned first.
func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	latest, err := s.queryScans(ctx,
		`SELECT * FROM (
		   SELECT DISTINCT ON (domain) `+scanColumns+` FROM scans ORDER BY domain, created_at DESC
		 ) latest ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{}
	rows, err := s.pool.Query(ctx, `SELECT domain, count(*) FROM scans GROUP BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		counts[d] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Domain, len(latest))
	for i, sc := range latest {
		out[i] = Domain{Domain: sc.Domain, ScanCount: counts[sc.Domain], Latest: sc}
	}
	return out, nil
}

// PreviousCompleted returns the most recent completed scan of the same
// domain that was created before scan id, with its results. It returns
// ErrNotFound if there is none.
func (s *Store) PreviousCompleted(ctx context.Context, id int64) (*ScanDetail, error) {
	var prevID int64
	err := s.pool.QueryRow(ctx,
		`SELECT p.id FROM scans p JOIN scans c ON c.id = $1
		 WHERE p.domain = c.domain AND p.status = 'completed' AND p.created_at < c.created_at
		 ORDER BY p.created_at DESC LIMIT 1`, id).Scan(&prevID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetScan(ctx, prevID)
}

// KnownSubdomains returns every subdomain found by the domain's completed
// scans, each with the union of sources that ever reported it. Scans carry
// these forward so the subdomain list is append-only.
func (s *Store) KnownSubdomains(ctx context.Context, domain string) ([]asm.Subdomain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT sd.host,
		        COALESCE(array_agg(DISTINCT src ORDER BY src) FILTER (WHERE src IS NOT NULL), '{}')
		 FROM subdomains sd
		 JOIN scans sc ON sc.id = sd.scan_id
		 LEFT JOIN LATERAL unnest(sd.sources) AS src ON true
		 WHERE sc.domain = $1 AND sc.status = 'completed'
		 GROUP BY sd.host
		 ORDER BY sd.host`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []asm.Subdomain{}
	for rows.Next() {
		var v asm.Subdomain
		if err := rows.Scan(&v.Host, &v.Sources); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) queryScans(ctx context.Context, sql string, args ...any) ([]Scan, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scans := []Scan{}
	for rows.Next() {
		sc, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, *sc)
	}
	return scans, rows.Err()
}

// GetScan returns a scan with all of its results.
func (s *Store) GetScan(ctx context.Context, id int64) (*ScanDetail, error) {
	sc, err := scanRow(s.pool.QueryRow(ctx, `SELECT `+scanColumns+` FROM scans WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := &ScanDetail{Scan: *sc}

	d.Subdomains, err = collect(ctx, s.pool,
		`SELECT host, sources, carried_over FROM subdomains WHERE scan_id = $1 ORDER BY host`, id,
		func(r pgx.Rows) (asm.Subdomain, error) {
			var v asm.Subdomain
			return v, r.Scan(&v.Host, &v.Sources, &v.CarriedOver)
		})
	if err != nil {
		return nil, err
	}

	d.DNSRecords, err = collect(ctx, s.pool,
		`SELECT host, record_type, value FROM dns_records WHERE scan_id = $1 ORDER BY host, record_type, value`, id,
		func(r pgx.Rows) (asm.DNSRecord, error) {
			var v asm.DNSRecord
			return v, r.Scan(&v.Host, &v.Type, &v.Value)
		})
	if err != nil {
		return nil, err
	}

	d.TLSCerts, err = collect(ctx, s.pool,
		`SELECT host, ip, port, COALESCE(tls_version, ''), COALESCE(cipher, ''), COALESCE(subject_cn, ''),
		        subject_org, sans, COALESCE(issuer_cn, ''), issuer_org, COALESCE(serial, ''),
		        not_before, not_after, expired, self_signed, mismatched, wildcard,
		        COALESCE(fingerprint_sha256, '')
		 FROM tls_certificates WHERE scan_id = $1 ORDER BY host, port`, id,
		func(r pgx.Rows) (asm.TLSCert, error) {
			var v asm.TLSCert
			return v, r.Scan(&v.Host, &v.IP, &v.Port, &v.TLSVersion, &v.Cipher, &v.SubjectCN,
				&v.SubjectOrg, &v.SANs, &v.IssuerCN, &v.IssuerOrg, &v.Serial,
				&v.NotBefore, &v.NotAfter, &v.Expired, &v.SelfSigned, &v.Mismatched, &v.Wildcard,
				&v.FingerprintSHA256)
		})
	if err != nil {
		return nil, err
	}

	return d, nil
}

const scanColumns = `id, domain, status, stage, error, created_at, started_at, finished_at,
	(SELECT count(*) FROM subdomains s WHERE s.scan_id = scans.id) AS subdomain_count,
	(SELECT count(DISTINCT host) FROM dns_records d WHERE d.scan_id = scans.id AND d.record_type IN ('A', 'AAAA')) AS resolved_count,
	(SELECT count(*) FROM dns_records d WHERE d.scan_id = scans.id) AS dns_record_count,
	(SELECT count(*) FROM tls_certificates t WHERE t.scan_id = scans.id) AS tls_cert_count`

func scanRow(row pgx.Row) (*Scan, error) {
	var sc Scan
	err := row.Scan(&sc.ID, &sc.Domain, &sc.Status, &sc.Stage, &sc.Error,
		&sc.CreatedAt, &sc.StartedAt, &sc.FinishedAt,
		&sc.Counts.Subdomains, &sc.Counts.ResolvedHosts, &sc.Counts.DNSRecords, &sc.Counts.TLSCerts)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func collect[T any](ctx context.Context, pool *pgxpool.Pool, sql string, id int64, fn func(pgx.Rows) (T, error)) ([]T, error) {
	rows, err := pool.Query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []T{}
	for rows.Next() {
		v, err := fn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
