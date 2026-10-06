package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Frequency is how often a configured scan runs.
type Frequency string

const (
	FreqManual  Frequency = "manual" // only on demand (no auto-schedule)
	FreqDaily   Frequency = "daily"
	FreqWeekly  Frequency = "weekly"
	FreqMonthly Frequency = "monthly"
)

// ScanOptions are the per-scan engine toggles a config carries. The zero value
// means "full scan with server defaults".
type ScanOptions struct {
	SkipIPDR  bool   `json:"skip_ipdr"`
	SkipPorts bool   `json:"skip_ports"`
	SkipCerts bool   `json:"skip_certs"`
	PortType  string `json:"port_type"` // "", "syn", "connect"
	PortSpec  string `json:"port_spec"` // "", "-", "1-1000", "80,443"
	PortRate  int    `json:"port_rate"`
}

// ScanConfig is a saved, schedulable scan definition.
type ScanConfig struct {
	ID         int64       `json:"id"`
	Name       string      `json:"name"`
	Domains    []string    `json:"domains"`
	Frequency  Frequency   `json:"frequency"`
	TimeOfDay  string      `json:"time_of_day"`  // "HH:MM" in Timezone
	Weekday    *int        `json:"weekday"`      // 0..6 (weekly)
	DayOfMonth *int        `json:"day_of_month"` // 1..31 (monthly)
	Timezone   string      `json:"timezone"`     // IANA name
	Options    ScanOptions `json:"options"`
	Enabled    bool        `json:"enabled"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	LastRunAt  *time.Time  `json:"last_run_at"`
	NextRunAt  *time.Time  `json:"next_run_at"`
}

const configColumns = `id, name, domains, frequency, time_of_day, weekday, day_of_month,
	timezone, skip_ipdr, skip_ports, skip_certs, port_type, port_spec, port_rate,
	enabled, created_at, updated_at, last_run_at, next_run_at`

func scanConfigRow(row pgx.Row) (*ScanConfig, error) {
	var c ScanConfig
	err := row.Scan(&c.ID, &c.Name, &c.Domains, &c.Frequency, &c.TimeOfDay, &c.Weekday,
		&c.DayOfMonth, &c.Timezone, &c.Options.SkipIPDR, &c.Options.SkipPorts, &c.Options.SkipCerts,
		&c.Options.PortType, &c.Options.PortSpec, &c.Options.PortRate,
		&c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.LastRunAt, &c.NextRunAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateConfig inserts a config and sets its next run time from the schedule.
func (s *Store) CreateConfig(ctx context.Context, c *ScanConfig) (*ScanConfig, error) {
	next := c.nextRunFrom(time.Now())
	row := s.pool.QueryRow(ctx,
		`INSERT INTO scan_configs
		   (name, domains, frequency, time_of_day, weekday, day_of_month, timezone,
		    skip_ipdr, skip_ports, skip_certs, port_type, port_spec, port_rate, enabled, next_run_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING `+configColumns,
		c.Name, c.Domains, c.Frequency, c.TimeOfDay, c.Weekday, c.DayOfMonth, c.Timezone,
		c.Options.SkipIPDR, c.Options.SkipPorts, c.Options.SkipCerts,
		c.Options.PortType, c.Options.PortSpec, c.Options.PortRate, c.Enabled, next)
	return scanConfigRow(row)
}

// UpdateConfig replaces a config's fields and recomputes its next run time.
func (s *Store) UpdateConfig(ctx context.Context, c *ScanConfig) (*ScanConfig, error) {
	next := c.nextRunFrom(time.Now())
	row := s.pool.QueryRow(ctx,
		`UPDATE scan_configs SET
		   name=$2, domains=$3, frequency=$4, time_of_day=$5, weekday=$6, day_of_month=$7,
		   timezone=$8, skip_ipdr=$9, skip_ports=$10, skip_certs=$11, port_type=$12,
		   port_spec=$13, port_rate=$14, enabled=$15, next_run_at=$16, updated_at=now()
		 WHERE id=$1 RETURNING `+configColumns,
		c.ID, c.Name, c.Domains, c.Frequency, c.TimeOfDay, c.Weekday, c.DayOfMonth, c.Timezone,
		c.Options.SkipIPDR, c.Options.SkipPorts, c.Options.SkipCerts,
		c.Options.PortType, c.Options.PortSpec, c.Options.PortRate, c.Enabled, next)
	cfg, err := scanConfigRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return cfg, err
}

func (s *Store) GetConfig(ctx context.Context, id int64) (*ScanConfig, error) {
	cfg, err := scanConfigRow(s.pool.QueryRow(ctx, `SELECT `+configColumns+` FROM scan_configs WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return cfg, err
}

func (s *Store) ListConfigs(ctx context.Context) ([]ScanConfig, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+configColumns+` FROM scan_configs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanConfig{}
	for rows.Next() {
		c, err := scanConfigRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteConfig(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scan_configs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DueConfigs returns enabled configs whose next run time has passed.
func (s *Store) DueConfigs(ctx context.Context, now time.Time) ([]ScanConfig, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+configColumns+` FROM scan_configs
		 WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
		 ORDER BY next_run_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanConfig{}
	for rows.Next() {
		c, err := scanConfigRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// MarkConfigRan records a run and advances next_run_at per the schedule.
func (s *Store) MarkConfigRan(ctx context.Context, id int64, ran time.Time) error {
	cfg, err := s.GetConfig(ctx, id)
	if err != nil {
		return err
	}
	next := cfg.nextRunFrom(ran.Add(time.Minute)) // avoid immediately re-firing
	_, err = s.pool.Exec(ctx,
		`UPDATE scan_configs SET last_run_at=$2, next_run_at=$3 WHERE id=$1`, id, ran, next)
	return err
}

// nextRunFrom computes the next scheduled run strictly after `after`, or nil
// for manual configs / invalid schedules.
func (c *ScanConfig) nextRunFrom(after time.Time) *time.Time {
	if !c.Enabled || c.Frequency == FreqManual || c.Frequency == "" {
		return nil
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		loc = time.UTC
	}
	hh, mm, ok := parseHHMM(c.TimeOfDay)
	if !ok {
		return nil
	}
	after = after.In(loc)

	switch c.Frequency {
	case FreqDaily:
		cand := time.Date(after.Year(), after.Month(), after.Day(), hh, mm, 0, 0, loc)
		for !cand.After(after) {
			cand = cand.AddDate(0, 0, 1)
		}
		return utcPtr(cand)
	case FreqWeekly:
		wd := 0
		if c.Weekday != nil {
			wd = ((*c.Weekday % 7) + 7) % 7
		}
		cand := time.Date(after.Year(), after.Month(), after.Day(), hh, mm, 0, 0, loc)
		for cand.Weekday() != time.Weekday(wd) || !cand.After(after) {
			cand = cand.AddDate(0, 0, 1)
		}
		return utcPtr(cand)
	case FreqMonthly:
		dom := 1
		if c.DayOfMonth != nil {
			dom = *c.DayOfMonth
		}
		// Walk forward month by month until we land on a valid day after `after`.
		for m := 0; m < 24; m++ {
			first := time.Date(after.Year(), after.Month(), 1, hh, mm, 0, 0, loc).AddDate(0, m, 0)
			daysIn := daysInMonth(first.Year(), first.Month(), loc)
			d := dom
			if d > daysIn {
				d = daysIn // clamp (e.g. day 31 in February)
			}
			cand := time.Date(first.Year(), first.Month(), d, hh, mm, 0, 0, loc)
			if cand.After(after) {
				return utcPtr(cand)
			}
		}
	}
	return nil
}

func utcPtr(t time.Time) *time.Time { u := t.UTC(); return &u }

func parseHHMM(s string) (h, m int, ok bool) {
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

func daysInMonth(year int, month time.Month, loc *time.Location) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
}
