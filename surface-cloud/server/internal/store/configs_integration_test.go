//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"surface/asm"
)

func TestScanConfigRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	wd := 2 // Tuesday
	created, err := s.CreateConfig(ctx, &ScanConfig{
		Name: "prod", Domains: []string{"example.com", "api.example.com"},
		Frequency: FreqWeekly, TimeOfDay: "09:30", Weekday: &wd, Timezone: "America/New_York",
		Options: ScanOptions{SkipCerts: true, PortSpec: "1-1000"}, Enabled: true,
	})
	must(t, err)
	if created.ID == 0 || created.NextRunAt == nil {
		t.Fatalf("expected id and next_run_at, got %+v", created)
	}
	if nr := created.NextRunAt; nr.Weekday() != time.Tuesday {
		t.Errorf("next run weekday = %s, want Tuesday", nr.Weekday())
	}

	// A scan can link to the config.
	sc, err := s.CreateScan(ctx, "example.com", &created.ID)
	must(t, err)
	must(t, s.SaveResult(ctx, sc.ID, &asm.Result{}))

	// Update: switch to daily, disable scheduling via manual.
	created.Frequency = FreqManual
	created.Enabled = true
	upd, err := s.UpdateConfig(ctx, created)
	must(t, err)
	if upd.NextRunAt != nil {
		t.Errorf("manual config should have no next_run_at, got %v", upd.NextRunAt)
	}

	got, err := s.GetConfig(ctx, created.ID)
	must(t, err)
	if got.Options.SkipCerts != true || got.Options.PortSpec != "1-1000" || len(got.Domains) != 2 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	list, err := s.ListConfigs(ctx)
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("list = %d, want 1", len(list))
	}

	must(t, s.DeleteConfig(ctx, created.ID))
	if _, err := s.GetConfig(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestDueConfigs(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	daily, err := s.CreateConfig(ctx, &ScanConfig{
		Name: "d", Domains: []string{"example.com"}, Frequency: FreqDaily,
		TimeOfDay: "00:00", Timezone: "UTC", Enabled: true,
	})
	must(t, err)
	// Not due far in the past-less future; force due by querying with a far-future now.
	due, err := s.DueConfigs(ctx, time.Now().Add(48*time.Hour))
	must(t, err)
	if len(due) != 1 || due[0].ID != daily.ID {
		t.Fatalf("due = %+v, want the daily config", due)
	}

	// Manual config is never due.
	_, err = s.CreateConfig(ctx, &ScanConfig{Name: "m", Domains: []string{"x.example.com"}, Frequency: FreqManual, Timezone: "UTC", Enabled: true})
	must(t, err)
	due, err = s.DueConfigs(ctx, time.Now().Add(48*time.Hour))
	must(t, err)
	if len(due) != 1 {
		t.Fatalf("manual config should not be due; due=%d", len(due))
	}
}
