package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"surface-cloud/internal/store"
	"surface/asm"
)

// configInput is the editable shape of a scan config (client-facing).
type configInput struct {
	Name       string            `json:"name"`
	Domains    []string          `json:"domains"`
	Frequency  store.Frequency   `json:"frequency"`
	TimeOfDay  string            `json:"time_of_day"`
	Weekday    *int              `json:"weekday"`
	DayOfMonth *int              `json:"day_of_month"`
	Timezone   string            `json:"timezone"`
	Options    store.ScanOptions `json:"options"`
	Enabled    bool              `json:"enabled"`
}

// toConfig validates the input and builds a store.ScanConfig (without ID).
func (in configInput) toConfig() (*store.ScanConfig, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	if len(in.Domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	domains := make([]string, 0, len(in.Domains))
	seen := map[string]bool{}
	for _, d := range in.Domains {
		nd, err := asm.NormalizeDomain(d)
		if err != nil {
			return nil, errors.New("invalid domain: " + d)
		}
		if !seen[nd] {
			seen[nd] = true
			domains = append(domains, nd)
		}
	}

	freq := in.Frequency
	if freq == "" {
		freq = store.FreqManual
	}
	switch freq {
	case store.FreqManual, store.FreqDaily, store.FreqWeekly, store.FreqMonthly:
	default:
		return nil, errors.New("invalid frequency")
	}

	tz := in.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return nil, errors.New("invalid timezone")
	}

	tod := in.TimeOfDay
	if tod == "" {
		tod = "00:00"
	}
	if !validHHMM(tod) {
		return nil, errors.New("time_of_day must be HH:MM")
	}

	if freq == store.FreqWeekly {
		if in.Weekday == nil || *in.Weekday < 0 || *in.Weekday > 6 {
			return nil, errors.New("weekly schedule needs weekday 0..6")
		}
	}
	if freq == store.FreqMonthly {
		if in.DayOfMonth == nil || *in.DayOfMonth < 1 || *in.DayOfMonth > 31 {
			return nil, errors.New("monthly schedule needs day_of_month 1..31")
		}
	}
	if in.Options.PortType != "" && in.Options.PortType != "syn" && in.Options.PortType != "connect" {
		return nil, errors.New("port_type must be syn or connect")
	}

	return &store.ScanConfig{
		Name: strings.TrimSpace(in.Name), Domains: domains, Frequency: freq,
		TimeOfDay: tod, Weekday: in.Weekday, DayOfMonth: in.DayOfMonth, Timezone: tz,
		Options: in.Options, Enabled: in.Enabled,
	}, nil
}

func validHHMM(s string) bool {
	var h, m int
	if n, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || n != 2 {
		return false
	}
	return h >= 0 && h <= 23 && m >= 0 && m <= 59
}

func (a *API) listConfigs(w http.ResponseWriter, r *http.Request) {
	cfgs, err := a.store.ListConfigs(r.Context())
	if err != nil {
		a.internalError(w, "list configs", err)
		return
	}
	writeJSON(w, http.StatusOK, cfgs)
}

func (a *API) createConfig(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	cfg, err := in.toConfig()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := a.store.CreateConfig(r.Context(), cfg)
	if err != nil {
		a.internalError(w, "create config", err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cfg, err := a.store.GetConfig(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "config not found")
		return
	}
	if err != nil {
		a.internalError(w, "get config", err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (a *API) updateConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	in, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	cfg, err := in.toConfig()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg.ID = id
	updated, err := a.store.UpdateConfig(r.Context(), cfg)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "config not found")
		return
	}
	if err != nil {
		a.internalError(w, "update config", err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) deleteConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := a.store.DeleteConfig(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "config not found")
		return
	}
	if err != nil {
		a.internalError(w, "delete config", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runConfig fans the config out to a scan per domain immediately.
func (a *API) runConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cfg, err := a.store.GetConfig(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "config not found")
		return
	}
	if err != nil {
		a.internalError(w, "get config", err)
		return
	}
	started := a.enqueueConfig(r.Context(), cfg)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": started, "domains": len(cfg.Domains)})
}

// enqueueConfig starts a scan for each domain in the config that isn't already
// in progress, and returns how many it started. Shared by the run-now endpoint
// and the scheduler.
func (a *API) enqueueConfig(ctx context.Context, cfg *store.ScanConfig) int {
	started := 0
	for _, domain := range cfg.Domains {
		id := cfg.ID
		scan, err := a.store.CreateScan(ctx, domain, &id)
		if errors.Is(err, store.ErrConflict) {
			continue // a scan of this domain is already running
		}
		if err != nil {
			a.logger.Error("config scan create", "config", cfg.ID, "domain", domain, "err", err)
			continue
		}
		a.jobs.Submit(scan.ID, domain, cfg.Options)
		started++
	}
	return started
}

func decodeConfig(w http.ResponseWriter, r *http.Request) (configInput, bool) {
	var in configInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return in, false
	}
	return in, true
}
