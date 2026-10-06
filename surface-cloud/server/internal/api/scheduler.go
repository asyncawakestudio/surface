package api

import (
	"context"
	"time"
)

// Scheduler periodically fires configured scans whose next run time has
// passed. It runs entirely in-process.
type Scheduler struct {
	api      *API
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewScheduler builds a scheduler that checks for due configs every interval.
func (a *API) NewScheduler(interval time.Duration) *Scheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Scheduler{api: a, interval: interval, done: make(chan struct{})}
}

// Start runs the scheduler loop until Stop is called.
func (s *Scheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() {
		defer close(s.done)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		s.tick(ctx) // run once promptly on startup
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.tick(ctx)
			}
		}
	}()
}

// Stop halts the loop and waits for the current tick to finish.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	now := time.Now()
	due, err := s.api.store.DueConfigs(ctx, now)
	if err != nil {
		s.api.logger.Error("scheduler: list due configs", "err", err)
		return
	}
	for i := range due {
		cfg := &due[i]
		// Advance the schedule first so a slow/large run can't double-fire.
		if err := s.api.store.MarkConfigRan(ctx, cfg.ID, now); err != nil {
			s.api.logger.Error("scheduler: mark ran", "config", cfg.ID, "err", err)
			continue
		}
		started := s.api.enqueueConfig(ctx, cfg)
		s.api.logger.Info("scheduler: fired config", "config", cfg.ID, "name", cfg.Name,
			"domains", len(cfg.Domains), "started", started)
	}
}
