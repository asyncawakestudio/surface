package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"surface/internal/asm"
)

// stopReason records why a job was cancelled, which decides the status it
// leaves behind.
type stopReason int

const (
	stopNone     stopReason = iota
	stopPause               // mark the scan paused
	stopShutdown            // server shutting down; mark failed
)

type job struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	reason stopReason
}

func (jb *job) stop(r stopReason) {
	jb.mu.Lock()
	if jb.reason == stopNone {
		jb.reason = r
	}
	jb.mu.Unlock()
	jb.cancel()
}

func (jb *job) stopReason() stopReason {
	jb.mu.Lock()
	defer jb.mu.Unlock()
	return jb.reason
}

// Jobs runs scans in the background with bounded concurrency.
type Jobs struct {
	store   Store
	scanner Scanner
	logger  *slog.Logger
	timeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	wg     sync.WaitGroup

	mu     sync.Mutex
	active map[int64]*job
}

// NewJobs creates a job runner allowing maxConcurrent scans at once, each
// limited to timeout.
func NewJobs(st Store, sc Scanner, logger *slog.Logger, maxConcurrent int, timeout time.Duration) *Jobs {
	ctx, cancel := context.WithCancel(context.Background())
	return &Jobs{
		store:   st,
		scanner: sc,
		logger:  logger,
		timeout: timeout,
		ctx:     ctx,
		cancel:  cancel,
		sem:     make(chan struct{}, maxConcurrent),
		active:  make(map[int64]*job),
	}
}

// Submit queues a scan. It returns immediately.
func (j *Jobs) Submit(id int64, domain string) {
	ctx, cancel := context.WithCancel(j.ctx)
	jb := &job{cancel: cancel, done: make(chan struct{})}

	j.mu.Lock()
	j.active[id] = jb
	j.mu.Unlock()

	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		defer close(jb.done)
		defer cancel()
		defer func() {
			j.mu.Lock()
			delete(j.active, id)
			j.mu.Unlock()
		}()

		select {
		case j.sem <- struct{}{}:
			defer func() { <-j.sem }()
		case <-ctx.Done():
			j.finishCancelled(id, jb)
			return
		}
		// Cancelled while waiting on the semaphore and it was picked anyway.
		if ctx.Err() != nil {
			j.finishCancelled(id, jb)
			return
		}
		j.run(ctx, id, domain, jb)
	}()
}

// Active reports whether a scan is queued or running in this process.
func (j *Jobs) Active(id int64) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.active[id]
	return ok
}

// Pause cancels a queued or running scan and waits up to wait for it to
// record its paused state. It reports whether the scan was active.
func (j *Jobs) Pause(id int64, wait time.Duration) bool {
	j.mu.Lock()
	jb, ok := j.active[id]
	j.mu.Unlock()
	if !ok {
		return false
	}
	jb.stop(stopPause)
	select {
	case <-jb.done:
	case <-time.After(wait):
		j.logger.Warn("scan did not pause in time", "scan_id", id, "waited", wait)
	}
	return true
}

// Shutdown cancels running scans and waits for them to record their state.
func (j *Jobs) Shutdown() {
	j.mu.Lock()
	for _, jb := range j.active {
		jb.stop(stopShutdown)
	}
	j.mu.Unlock()
	j.cancel()
	j.wg.Wait()
}

func (j *Jobs) run(ctx context.Context, id int64, domain string, jb *job) {
	log := j.logger.With("scan_id", id, "domain", domain)
	ctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	// Status updates use a detached context so they're still written when
	// the scan itself is cancelled.
	bg := context.WithoutCancel(ctx)

	if err := j.store.MarkRunning(bg, id); err != nil {
		log.Error("mark running", "err", err)
		return
	}
	// Subdomains are append-only: hosts from earlier scans are carried into
	// this one. Without them the scan would silently drop known assets, so
	// failing to load them fails the scan.
	known, err := j.store.KnownSubdomains(bg, domain)
	if err != nil {
		log.Error("load known subdomains", "err", err)
		j.fail(id, "failed to load subdomains from previous scans")
		return
	}
	log.Info("scan started", "known_subdomains", len(known))
	start := time.Now()

	res, err := j.scanner.Run(ctx, asm.Target{Domain: domain, KnownSubdomains: known}, func(stage asm.Stage) {
		log.Info("scan stage", "stage", stage)
		if err := j.store.SetStage(bg, id, string(stage)); err != nil {
			log.Warn("set stage", "err", err)
		}
	})
	if err != nil {
		if jb.stopReason() != stopNone {
			j.finishCancelled(id, jb)
			return
		}
		log.Error("scan failed", "err", err)
		j.fail(id, err.Error())
		return
	}

	if err := j.store.SaveResult(bg, id, res); err != nil {
		log.Error("save result", "err", err)
		j.fail(id, "failed to save results")
		return
	}
	log.Info("scan completed",
		"duration", time.Since(start).Round(time.Second),
		"subdomains", len(res.Subdomains),
		"dns_records", len(res.DNSRecords),
		"tls_certs", len(res.TLSCerts),
	)
}

// finishCancelled records the final state of a job that was stopped.
func (j *Jobs) finishCancelled(id int64, jb *job) {
	switch jb.stopReason() {
	case stopPause:
		j.logger.Info("scan paused", "scan_id", id)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := j.store.MarkPaused(ctx, id); err != nil {
			j.logger.Error("mark paused", "scan_id", id, "err", err)
		}
	default:
		j.fail(id, "server shutting down")
	}
}

func (j *Jobs) fail(id int64, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := j.store.MarkFailed(ctx, id, msg); err != nil {
		j.logger.Error("mark failed", "scan_id", id, "err", err)
	}
}
