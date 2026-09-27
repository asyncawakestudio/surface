package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"surface/internal/asm"
)

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
	active map[int64]struct{}
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
		active:  make(map[int64]struct{}),
	}
}

// Submit queues a scan. It returns immediately.
func (j *Jobs) Submit(id int64, domain string) {
	j.mu.Lock()
	j.active[id] = struct{}{}
	j.mu.Unlock()

	j.wg.Add(1)
	go func() {
		defer j.wg.Done()
		defer func() {
			j.mu.Lock()
			delete(j.active, id)
			j.mu.Unlock()
		}()

		select {
		case j.sem <- struct{}{}:
			defer func() { <-j.sem }()
		case <-j.ctx.Done():
			j.fail(id, "server shutting down")
			return
		}
		j.run(id, domain)
	}()
}

// Active reports whether a scan is queued or running in this process.
func (j *Jobs) Active(id int64) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.active[id]
	return ok
}

// Shutdown cancels running scans and waits for them to record their state.
func (j *Jobs) Shutdown() {
	j.cancel()
	j.wg.Wait()
}

func (j *Jobs) run(id int64, domain string) {
	log := j.logger.With("scan_id", id, "domain", domain)
	ctx, cancel := context.WithTimeout(j.ctx, j.timeout)
	defer cancel()

	// Status updates use a detached context so they're still written when
	// the scan itself is cancelled.
	bg := context.WithoutCancel(ctx)

	if err := j.store.MarkRunning(bg, id); err != nil {
		log.Error("mark running", "err", err)
		return
	}
	log.Info("scan started")
	start := time.Now()

	res, err := j.scanner.Run(ctx, domain, func(stage asm.Stage) {
		log.Info("scan stage", "stage", stage)
		if err := j.store.SetStage(bg, id, string(stage)); err != nil {
			log.Warn("set stage", "err", err)
		}
	})
	if err != nil {
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

func (j *Jobs) fail(id int64, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := j.store.MarkFailed(ctx, id, msg); err != nil {
		j.logger.Error("mark failed", "scan_id", id, "err", err)
	}
}
