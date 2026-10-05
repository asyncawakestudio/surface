package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"surface/internal/api"
	"surface/internal/asm"
	"surface/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if n, err := st.FailInterrupted(ctx); err != nil {
		return err
	} else if n > 0 {
		logger.Warn("marked interrupted scans as failed", "count", n)
	}

	scanner := asm.New(asm.Options{
		SubfinderProviderConfig: os.Getenv("SUBFINDER_PROVIDER_CONFIG"),
		Resolvers:               envList("DNS_RESOLVERS"),
		IPInfoToken:             os.Getenv("IPINFO_TOKEN"),
		PortScan:                envBool("PORT_SCAN", true),
		PortScanPorts:           os.Getenv("PORT_SCAN_PORTS"),   // default "-" (all) when empty
		PortScanRate:            envInt("PORT_SCAN_RATE", 0),    // 0 -> package default
		PortScanRetries:         envInt("PORT_SCAN_RETRIES", 0), // 0 -> package default
		Logger:                  logger,
	})
	jobs := api.NewJobs(st, scanner, logger,
		envInt("MAX_CONCURRENT_SCANS", 2),
		time.Duration(envInt("SCAN_TIMEOUT_MINUTES", 30))*time.Minute,
	)

	handler := api.New(st, jobs, logger).Handler()
	// In production the server also serves the built client; in development
	// Vite serves it and proxies /api here.
	if dir := os.Getenv("STATIC_DIR"); dir != "" {
		handler = api.WithStatic(handler, dir)
		logger.Info("serving client", "dir", dir)
	}

	srv := &http.Server{
		Addr:              ":" + envString("PORT", "8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	jobs.Shutdown()
	return err
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envList(key string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
