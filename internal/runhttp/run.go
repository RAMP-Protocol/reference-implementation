// Package runhttp shares HTTP server bootstrap logic between services.
package runhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// EnvOr returns os.Getenv(key) if set, otherwise fallback.
func EnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// EnvBool reads a boolean env var: unset → def; "0"/"false"/"no"/"off"
// (case-insensitive) → false; any other non-empty value → true. Both services
// gate their per-agent well-known resolution flag through this, so the parse
// rule lives once.
func EnvBool(key string, def bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "":
		return def
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// EnvDuration parses a Go duration from key, returning def on absent/invalid/
// negative input. A zero return lets a downstream consumer apply its own default.
func EnvDuration(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return def
	}
	return d
}

// Serve runs an HTTP server on addr with the given handler, logging with name,
// and performs a graceful shutdown on SIGINT / SIGTERM.
func Serve(name, addr string, handler http.Handler, logger *slog.Logger) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info(name+" listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down", "service", name)
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Error("shutdown error", "err", err)
	}
}
