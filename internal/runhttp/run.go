// Package runhttp shares HTTP server bootstrap logic between services.
package runhttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// EnvOrFile resolves a value from the environment variable key, or when that is
// empty, from the file named by its "_FILE" companion (key+"_FILE"), trimmed of
// surrounding whitespace. It lets a secret arrive as a mounted file rather than
// only inline env — the pattern Docker and Kubernetes secrets use.
//
// The inline variable wins when both are set. A "_FILE" that is set but
// unreadable is an error, never a silent empty: a secret that failed to load is
// not the same as a secret that was not configured, and treating them alike is
// how a service comes up unauthenticated and looks fine.
//
// It lives here, beside EnvOr and EnvDuration, so the next service that needs a
// mounted secret imports this rather than growing a second spelling of it.
func EnvOrFile(key string) (string, error) {
	if v := EnvOr(key, ""); v != "" {
		return v, nil
	}
	path := EnvOr(key+"_FILE", "")
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled secret path, same trust as the env var it replaces
	if err != nil {
		return "", fmt.Errorf("%s_FILE: %w", key, err)
	}
	return strings.TrimSpace(string(data)), nil
}

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

// EnvOptIn reads a deliberately-unsafe opt-in flag: true ONLY when the value is
// "true" (any case) or exactly "1". Everything else — unset, empty, "0",
// "false", "yes", "on", or a typo like "flase" — is false.
//
// This is a strict allowlist, and that is the whole point of it existing beside
// EnvBool. EnvBool is a denylist: any value it does not recognise as false is
// true, so a mistyped "disabled" would ENABLE the thing being guarded. That is
// acceptable for a feature toggle whose safe state is on; it is the wrong shape
// for a flag whose only job is to let an operator step outside a safety
// default, where a typo must fail closed. The SDK's guarded-client flags
// (SKIP_SSRF, ALLOW_INSECURE) use these exact rules, so an operator who has met
// one has met them all.
func EnvOptIn(key string) bool {
	v := os.Getenv(key)
	return strings.EqualFold(v, "true") || v == "1"
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

// EnvInt64 parses a positive integer from key, CLAMPED to ceiling, returning def
// when the variable is absent.
//
// Clamping rather than discarding is the point. An operator who asks for more than
// the ceiling means "as much as you will give me"; answering that with the
// default — which is typically far LESS than they asked for — is the surprising
// reading, and it is silent. Values that are not a number at all, or are not
// positive, are a different case: they carry no intent to honour, so they return
// def and report notOK so the caller can fail loudly if it chooses.
func EnvInt64(key string, def, ceiling int64) (value int64, ok bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return def, false
	}
	return min(n, ceiling), true
}

// Serve runs an HTTP server on addr with the given handler, logging with name,
// and performs a graceful shutdown on SIGINT / SIGTERM. It is a thin single-server
// adapter over ServeGroup, which owns the server construction and the 10s graceful
// shutdown; Serve adds only the process signal handler and the os.Exit on failure
// that its callers rely on.
func Serve(name, addr string, handler http.Handler, logger *slog.Logger) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := ServeGroup(ctx, logger, ServerSpec{Name: name, Addr: addr, Handler: handler})
	stop() // explicit (not deferred) so it runs before a non-zero os.Exit
	if err != nil {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
}

// ServerSpec names one HTTP server for ServeGroup: a display name, a bind
// address, and the handler to serve.
type ServerSpec struct {
	Name    string
	Addr    string
	Handler http.Handler
}

// ServeGroup runs one HTTP server per spec under a single shutdown context and
// blocks until ctx is cancelled (SIGINT/SIGTERM is the caller's to install) or
// any server fails. On either trigger it gracefully shuts down every server
// within 10s. Unlike Serve it takes an external context (so co-managed listeners
// share one signal) and returns an error instead of calling os.Exit, which keeps
// it composable. Returns the first non-ErrServerClosed listener error, or nil on
// a clean shutdown.
func ServeGroup(ctx context.Context, logger *slog.Logger, specs ...ServerSpec) error {
	g, gctx := errgroup.WithContext(ctx)
	srvs := make([]*http.Server, len(specs))
	names := make([]string, len(specs))
	for i, s := range specs {
		srv := &http.Server{
			Addr:              s.Addr,
			Handler:           s.Handler,
			ReadHeaderTimeout: 5 * time.Second,
			// Go's default is 1 MiB, which is far larger than any RAMP request
			// needs and bounds every header-sourced value the services persist or
			// log. 64 KiB comfortably clears an RFC 9421 multisig chain plus an
			// entitlement token.
			MaxHeaderBytes: 64 << 10,
		}
		srvs[i] = srv
		names[i] = s.Name
		name, addr := s.Name, s.Addr
		g.Go(func() error {
			logger.Info(name+" listening", "addr", addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s: %w", name, err)
			}
			return nil
		})
	}
	g.Go(func() error {
		<-gctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for i, srv := range srvs {
			logger.Info("shutting down", "service", names[i])
			if err := srv.Shutdown(shutCtx); err != nil {
				logger.Error("shutdown error", "service", names[i], "err", err)
			}
		}
		return nil
	})
	return g.Wait()
}
