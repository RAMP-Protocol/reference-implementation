package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestRun_MissingDSNErrors asserts the Exchange refuses to start when
// EXCHANGE_DSN is absent, matching the Broker's BROKER_DSN contract.
//
// The Exchange used to start anyway and serve /healthz alone. That mode could
// not work: db.Setup returns a typed-nil *pgxpool.Pool, and a nil pointer
// carried in an interface is not a nil interface, so the handler's nil guard
// let a Ping through to a nil pool and the request panicked. It also served
// nothing — the catalog snapshot is built from the database, and boot returned
// long before that.
//
// Before the rejection existed this test did not fail, it HUNG: run() reached
// the listener and blocked. A timeout, not an assertion, was the old behavior.
func TestRun_MissingDSNErrors(t *testing.T) {
	// Empty, not unset: config is read through runhttp.EnvOr, which treats the
	// two identically, and t.Setenv restores the previous value afterwards.
	t.Setenv("EXCHANGE_DSN", "")

	err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("run with no EXCHANGE_DSN returned nil error; want a missing-DSN error")
	}
	// The sentinel proves the guard fired at the DSN check rather than something
	// downstream failing for its own reasons — signing keys and the broker
	// well-known URL are equally unset here and would each abort the boot with a
	// different message.
	if !strings.Contains(err.Error(), "EXCHANGE_DSN is required") {
		t.Fatalf("error %q is not the explicit missing-DSN rejection", err)
	}
}

// TestBuildHTTPSigDeps_AnnouncesPerProcessReplayStore asserts the Exchange says
// so when REDIS_URL is unset, rather than leaving the absence of
// exchange.httpsig.replay_store_ready as the only evidence. A per-process replay
// store is correct at one instance and unsafe above it, so an operator needs a
// line to grep and alert on — the Broker has emitted broker.redis.disabled for
// exactly this reason since it was written.
//
// The assertion is on the log, NOT the return value: REDIS_URL is read before
// the key file is loaded and before the fail-closed well-known guard, so the
// line is emitted and the call then fails for unrelated reasons. That error is
// ignored on purpose. Reading a slog sink to observe behaviour is permitted as
// an observation seam (Testing Doctrine point 9).
func TestBuildHTTPSigDeps_AnnouncesPerProcessReplayStore(t *testing.T) {
	// Empty, not unset: runhttp.EnvOr treats the two identically, and t.Setenv
	// restores whatever the environment had.
	t.Setenv("REDIS_URL", "")

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))

	//nolint:errcheck // the call is expected to fail after the line under test
	// is emitted; the boot inputs it needs next are deliberately not supplied.
	_, _, _ = buildHTTPSigDeps(context.Background(), logger, http.DefaultClient)

	if !strings.Contains(logged.String(), "exchange.httpsig.replay_store_disabled") {
		t.Fatalf("no exchange.httpsig.replay_store_disabled line with REDIS_URL unset; logged: %s", logged.String())
	}
	if strings.Contains(logged.String(), "exchange.httpsig.replay_store_ready") {
		t.Fatalf("logged replay_store_ready with REDIS_URL unset; logged: %s", logged.String())
	}
}
