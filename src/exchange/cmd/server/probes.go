// Liveness and readiness for the Exchange's public listener. /healthz answers
// "this process is up"; /readyz answers the harder question of whether it can
// actually serve, which is what a load balancer must gate traffic on.
package main

import (
	"context"
	"net/http"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

func healthzHandler(pool interface{ Ping(context.Context) error }) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// ledgerHealthCheck returns the billing backend's liveness probe, or nil when the
// selected backend has no ledger to probe.
//
// The assertion lives here, at the composition root, rather than as a method on
// billing.Adapter: only one of the three backends has a remote dependency, so putting
// Health on the shared interface would oblige the other two to answer a question they
// cannot meaningfully be asked (Architecture Rule 3 — narrow interfaces at the ports).
func ledgerHealthCheck(adapter billing.Adapter) func(context.Context) error {
	probe, ok := adapter.(interface{ Health(context.Context) error })
	if !ok {
		return nil
	}
	return probe.Health
}

// readinessProbeTimeout bounds the ledger round-trip /readyz makes. The TigerBeetle
// client's own op-timeout is 5s, which is longer than a probe should ever block —
// and long enough to time out a caller polling with `curl -m 5`. A readiness check
// that cannot answer promptly is a failed readiness check, so this cuts it short.
const readinessProbeTimeout = 2 * time.Second

// readyzHandler reports whether the Exchange can actually serve, as opposed to
// merely running. It checks the catalog database and — when the deployment runs a
// ledger — that the ledger answers.
//
// This is deliberately separate from /healthz, which stays a liveness signal over
// the database alone. The split is what
// lets an orchestrator drain an instance whose ledger has gone away WITHOUT a routine
// ledger restart also restarting the Exchange, and it keeps free resources served
// throughout: a ledger outage denies paid transactions, it does not break the process.
//
// Both checks are nil-tolerant, matching healthzHandler: a nil ledger func is the
// free/in-memory billing backend, which has no ledger to probe and is ready as soon
// as the database answers.
func readyzHandler(
	pool interface{ Ping(context.Context) error },
	ledger func(context.Context) error,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if ledger != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readinessProbeTimeout)
			defer cancel()
			if err := ledger(ctx); err != nil {
				http.Error(w, "ledger unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
