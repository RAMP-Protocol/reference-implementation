//go:build integration

package billing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// TestTigerBeetleAdapterHealth drives the adapter's readiness probe against the
// real ledger. It is what backs the Exchange's /readyz: the composition root
// type-asserts this method off billing.Adapter, so if it stops reporting the
// cluster's true state the readiness endpoint silently starts lying.
//
// The negative case matters as much as the positive one. A probe that cannot
// distinguish "answering" from "gone" is worse than none, because it would hold a
// drained instance in rotation while every paid transaction fails.
func TestTigerBeetleAdapterHealth(t *testing.T) {
	adapter, _ := newTBAdapter("health", time.Minute)

	probe, ok := adapter.(interface{ Health(context.Context) error })
	if !ok {
		t.Fatal("TigerBeetleAdapter does not expose Health; /readyz cannot cover the ledger")
	}

	t.Run("cluster answering", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := probe.Health(ctx); err != nil {
			t.Fatalf("Health() against a live cluster = %v, want nil", err)
		}
	})

	t.Run("caller deadline is honoured", func(t *testing.T) {
		// The TigerBeetle client is not context-cancelable, so the adapter relies on
		// the client's withDeadline wrapper to bound the call. /readyz passes a 2s
		// context precisely because the client's own timeout is 5s; an already-expired
		// context must come back promptly rather than run to that longer bound.
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		start := time.Now()
		err := probe.Health(ctx)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Health() with an expired context took %v; the caller's deadline was ignored", elapsed)
		}
		if err == nil {
			t.Fatal("Health() with an expired context = nil, want an error")
		}
		if !errors.Is(err, tigerbeetle.ErrUnavailable) {
			t.Errorf("Health() = %v, want it to wrap ErrUnavailable so callers can classify it", err)
		}
	})
}

// TestFreeAdapterHasNoHealth pins the other half of the contract: the default
// billing backend exposes no Health, so the composition root leaves /readyz's
// ledger probe nil and readiness collapses onto liveness. Were FreeAdapter ever to
// grow the method, every free-tier deployment would start probing a ledger it does
// not have.
func TestFreeAdapterHasNoHealth(t *testing.T) {
	var adapter billing.Adapter = billing.FreeAdapter{}
	if _, ok := adapter.(interface{ Health(context.Context) error }); ok {
		t.Error("FreeAdapter exposes Health; /readyz would probe a ledger that does not exist")
	}
}
