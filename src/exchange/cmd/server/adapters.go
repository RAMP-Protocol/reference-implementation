package main

// Billing and account system-of-record adapter selection. Both are chosen from
// the environment at boot and both own releasable resources, so they are wired
// and torn down together — keeping the selection here also keeps main.go's run()
// within the function-length budget.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// selectAdapters constructs the billing and SoR adapters together and returns a
// single cleanup that releases both, so run() carries one boot step rather than
// two near-identical select-and-defer pairs. A failure in either is a boot-time
// config fault: the caller returns it and the process exits non-zero rather than
// silently degrading. The billing cleanup is run even when the SoR construction
// fails, so a half-built pair leaks nothing.
func selectAdapters(
	ctx context.Context, logger *slog.Logger,
) (billing.Adapter, sor.Adapter, func(), error) {
	billingAdapter, billingCleanup, err := selectBillingAdapter(ctx, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	// Constructed at boot so a misconfigured SoR fails fast.
	sorAdapter, sorCleanup, err := selectSoRAdapter(ctx, logger)
	if err != nil {
		billingCleanup()
		return nil, nil, nil, err
	}
	return billingAdapter, sorAdapter, func() {
		sorCleanup()
		billingCleanup()
	}, nil
}

// selectBillingAdapter chooses the Adapter at boot. RAMP_BILLING_ADAPTER=free
// (default) returns billing.FreeAdapter{}; the always-approve zero-state
// adapter appropriate for demo / wholesale tiers. =inmemory returns the
// prepaid-balance InMemoryAdapter seeded from EXCHANGE_BILLING_SEED.
// =tigerbeetle returns the persisted ledger adapter (see billing_tigerbeetle.go).
// Unknown values fall back to free with a warning.
//
// Env-prefix convention: RAMP_BILLING_ADAPTER is the cross-cutting BACKEND SELECTOR
// (the RAMP_ prefix marks a platform-wide switch a deployment sets once); the chosen
// adapter's own configuration lives under EXCHANGE_BILLING_* (this Exchange process's
// settings). Selector vs. per-process config — two prefixes on purpose.
//
// The returned func() releases any adapter-owned resources (the TigerBeetle
// client connection); it is a no-op for free/inmemory. A non-nil error means an
// explicitly-selected backend could not be constructed — boot fails rather than
// silently degrading to free.
func selectBillingAdapter(ctx context.Context, logger *slog.Logger) (billing.Adapter, func(), error) {
	noop := func() {}
	switch kind := runhttp.EnvOr("RAMP_BILLING_ADAPTER", "free"); kind {
	case "free":
		return billing.FreeAdapter{}, noop, nil
	case "inmemory":
		return newBillingAdapter(logger), noop, nil
	case "tigerbeetle":
		return newTigerBeetleBillingAdapter(ctx, logger)
	default:
		logger.Warn("RAMP_BILLING_ADAPTER unknown value; using free", "value", kind)
		return billing.FreeAdapter{}, noop, nil
	}
}

// selectSoRAdapter chooses the System-of-Record Adapter at boot.
// RAMP_SOR_ADAPTER=postgres (the default) returns the Postgres-backed adapter
// (see sor.go); ANY other value FAILS BOOT.
//
// The unknown-value fail-fast is a deliberate divergence from
// selectBillingAdapter, which degrades to the safe free adapter: the SoR is the
// single source of truth for account status and has no safe zero-state backend
// to fall back to, so an unrecognized selector must stop the boot rather than
// serve transactions against an unintended (or absent) store (AC #5).
//
// Env-prefix convention mirrors billing: RAMP_SOR_ADAPTER is the cross-cutting
// backend SELECTOR (RAMP_ marks a platform-wide switch); the chosen backend's
// own configuration lives under EXCHANGE_SOR_* (this process's settings).
//
// The returned func() closes the SoR pool on shutdown.
func selectSoRAdapter(ctx context.Context, logger *slog.Logger) (sor.Adapter, func(), error) {
	switch kind := runhttp.EnvOr("RAMP_SOR_ADAPTER", "postgres"); kind {
	case "postgres":
		return newPostgresSoRAdapter(ctx, logger)
	default:
		return nil, nil, fmt.Errorf("sor: unknown RAMP_SOR_ADAPTER %q", kind)
	}
}

// newBillingAdapter builds the in-memory billing adapter, optionally seeded
// with demo agent balances from EXCHANGE_BILLING_SEED — a JSON object of the
// shape `{"agent-id": {"value": "100.00", "currency": "USD"}}`. Malformed
// entries are logged and skipped so a typo can't wedge the whole service.
func newBillingAdapter(logger *slog.Logger) *billing.InMemoryAdapter {
	seed := billing.InMemoryOptions{Balances: map[string]billing.Amount{}}
	raw := runhttp.EnvOr("EXCHANGE_BILLING_SEED", "")
	if raw == "" {
		return billing.NewInMemoryAdapter(seed)
	}
	var parsed map[string]struct {
		Value    string `json:"value"`
		Currency string `json:"currency"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		logger.Warn("EXCHANGE_BILLING_SEED ignored: invalid JSON", "err", err)
		return billing.NewInMemoryAdapter(seed)
	}
	for agentID, amt := range parsed {
		a, err := billing.NewAmount(amt.Value, amt.Currency)
		if err != nil {
			logger.Warn("EXCHANGE_BILLING_SEED entry skipped", "agent_id", agentID, "err", err)
			continue
		}
		seed.Balances[agentID] = a
	}
	logger.Info("billing adapter seeded", "agents", len(seed.Balances))
	return billing.NewInMemoryAdapter(seed)
}
