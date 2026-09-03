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
// two near-identical select-and-defer pairs. The returned currency is the
// selected billing backend's ledger currency (ISO 4217 alpha), threaded into
// ExchangeConfig.LedgerCurrency so the welcome-credit grant is denominated in
// the same currency the adapter checks. A failure in either is a boot-time
// config fault: the caller returns it and the process exits non-zero rather than
// silently degrading. The billing cleanup is run even when the SoR construction
// fails, so a half-built pair leaks nothing.
func selectAdapters(
	ctx context.Context, logger *slog.Logger,
) (billing.Adapter, string, sor.Adapter, func(), error) {
	billingAdapter, currency, billingCleanup, err := selectBillingAdapter(ctx, logger)
	if err != nil {
		return nil, "", nil, nil, err
	}
	// Constructed at boot so a misconfigured SoR fails fast.
	sorAdapter, sorCleanup, err := selectSoRAdapter(ctx, logger)
	if err != nil {
		billingCleanup()
		return nil, "", nil, nil, err
	}
	return billingAdapter, currency, sorAdapter, func() {
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
// The returned currency is the backend's ledger currency: the demo tiers
// (free, in-memory) run in USD, TigerBeetle's comes from
// EXCHANGE_BILLING_LEDGER. The returned func() releases any adapter-owned
// resources (the TigerBeetle client connection); it is a no-op for
// free/inmemory. A non-nil error means an explicitly-selected backend could
// not be constructed — boot fails rather than silently degrading to free.
func selectBillingAdapter(ctx context.Context, logger *slog.Logger) (billing.Adapter, string, func(), error) {
	noop := func() {}
	switch kind := runhttp.EnvOr("RAMP_BILLING_ADAPTER", "free"); kind {
	case "free":
		return billing.FreeAdapter{}, demoCurrency, noop, nil
	case "inmemory":
		return newBillingAdapter(logger), demoCurrency, noop, nil
	case "tigerbeetle":
		return newTigerBeetleBillingAdapter(ctx, logger)
	default:
		logger.Warn("RAMP_BILLING_ADAPTER unknown value; using free", "value", kind)
		return billing.FreeAdapter{}, demoCurrency, noop, nil
	}
}

// demoCurrency is the ledger currency of the demo billing tiers (free,
// in-memory). It reads the adapters' own constant rather than repeating the
// literal, so the currency this wiring reports and the currency those adapters
// check every Credit against cannot drift apart.
const demoCurrency = billing.DemoCurrency

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
//
// An entry in any currency other than demoCurrency is skipped for the same
// reason, and this is the only production path that could otherwise create a
// balance the tier does not denominate. Such a balance cannot receive the
// Register welcome credit, and a publisher pricing a term in its currency could
// spend it, so the account is better absent than present and wrong: a skipped
// agent is denied at Authorize as an unknown account, which is a clean signal.
// Skipping rather than failing boot follows the malformed-amount rule directly
// below — one bad entry must not stop the service starting.
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
		if a.Currency != demoCurrency {
			logger.Warn("EXCHANGE_BILLING_SEED entry skipped: unsupported currency",
				"agent_id", agentID, "currency", a.Currency, "want_currency", demoCurrency)
			continue
		}
		seed.Balances[agentID] = a
	}
	logger.Info("billing adapter seeded", "agents", len(seed.Balances))
	return billing.NewInMemoryAdapter(seed)
}
