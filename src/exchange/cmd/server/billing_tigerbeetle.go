package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// billingURLTTL mirrors service.ExchangeConfig's default signed-URL TTL (5m).
// The hold must outlive the URL by a grace window so a settle/void can still
// land at the edge of URL validity. If the Exchange later makes URLTTL
// configurable, thread the same value here so the two stay coupled.
const billingURLTTL = 5 * time.Minute

// newTigerBeetleBillingAdapter builds the persisted TigerBeetle billing adapter
// from the environment. Config is fully validated before the client connection
// opens, so a misconfiguration fails fast without leaking a socket. The returned
// func() closes the client on shutdown.
//
// Environment variables (all under the EXCHANGE_BILLING_ prefix — one adapter,
// one convention):
//   - EXCHANGE_BILLING_LEDGER: ISO 4217 numeric currency (e.g. 978 = EUR); the
//     TigerBeetle ledger id and the source for the adapter's alpha Currency.
//   - EXCHANGE_BILLING_TB_ADDRESS: TigerBeetle IP:port (hostnames are rejected).
//   - EXCHANGE_BILLING_TB_CLUSTER_ID: cluster id (default 0).
//   - EXCHANGE_BILLING_HOLD_GRACE: hold-timeout grace over the URL TTL (default 1m).
//   - EXCHANGE_BILLING_TB_OP_TIMEOUT: per-call cluster deadline (default 5s); a
//     call exceeding it fails fast with a retryable unavailable error instead of
//     blocking on an unreachable cluster.
func newTigerBeetleBillingAdapter(
	ctx context.Context, logger *slog.Logger,
) (billing.Adapter, func(), error) {
	ledger, currency, err := billingLedgerCurrency()
	if err != nil {
		return nil, nil, err
	}
	addr := runhttp.EnvOr("EXCHANGE_BILLING_TB_ADDRESS", "")
	if addr == "" {
		return nil, nil, fmt.Errorf("billing: EXCHANGE_BILLING_TB_ADDRESS is required for RAMP_BILLING_ADAPTER=tigerbeetle")
	}
	cluster, err := strconv.ParseUint(runhttp.EnvOr("EXCHANGE_BILLING_TB_CLUSTER_ID", "0"), 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("billing: invalid EXCHANGE_BILLING_TB_CLUSTER_ID: %w", err)
	}
	grace, err := time.ParseDuration(runhttp.EnvOr("EXCHANGE_BILLING_HOLD_GRACE", "1m"))
	if err != nil {
		return nil, nil, fmt.Errorf("billing: invalid EXCHANGE_BILLING_HOLD_GRACE: %w", err)
	}
	var clientOpts []tigerbeetle.Option
	if raw := runhttp.EnvOr("EXCHANGE_BILLING_TB_OP_TIMEOUT", ""); raw != "" {
		opTimeout, pErr := time.ParseDuration(raw)
		if pErr != nil {
			return nil, nil, fmt.Errorf("billing: invalid EXCHANGE_BILLING_TB_OP_TIMEOUT: %w", pErr)
		}
		clientOpts = append(clientOpts, tigerbeetle.WithOpTimeout(opTimeout))
	}

	client, err := tigerbeetle.NewClient(cluster, []string{addr}, logger, clientOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("billing: connect TigerBeetle at %s: %w", addr, err)
	}
	if err := client.Health(ctx); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("billing: TigerBeetle health check: %w", err)
	}

	adapter := billing.NewTigerBeetleAdapter(billing.TigerBeetleOptions{
		Client:      client,
		Ledger:      ledger,
		Currency:    currency,
		HoldTimeout: billingURLTTL + grace,
		// IDNamespace deliberately empty: production hashing stays unsalted.
	})
	// Boot-path logs use free-text messages by convention (see keys.go /
	// keyresolver.go); dotted event names (exchange.*) are the request/lifecycle path.
	logger.Info("billing adapter: tigerbeetle",
		"ledger", ledger, "currency", currency, "address", addr,
		"hold_timeout", billingURLTTL+grace)
	return adapter, client.Close, nil
}

// billingLedgerCurrency reads EXCHANGE_BILLING_LEDGER (ISO 4217 numeric) and
// maps it to the ledger id plus its ISO 4217 alpha code. Phase 1 is
// single-currency, so only the deployed set is supported; an unknown numeric is
// a hard error rather than a silent default.
func billingLedgerCurrency() (uint32, string, error) {
	raw := runhttp.EnvOr("EXCHANGE_BILLING_LEDGER", "")
	if raw == "" {
		return 0, "", fmt.Errorf("billing: EXCHANGE_BILLING_LEDGER is required for RAMP_BILLING_ADAPTER=tigerbeetle")
	}
	numeric, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("billing: invalid EXCHANGE_BILLING_LEDGER %q: %w", raw, err)
	}
	currency, ok := currencyForLedger(uint32(numeric))
	if !ok {
		return 0, "", fmt.Errorf("billing: unsupported EXCHANGE_BILLING_LEDGER %d (supported: 978=EUR, 840=USD)", numeric)
	}
	return uint32(numeric), currency, nil
}

// currencyForLedger maps an ISO 4217 numeric code to its alpha code for the
// currencies the Exchange operates in. Extend this table when a new deployment
// currency is added (and, for multi-currency, fold the ledger into the account
// id derivation — see the design doc).
func currencyForLedger(numeric uint32) (string, bool) {
	switch numeric {
	case 978:
		return "EUR", true
	case 840:
		return "USD", true
	default:
		return "", false
	}
}
