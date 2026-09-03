package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestSelectBillingAdapter_Mapping pins the boot selector's adapter mapping and
// the unknown-value fallback (the backend is selected via RAMP_BILLING_ADAPTER).
// The tigerbeetle happy path needs a live cluster and is covered by the
// transport E2E; here we assert the non-TB branches and the TB fail-fast on
// misconfiguration (config is validated before any connection opens).
func TestSelectBillingAdapter_Mapping(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr bool
		assert  func(t *testing.T, a billing.Adapter)
	}{
		{
			name: "default free when unset",
			env:  "",
			assert: func(t *testing.T, a billing.Adapter) {
				if _, ok := a.(billing.FreeAdapter); !ok {
					t.Fatalf("adapter = %T, want billing.FreeAdapter", a)
				}
			},
		},
		{
			name: "free",
			env:  "free",
			assert: func(t *testing.T, a billing.Adapter) {
				if _, ok := a.(billing.FreeAdapter); !ok {
					t.Fatalf("adapter = %T, want billing.FreeAdapter", a)
				}
			},
		},
		{
			name: "inmemory",
			env:  "inmemory",
			assert: func(t *testing.T, a billing.Adapter) {
				if _, ok := a.(*billing.InMemoryAdapter); !ok {
					t.Fatalf("adapter = %T, want *billing.InMemoryAdapter", a)
				}
			},
		},
		{
			name: "unknown falls back to free",
			env:  "bogus",
			assert: func(t *testing.T, a billing.Adapter) {
				if _, ok := a.(billing.FreeAdapter); !ok {
					t.Fatalf("adapter = %T, want billing.FreeAdapter", a)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RAMP_BILLING_ADAPTER", tc.env)
			got, currency, cleanup, err := selectBillingAdapter(context.Background(), discardLogger())
			if err != nil {
				t.Fatalf("selectBillingAdapter: %v", err)
			}
			t.Cleanup(cleanup)
			if currency != "USD" {
				t.Fatalf("currency = %q, want USD for the demo tiers", currency)
			}
			tc.assert(t, got)
		})
	}
}

// TestSelectBillingAdapter_TigerBeetleFailFast confirms an explicitly-selected
// tigerbeetle backend fails boot (rather than silently degrading to free) when
// its configuration is missing or unsupported — validated before any connection.
func TestSelectBillingAdapter_TigerBeetleFailFast(t *testing.T) {
	cases := []struct {
		name   string
		ledger string
		addr   string
	}{
		{"missing ledger", "", "127.0.0.1:3000"},
		{"unsupported ledger", "999", "127.0.0.1:3000"},
		{"missing address", "840", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RAMP_BILLING_ADAPTER", "tigerbeetle")
			t.Setenv("EXCHANGE_BILLING_LEDGER", tc.ledger)
			t.Setenv("EXCHANGE_BILLING_TB_ADDRESS", tc.addr)
			got, _, _, err := selectBillingAdapter(context.Background(), discardLogger())
			if err == nil {
				t.Fatalf("want error, got adapter %T", got)
			}
		})
	}
}

// TestNewBillingAdapter_SeedRejectsForeignCurrency pins the composition root's
// half of the two-currency rule on the in-memory tier. EXCHANGE_BILLING_SEED is
// the only production path that could create a balance denominated in something
// other than the demo currency: billing.NewAmount does not validate the currency
// string, so the JSON's value is taken as written.
//
// Such a balance is not merely unusable. It cannot receive the Register welcome
// credit, and because a publisher's catalog term carries its own currency, a
// term priced in that currency would match and spend it. The entry is therefore
// skipped, and the warning must name the agent and the expected currency so the
// operator can find the typo — a silent skip would read as "the seed applied".
func TestNewBillingAdapter_SeedRejectsForeignCurrency(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	t.Setenv("EXCHANGE_BILLING_SEED",
		`{"agent-usd": {"value": "5.00", "currency": "USD"},
		  "agent-eur": {"value": "5.00", "currency": "EUR"}}`)

	a := newBillingAdapter(logger)
	ctx := context.Background()

	// The well-formed USD entry in the same seed is kept: one bad entry must not
	// discard the others.
	kept, err := a.GetBalance(ctx, "agent-usd")
	if err != nil {
		t.Fatalf("GetBalance(agent-usd): %v", err)
	}
	if kept.Currency != billing.DemoCurrency || kept.Value.FloatString(2) != "5.00" {
		t.Errorf("agent-usd balance = %s %s, want 5.00 %s",
			kept.Value.FloatString(2), kept.Currency, billing.DemoCurrency)
	}

	// The EUR entry is absent entirely, not present with a coerced currency.
	if _, err := a.GetBalance(ctx, "agent-eur"); err == nil {
		t.Error("agent-eur has a balance; the EUR seed entry must be skipped")
	}

	out := logs.String()
	if !strings.Contains(out, "agent-eur") || !strings.Contains(out, "EUR") {
		t.Errorf("warning must name the agent and its currency, got:\n%s", out)
	}
	if !strings.Contains(out, billing.DemoCurrency) {
		t.Errorf("warning must name the expected currency, got:\n%s", out)
	}
}
