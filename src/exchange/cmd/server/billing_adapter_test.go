package main

import (
	"context"
	"io"
	"log/slog"
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
			got, cleanup, err := selectBillingAdapter(context.Background(), discardLogger())
			if err != nil {
				t.Fatalf("selectBillingAdapter: %v", err)
			}
			t.Cleanup(cleanup)
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
			got, _, err := selectBillingAdapter(context.Background(), discardLogger())
			if err == nil {
				t.Fatalf("want error, got adapter %T", got)
			}
		})
	}
}
