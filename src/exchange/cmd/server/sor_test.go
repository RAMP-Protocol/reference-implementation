package main

import (
	"context"
	"strings"
	"testing"
)

// TestSelectSoRAdapter_Mapping pins the SoR boot selector's routing and its
// deliberate fail-fast on an unknown backend — the divergence from
// selectBillingAdapter, which silently falls back to free (AC #5). The Postgres
// happy path needs a live database and is covered by the sor package
// integration suite; every case here is designed to fail BEFORE a pool opens,
// so no real database is required:
//   - the unknown-value case is rejected by the selector itself;
//   - the postgres cases fail on env validation (missing DSN, invalid TTL),
//     which the constructor performs before db.Open dials — proving both that
//     the default routes to the postgres path and that all env is validated
//     ahead of the pool (no leaked socket).
func TestSelectSoRAdapter_Mapping(t *testing.T) {
	tests := []struct {
		name    string
		adapter string
		dsn     string
		ttl     string
		wantErr string
	}{
		{
			// Unset RAMP_SOR_ADAPTER must resolve to postgres; with the DSN
			// missing that path fails fast, which is how we observe the routing.
			name:    "default routes to postgres, missing DSN fails fast",
			adapter: "",
			dsn:     "",
			wantErr: "EXCHANGE_SOR_DSN is required",
		},
		{
			name:    "explicit postgres, missing DSN fails fast",
			adapter: "postgres",
			dsn:     "",
			wantErr: "EXCHANGE_SOR_DSN is required",
		},
		{
			name:    "unknown adapter fails boot naming the value",
			adapter: "bogus",
			wantErr: `unknown RAMP_SOR_ADAPTER "bogus"`,
		},
		{
			// DSN is present but never dialed: the TTL parse runs first and
			// fails, proving env is validated before the pool opens.
			name:    "invalid cache TTL fails before pool opens",
			adapter: "postgres",
			dsn:     "postgres://unused:unused@127.0.0.1:1/unused",
			ttl:     "not-a-duration",
			wantErr: "invalid EXCHANGE_SOR_CACHE_TTL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RAMP_SOR_ADAPTER", tc.adapter)
			t.Setenv("EXCHANGE_SOR_DSN", tc.dsn)
			t.Setenv("EXCHANGE_SOR_CACHE_TTL", tc.ttl)
			got, cleanup, err := selectSoRAdapter(context.Background(), discardLogger())
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			if err == nil {
				t.Fatalf("want error containing %q, got adapter %T", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}
