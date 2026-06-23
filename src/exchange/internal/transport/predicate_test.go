package transport_test

import (
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestGlobalSigRequestPredicate captures the universal-signing entry policy:
// every /ramp.* RPC except CatalogService MUST clear the RFC 9421
// static-resolver gate, regardless of whether Signature-Input is set on the
// wire (an unsigned request fails verification at the middleware; the
// predicate's job is to mark the path as gated, not to short-circuit on header
// presence). CatalogService is excluded because CatalogSignatureMiddleware runs
// a per-contributor signer further down — Catalog requests are still verified,
// just by a different mechanism. Non-ramp paths (healthz, /.well-known) are
// public.
func TestGlobalSigRequestPredicate(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		hasSigHdr bool
		want      bool
	}{
		{"DiscoverResources unsigned still must verify", "/ramp.v1.ExchangeService/DiscoverResources", false, true},
		{"ExecuteTransaction unsigned still must verify", "/ramp.v1.ExchangeService/ExecuteTransaction", false, true},
		{"ReportUsage unsigned still must verify", "/ramp.v1.ExchangeService/ReportUsage", false, true},
		{"DiscoverResources signed must verify", "/ramp.v1.ExchangeService/DiscoverResources", true, true},
		{"ExecuteTransaction signed must verify", "/ramp.v1.ExchangeService/ExecuteTransaction", true, true},
		{"ReportUsage signed must verify", "/ramp.v1.ExchangeService/ReportUsage", true, true},
		{"CatalogService path excluded (signed)", "/ramp.v1.CatalogService/PushResources", true, false},
		{"CatalogService path excluded (unsigned)", "/ramp.v1.CatalogService/PushResources", false, false},
		{"healthz outside ramp.* namespace", "/healthz", false, false},
		{"well-known outside ramp.* namespace", "/.well-known/ramp.json", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, http.NoBody)
			if tc.hasSigHdr {
				r.Header.Set("Signature-Input", `sig=("@method");keyid="k";created=1`)
			}
			if got := transport.GlobalSigRequestPredicate(r); got != tc.want {
				t.Fatalf("predicate(%s, sig=%v) = %v, want %v", tc.path, tc.hasSigHdr, got, tc.want)
			}
		})
	}
}
