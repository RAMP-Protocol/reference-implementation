// ADR-008 D2 obligation tests for the Broker-side absence_reason
// vocabulary. Each test asserts on the specific enum value (NOT on
// len(offers)==0 / truthiness) so a regression that collapses all
// causes to one value is caught at the helper boundary.
//
// W1 of the proto-rename wave dropped the project-specific enum values
// (NO_HEALTHY_EXCHANGE, NO_AGENT_ENTITLEMENT, GRANTS_DO_NOT_COVER,
// UNKNOWN_RESOURCE, INTERNAL_ERROR, OUTSTANDING_OBLIGATIONS,
// BILLING_BLOCK, SUBSCRIPTION_EXPIRED) in favour of the canonical
// RAMP-protocol vocabulary (NOT_IN_CATALOG, SCOPE_INSUFFICIENT,
// NOT_AUTHORIZED, TEMPORARILY_UNAVAILABLE). The assertions below
// follow the new mapping documented on
// `pickResolveAbsenceReason` in resolve_responses.go.

package resolve

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestPickResolveAbsenceReason exhaustively covers the branches of
// pickResolveAbsenceReason after the W1 proto rename. The precedence
// order mirrors the production reasoning: transient upstream-wide
// failures beat refusals, upstream-propagated reasons beat the
// broker-local fallbacks.
func TestPickResolveAbsenceReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		flags discoverFlags
		want  rampv1.OfferAbsenceReason
	}{
		{
			name: "TEMPORARILY_UNAVAILABLE: every upstream call failed",
			flags: discoverFlags{
				allUpstreamFailed: true,
				// scopeRestricted/upstreamReason cannot suppress
				// the transient-upstream verdict — ADR-008 D2 rule.
				scopeRestricted: true,
				upstreamReason:  rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT,
			},
			want: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE,
		},
		{
			name: "upstream NOT_IN_CATALOG propagates",
			flags: discoverFlags{
				upstreamReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
			},
			want: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
		},
		{
			name: "upstream NOT_AUTHORIZED propagates",
			flags: discoverFlags{
				upstreamReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED,
			},
			want: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED,
		},
		{
			name: "upstream SCOPE_INSUFFICIENT propagates",
			flags: discoverFlags{
				upstreamReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT,
			},
			want: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT,
		},
		{
			name: "SCOPE_INSUFFICIENT: scopeRestricted, no upstream reason",
			flags: discoverFlags{
				scopeRestricted: true,
			},
			want: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT,
		},
		{
			name:  "NOT_IN_CATALOG: nothing else set (catalog miss)",
			flags: discoverFlags{},
			want:  rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickResolveAbsenceReason(tc.flags)
			if got != tc.want {
				t.Fatalf("absence_reason = %v, want %v", got, tc.want)
			}
		})
	}
}
