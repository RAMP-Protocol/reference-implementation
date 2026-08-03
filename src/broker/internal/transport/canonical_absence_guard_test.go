// Structural guard for the typed-absence-reason contract: the broker's refusal cause MUST
// be emitted ONLY on the typed DiscoveryResponse.absence_reason field (proto field
// 16) — never under a ramp.broker.absence_reason ext key — and the licensed /
// no-refusal path MUST emit neither. This is the class-level counter-measure to
// the disease this guard cures: a cause computed as an enum but smuggled to the wire
// via ext. It is intentionally exhaustive over every OfferAbsenceReason value
// (driven from the generated proto enum map) so a new enum value, or a future
// edit that re-introduces the ext smuggle, breaks the build at the single
// typed-emission point (toDiscoveryResponse / brokerExt).
//
// White-box (package transport) unit test of the pure mapper toDiscoveryResponse:
// permitted by Testing Doctrine pt 2 (pure logic / mapper with >3 branches),
// matching the existing resolve_responses_test.go guard precedent.

package transport

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
)

// absenceExtKey is the contractual ext key the canonical-absence work ELIMINATED. The guards below
// assert it is NEVER present — it exists here only as the thing they forbid.
const absenceExtKey = "ramp.broker.absence_reason"

// TestAbsenceReasonTypedOnly is the positive guard: for EVERY non-zero
// OfferAbsenceReason, toDiscoveryResponse emits the typed field AND emits NO
// ramp.broker.absence_reason ext key (ADR-019 — the typed field is the
// sole refusal-cause surface). Iterates the generated enum name map so a
// newly-added enum value is covered automatically.
func TestAbsenceReasonTypedOnly(t *testing.T) {
	t.Parallel()
	for v, name := range rampv1.OfferAbsenceReason_name {
		reason := rampv1.OfferAbsenceReason(v)
		if reason == rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
			continue // UNSPECIFIED is the no-refusal sentinel — see the negative guard.
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := toDiscoveryResponse(&resolve.Response{AbsenceReason: reason})

			if got := out.GetAbsenceReason(); got != reason {
				t.Errorf("typed absence_reason = %v, want %v", got, reason)
			}
			if _, ok := out.GetExt().GetFields()[absenceExtKey]; ok {
				t.Errorf("ext %q present — the refusal cause must ride ONLY on the typed field", absenceExtKey)
			}
		})
	}
}

// TestAbsenceReasonOmittedWhenNoRefusal is the negative guard: the
// licensed-discovery / no-refusal path (ranked Offers set, AbsenceReason
// UNSPECIFIED) emits NEITHER the typed field (stays nil → GetAbsenceReason() ==
// UNSPECIFIED) NOR the ext key. This pins the UNSPECIFIED-guard so a regression
// back to a truthiness/non-empty guard (which would emit on the
// licensed-discovery path) is caught.
func TestAbsenceReasonOmittedWhenNoRefusal(t *testing.T) {
	t.Parallel()
	out := toDiscoveryResponse(&resolve.Response{
		Groups: []resolve.OfferGroup{{
			URI:    "https://acme.example/article-42",
			Offers: []selection.Candidate{{Offer: core.RejectedOffer{Offer: &rampv1.Offer{OfferId: "offer-1"}}.Unsafe()}},
		}},
	})

	if len(out.GetOfferGroups()) == 0 {
		t.Fatal("expected offer_groups on the licensed-discovery path")
	}
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
		t.Errorf("typed absence_reason = %v, want UNSPECIFIED on the licensed-discovery path", got)
	}
	if _, ok := out.GetExt().GetFields()[absenceExtKey]; ok {
		t.Errorf("ext %q present on the licensed-discovery path, want omitted", absenceExtKey)
	}
}
