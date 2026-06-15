package transport

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// refusalProofMissing is the machine-readable error message surfaced when
// the upstream Exchange flagged offers as scope-restricted and the caller
// supplied no credential. Matches the obligation-05 vocabulary so operator
// tooling can triage.
const refusalProofMissing = "proof missing"

// noOffersReason picks the machine-readable error message for a
// no-offers resolve. When the Exchange flagged the entry as
// scope-restricted, the proof is missing — that is the obligation-05
// vocabulary an operator can triage on. Otherwise we fall back to the
// generic "no offers" message.
func noOffersReason(_ context.Context, scopeRestricted bool) string {
	if scopeRestricted {
		return refusalProofMissing
	}
	return "no offers returned by exchanges"
}

// isCredentialsRestricted reports whether an OfferAbsenceReason indicates
// the caller needs additional credentials to unlock an offer. The canonical
// proto (W1 of t3vk) collapsed the scope-gate and subscription-gate
// vocabularies onto a single SCOPE_INSUFFICIENT enum value; the broker
// boundary continues to treat them uniformly.
func isCredentialsRestricted(r rampv1.OfferAbsenceReason) bool {
	return r == rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT
}

// probeOutcome accumulates the per-domain probe results so the
// refusal-shape selector can map "no manifests at all" to the correct
// canonical absence vocabulary. v1 publishers MUST host ramp.json;
// missing → NOT_IN_CATALOG, transient → TEMPORARILY_UNAVAILABLE.
type probeOutcome struct {
	missing   int // ErrManifestMissing — publisher has no ramp.json
	transient int // ErrProbeFailed / unexpected error — upstream unreachable
}

// discoverFlags accumulates the per-exchange observations the
// caller needs to map to a ResolveResponse.AbsenceReason.
type discoverFlags struct {
	// scopeRestricted is true when any upstream OfferGroup carried the
	// scope-insufficient or subscription-required vocabulary — the
	// "credentials short" case.
	scopeRestricted bool
	// upstreamReason is the most recent non-UNSPECIFIED request-level
	// absence reason an upstream Exchange surfaced. The broker
	// preserves this signal when none of the exchanges returned an
	// offer so the caller doesn't lose the structured cause across the
	// proxy hop.
	upstreamReason rampv1.OfferAbsenceReason
	// allUpstreamFailed is true when every upstream Exchange call
	// failed (transient RPC errors). The resolve response is then
	// stamped INTERNAL_ERROR rather than a refusal-shaped reason.
	allUpstreamFailed bool
}

// noHealthyExchangeResponse is the canonical broker-side response
// when a publisher manifest exists but none of its referenced
// exchanges is healthy. Surfaces as TEMPORARILY_UNAVAILABLE on the
// wire — the W1 proto sync (t3vk) removed the bespoke
// NO_HEALTHY_EXCHANGE enum and the transient-upstream semantic now
// rides on TEMPORARILY_UNAVAILABLE. v1 emits no bare_url — every
// publisher MUST host ramp.json, so a refusal here is a real refusal,
// not a redirect to unbrokered fetch.
func noHealthyExchangeResponse() *ResolveResponse {
	return &ResolveResponse{
		Licensed:      false,
		AbsenceReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE.String(),
	}
}

// probeRefusalResponse is the broker's response when probeDomains
// yielded zero usable manifests. Per v1, every publisher MUST host
// /.well-known/ramp.json; the absence_reason distinguishes a publisher
// that returned 404 (NOT_IN_CATALOG — the canonical refusal) from a
// publisher whose manifest fetch failed transiently
// (TEMPORARILY_UNAVAILABLE). Mixed outcomes prefer NOT_IN_CATALOG only
// when no transient failures were observed.
func probeRefusalResponse(outcome probeOutcome) *ResolveResponse {
	reason := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
	if outcome.transient > 0 && outcome.missing == 0 {
		reason = rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE
	}
	return &ResolveResponse{
		Licensed:      false,
		AbsenceReason: reason.String(),
	}
}

// noOffersResponse is the broker's structured-cause response when the
// upstream exchanges all returned (without RPC errors) but produced
// no offers — either because of an upstream reason that propagates
// through, a credentials-restricted filter, or a generic empty-offers
// outcome. The free-text Error field carries the obligation-05
// vocabulary; AbsenceReason carries the ADR-008 D2 enum.
func noOffersResponse(
	ctx context.Context, flags discoverFlags,
) *ResolveResponse {
	return &ResolveResponse{
		Licensed:      false,
		Error:         noOffersReason(ctx, flags.scopeRestricted),
		AbsenceReason: pickResolveAbsenceReason(flags).String(),
	}
}

// budgetExhaustedResponse is the broker's response when the caller's
// budget would not cover the winning offer's price. Surfaces as
// NOT_AUTHORIZED on the wire — the W1 proto sync (t3vk) dropped the
// bespoke BILLING_BLOCK enum value; a budget-side authorization failure
// is reasonably modelled as caller-not-authorized to spend.
func budgetExhaustedResponse(budgetState *BudgetState) *ResolveResponse {
	return &ResolveResponse{
		Licensed:      false,
		Error:         "budget exhausted",
		Budget:        budgetState,
		AbsenceReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED.String(),
	}
}

// pickResolveAbsenceReason maps the per-exchange observations from
// the resolve hot path to the ADR-008 D2 request-level absence-reason
// vocabulary. Order of precedence:
//
//  1. allUpstreamFailed → TEMPORARILY_UNAVAILABLE (transient: every
//     Exchange RPC raised an error). ADR-008 D2 is explicit that an
//     internal failure must never be miscategorised as a clean refusal.
//     The W1 proto sync (t3vk) dropped the bespoke INTERNAL_ERROR
//     enum; TEMPORARILY_UNAVAILABLE carries the transient-upstream
//     semantic on the canonical surface.
//  2. upstreamReason set → propagate the upstream cause unchanged so
//     the caller sees the same vocabulary across the proxy hop.
//  3. scopeRestricted → SCOPE_INSUFFICIENT (caller's biscuit did not
//     unlock any offer; collapses the prior GRANTS_DO_NOT_COVER value
//     onto the canonical scope-gate vocabulary).
//  4. Otherwise NOT_IN_CATALOG — generic empty-offers fallback,
//     replacing the prior UNKNOWN_RESOURCE value.
func pickResolveAbsenceReason(flags discoverFlags) rampv1.OfferAbsenceReason {
	if flags.allUpstreamFailed {
		return rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE
	}
	if flags.upstreamReason != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
		return flags.upstreamReason
	}
	if flags.scopeRestricted {
		return rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT
	}
	return rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
}
