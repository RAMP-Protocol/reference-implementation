package licenseterm

import (
	"fmt"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/quotametrics"
)

// Validate checks a LicenseTerm for the structural, coherence and vocabulary
// rules this layer owns, returning non-fatal lint warnings (surfaced in
// PushResourcesResponse.warnings[]) and a fatal error for hard violations. It is
// the single home for term validation (doc.go): every rule the proto/ADR
// documents is either ENFORCED here (hard reject) or SURFACED here (warning) —
// no term rule is asserted only by a unit struct call, all are reachable via the
// PushResources surface.
//
// Validate does NOT mutate the term: canonicalization is Normalize's job and the
// handler runs Normalize first, so Validate sees already-canonical tokens (this
// is what makes the permitted∩prohibited intersection case-correct).
//
// Division of labour with protovalidate (RPC boundary): protovalidate owns the
// STRUCTURAL + cross-field hard-rejects — Pricing.unit / Quota.metric token
// FORMAT, PER_UNIT⇒unit set, FREE⇒rate 0, enum UNSPECIFIED sentinels — and they
// are NOT re-checked here. Validate owns everything FORMAT cannot express:
// registry MEMBERSHIP and cross-field COHERENCE.
//
// Hard rejects (err):
//   - Pricing-required, REFERENCE_ONLY⇒License.uri, and uri⇒uri_digest are SHAPE
//     rules now enforced by protovalidate (proto CEL) at the RPC boundary,
//     per-term — NOT here. REFERENCE_ONLY machine fields are permitted (an
//     advisory readable summary of the referenced document) and are validated +
//     canonicalized like any ENUMERATED term; the publisher certifies they do
//     not contradict that document (an attestation, not an ingest check).
//   - Pricing.unit / Quota.metric bare (non-namespaced) tokens MUST be
//     registered metering / quota tokens (membership). Namespaced (vendor:token)
//     values are deliberate custom units and pass.
//
// Coherence rules — Quota.limit ≥ 1, permitted ∩ prohibited disjoint, at most
// one Restriction per kind, and SHARE_ALIKE ⇒ scope_license — are SHAPE rules
// enforced by protovalidate (proto CEL) at the RPC boundary, NOT here.
//
// Lint warnings (term accepted, surfaced in warnings[]):
//   - A bare, unregistered Restriction token (any restriction) — vocab is
//     forward-compatible; unknown ≠ invalid, just flagged so publishers can fix
//     feeds. Membership is decoupled from the Restriction.advisory flag: under
//     scope-only projection the Exchange never evaluates restrictions, so an
//     unknown token can never gate access — it only warrants a lint flag.
//   - Obligation{kind=OTHER} without detail — descriptive, not fatal.
//
// Error type — intentionally a bare `error`, NOT the typed `*exchange.Error`
// that service.ValidateUsageReport returns. The divergence is
// deliberate and load-bearing, not an oversight:
//   - This validator's hard-reject error is NEVER mapped to a connect.Code. The
//     sole caller (service.CatalogService.validateEntryTerms) catches it and
//     FLATTENS it to the per-entry verdict RejectionReasonInvalidTerms — the
//     term-level failure becomes one of many CatalogPushRejection rows in a
//     successful PushResources response, not an RPC-level error. A `Kind` tag
//     would therefore be dead weight: nothing downstream reads it.
//   - licenseterm is a pure sub-library over rampv1.LicenseTerm with no service
//     dependencies. Coupling it to the service-layer exchange.Error package to
//     carry a Kind nobody consumes would invert the dependency direction (a
//     vocabulary/validation leaf importing a transport-facing error type) for no
//     behavioural gain. service.ValidateUsageReport returns the typed error precisely
//     because ITS failures DO become connect.Codes on the ReportUsage surface;
//     this validator's do not, so the bare error is the correct minority form.
//
// If a future slice needs per-rule rejection reasons to survive past the handler
// onto the wire, promote these hard-rejects to a typed verdict enum mirroring
// service.ValidateUsageReport's ValidationOutcome — but only then.
func Validate(term *rampv1.LicenseTerm, vocab VocabProvider) (warnings []string, err error) {
	// Pricing-required, REFERENCE_ONLY⇒License.uri and uri⇒uri_digest are SHAPE
	// rules enforced by protovalidate at the RPC boundary (proto CEL), not here.
	if err := validatePricingUnitMembership(term.GetPricing().GetUnit()); err != nil {
		return nil, err
	}
	if err := validateQuotas(term.GetQuotas()); err != nil {
		return nil, err
	}
	warnings = append(warnings, validateRestrictions(term.GetRestrictions(), vocab)...)
	warnings = append(warnings, validateObligations(term.GetObligations())...)
	return warnings, nil
}

// validatePricingUnitMembership rejects a bare Pricing.unit that is not a
// registered metering token. Empty (no unit) and namespaced (vendor:token)
// units are not membership-checked — the former is governed by protovalidate's
// PER_UNIT⇒unit cross-field rule, the latter is a deliberate custom unit.
func validatePricingUnitMembership(unit string) error {
	if isBareUnregistered(unit, pricingunits.IsRegistered) {
		return fmt.Errorf("pricing unit %q is not a registered metering token", unit)
	}
	return nil
}

// validateQuotas hard-rejects a bare, unregistered metric token. Quota.metric
// FORMAT and Quota.limit ≥ 1 are protovalidate's; registry membership is
// licenseterm's. Namespaced (vendor:token) metrics pass.
func validateQuotas(quotas []*rampv1.Quota) error {
	for _, q := range quotas {
		if isBareUnregistered(q.GetMetric(), quotametrics.IsRegistered) {
			return fmt.Errorf("quota metric %q is not a registered quota token", q.GetMetric())
		}
	}
	return nil
}

// validateRestrictions returns lint warnings for unregistered restriction
// tokens — the term is admitted either way. Coherence (one restriction per kind,
// permitted∩prohibited disjoint) is protovalidate's; registry membership — a
// warning, not a reject (open vocab) — is licenseterm's. Tokens are assumed
// already canonical (Normalize ran first).
//
// An unregistered bare token is forward-compatible (a token this Exchange's
// registry has not learned yet, or a vendor token that should have been
// namespaced), so it warns rather than rejects. Under scope-only projection the
// Exchange never evaluates restrictions; they ride on the offer as metadata and
// the agent self-selects (ADR-014 §Selection).
func validateRestrictions(restrictions []*rampv1.Restriction, vocab VocabProvider) []string {
	var warnings []string
	for _, r := range restrictions {
		kind := r.GetKind()
		for _, tok := range allTokens(r) {
			if isNamespaced(tok) || vocab.Known(kind, tok) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("unregistered %s restriction token %q (term accepted)", kind, tok))
		}
	}
	return warnings
}

// validateObligations lint-warns OTHER obligations lacking detail. SHARE_ALIKE's
// scope_license requirement is protovalidate's now.
func validateObligations(obligations []*rampv1.Obligation) []string {
	var warnings []string
	for _, o := range obligations {
		if o.GetKind() == rampv1.ObligationKind_OBLIGATION_KIND_OTHER && o.GetDetail() == "" {
			warnings = append(warnings, "obligation of kind OTHER has no detail (term accepted)")
		}
	}
	return warnings
}

// isBareUnregistered reports whether token is a non-empty, non-namespaced value
// that the given registry does not recognize. Empty and namespaced
// (vendor:token) tokens are never membership-checked.
func isBareUnregistered(token string, registered func(string) bool) bool {
	if token == "" || isNamespaced(token) {
		return false
	}
	return !registered(token)
}

// isNamespaced reports whether a token is a vendor-namespaced custom value
// (contains a ':'). Namespaced tokens are deliberate extensions and bypass
// registry membership on every axis.
func isNamespaced(token string) bool {
	return strings.Contains(token, ":")
}

// allTokens returns the union of a restriction's permitted and prohibited
// tokens for membership checking.
func allTokens(r *rampv1.Restriction) []string {
	return append(append([]string{}, r.GetPermitted()...), r.GetProhibited()...)
}

// Select projects a publisher's terms down to those the requester is entitled
// to. It is the SINGLE source of term-eligibility in the Exchange: the discovery
// handler calls Select before projecting terms onto Offer.terms and never
// reimplements this filtering itself.
//
// A term is kept iff the requester's Biscuit authority (Requester.scopes)
// covers ALL of the term's scopes (AND-coverage). An empty term scopes[] is
// public. Coverage is hierarchical: a requester scope "a:*" covers "a:US" and a
// bare "*" covers everything. Scope coverage is the ONLY eligibility filter.
//
// Restriction axes (USER_TYPE, GEOGRAPHY, FUNCTION) are NOT used to exclude
// terms here. A requester's attributes are self-declared and unvalidated, so
// filtering by them would be advisory at best and is the agent's concern, not
// the Exchange's (ADR-014: the Exchange filters by resource_id and scopes only;
// restrictions ride on the returned offer for the agent to self-honour, and are
// enforced at accept→report→reconcile). REFERENCE_ONLY terms likewise carry no
// machine restrictions (Validate rejects them at ingest); the License document
// governs.
//
// A nil requester selects nothing (no requester, no entitlement). Select never
// mutates its inputs.
//
// TRUST CAVEAT (deferred verification): requester.scopes is a self-declared wire
// field — the Exchange currently TRUSTS it without attestation. Scope coverage
// is therefore an honest projection of intent, NOT yet an authorization
// boundary: an agent could claim any scope. Scope verification (entitlement
// biscuit attenuation + WBA-bound identity) is deliberately deferred; when it
// lands, scopes will be verified upstream and this function is
// unchanged. Until then, do not treat scope coverage as an access-control gate.
func Select(terms []*rampv1.LicenseTerm, requester *rampv1.Requester) []*rampv1.LicenseTerm {
	if requester == nil {
		return nil
	}
	scopes := requester.GetScopes() // self-declared, trusted-for-now (see TRUST CAVEAT)
	out := make([]*rampv1.LicenseTerm, 0, len(terms))
	for _, term := range terms {
		if term == nil {
			continue
		}
		if !scopesCovered(term.GetScopes(), scopes) {
			continue
		}
		out = append(out, term)
	}
	return out
}

// scopesCovered reports whether every term scope is covered by some requester
// scope. Empty termScopes is public (always covered).
func scopesCovered(termScopes, requesterScopes []string) bool {
	for _, ts := range termScopes {
		if !scopeCovered(ts, requesterScopes) {
			return false
		}
	}
	return true
}

// scopeCovered reports whether termScope is covered by any requester scope. A
// requester scope covers a term scope when it is exactly equal, is the global
// "*", or is a hierarchical wildcard "prefix:*" whose prefix matches the term
// scope's prefix (so "dist:*" covers "dist:US" and "dist").
func scopeCovered(termScope string, requesterScopes []string) bool {
	for _, rs := range requesterScopes {
		if rs == "*" || rs == termScope {
			return true
		}
		if prefix, ok := strings.CutSuffix(rs, ":*"); ok {
			if termScope == prefix || strings.HasPrefix(termScope, prefix+":") {
				return true
			}
		}
	}
	return false
}

// Canonicalization (Normalize, canonicalToken, the alias maps and helpers) lives
// in canonical.go — the single home of the per-axis token rule the STORED side
// (Normalize) delegates to before persistence and Validate.
