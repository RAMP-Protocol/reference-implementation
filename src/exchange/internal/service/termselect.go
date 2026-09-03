package service

import (
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// selectTerms projects a publisher's terms down to those the requester is
// entitled to. It is the SINGLE source of term-eligibility in the Exchange: the
// discovery path calls selectTerms before projecting terms onto Offer.terms and
// never reimplements this filtering itself. Token canonicalization and the
// ingest-tier term checks are the SDK's (sdk/go/helpers); this scope projection
// is the one piece of term logic the Exchange keeps, because it is Exchange
// behaviour rather than a protocol rule.
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
// enforced at accept→report→reconcile). A REFERENCE_ONLY term's machine fields,
// when present, are an advisory summary of the referenced License document,
// which governs; they are not evaluated here either.
//
// A nil requester selects nothing (no requester, no entitlement). selectTerms
// never mutates its inputs, and the terms it returns are the same pointers it
// was given, in stored order — headlineIndex recovers the publisher's term
// index by pointer identity.
//
// TRUST CAVEAT (deferred verification): requester.scopes is a self-declared wire
// field — the Exchange currently TRUSTS it without attestation. Scope coverage
// is therefore an honest projection of intent, NOT yet an authorization
// boundary: an agent could claim any scope. Scope verification (entitlement
// biscuit attenuation + WBA-bound identity) is deliberately deferred; when it
// lands, scopes will be verified upstream and this function is
// unchanged. Until then, do not treat scope coverage as an access-control gate.
func selectTerms(terms []*rampv1.LicenseTerm, requester *rampv1.Requester) []*rampv1.LicenseTerm {
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
