package licenseterm

import (
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// functionAliases maps non-canonical FUNCTION tokens to their canonical form.
// Keys are already trimmed+lowercased before lookup.
var functionAliases = map[string]string{
	"generative-ai": "ai-input",
	"train-ai":      "ai-train",
	"scrape":        "crawl",
	"tdm":           "text-and-data-mining",
	"copy":          "reproduce",
	"adapt":         "modify",
	"derivative":    "modify",
}

// userTypeAliases maps non-canonical USER_TYPE tokens to their canonical form.
// Keys are already trimmed+lowercased before lookup.
var userTypeAliases = map[string]string{
	"personal":   "individual",
	"business":   "commercial_entity",
	"enterprise": "commercial_entity",
}

// Normalize canonicalizes a term's restriction tokens in place so that
// downstream Validate and Select compare against a single canonical vocabulary.
// It is the sole home of token canonicalization (doc.go contract) and is
// idempotent: Normalize(Normalize(t)) == Normalize(t).
//
// Canonicalization is per restriction axis (Restriction.kind), applied to both
// permitted[] and prohibited[]:
//
//   - FUNCTION (the proto zero value) and USER_TYPE: trim + lowercase, then
//     resolve aliases (e.g. generative-ai→ai-input, personal→individual).
//   - GEOGRAPHY: trim + UPPERCASE (ISO-3166 alpha-2 plus EU/EEA/*); no aliases.
//   - OTHER: left untouched — it carries custom, registry-less tokens.
//
// The handler MUST call Normalize before persisting and before Validate so the
// stored catalog row and the DiscoverResources→Offer.terms projection both
// carry canonical tokens.
func Normalize(term *rampv1.LicenseTerm) {
	for _, r := range term.GetRestrictions() {
		canon := canonicalizerFor(r.GetKind())
		if canon == nil {
			continue
		}
		canonicalizeTokens(r.GetPermitted(), canon)
		canonicalizeTokens(r.GetProhibited(), canon)
	}
}

// canonicalizerFor returns the per-token canonicalizer for an axis, or nil when
// the axis carries no canonicalization rule (OTHER) — nil lets Normalize skip
// the axis entirely. When non-nil, it delegates to canonicalToken, the single
// owner of the per-axis rule, so the stored catalog row and the
// DiscoverResources→Offer.terms projection carry one canonical token form.
func canonicalizerFor(kind rampv1.RestrictionKind) func(string) string {
	if !hasCanonicalRule(kind) {
		return nil // RESTRICTION_KIND_OTHER and any unknown axis: leave tokens as-is.
	}
	return func(tok string) string { return canonicalToken(kind, tok) }
}

// hasCanonicalRule reports whether an axis carries a canonicalization rule. Only
// the rule-bearing axes (FUNCTION, USER_TYPE, GEOGRAPHY) are canonicalized;
// OTHER and any unknown axis carry custom, registry-less tokens left as-is.
func hasCanonicalRule(kind rampv1.RestrictionKind) bool {
	switch kind {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
		rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
		rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return true
	default:
		return false
	}
}

// canonicalToken is the SINGLE source of the per-axis token canonicalization
// rule. The STORED side (Normalize, via canonicalizerFor) routes every
// restriction token through this function before persistence and Validate, so
// the catalog row and the DiscoverResources→Offer.terms projection carry one
// canonical token form and membership checks compare against canonical vocab.
//
// Per axis:
//   - FUNCTION and USER_TYPE: trim + lowercase, then resolve aliases.
//   - GEOGRAPHY: trim + UPPERCASE (ISO-3166 alpha-2 plus EU/EEA/*); no aliases.
//     This is the canonical geography form: the registry (geographytokens +
//     isoAlpha2) and the fixtures both represent geos as uppercase ISO codes, so
//     uppercasing is the rule that makes stored tokens compare and
//     membership-check correctly.
//   - OTHER and any unknown axis: returned unchanged (no rule).
func canonicalToken(kind rampv1.RestrictionKind, tok string) string {
	switch kind {
	case rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION:
		return resolveAlias(tok, functionAliases)
	case rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE:
		return resolveAlias(tok, userTypeAliases)
	case rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		return strings.ToUpper(strings.TrimSpace(tok))
	default:
		return tok
	}
}

// canonicalizeTokens rewrites each token in place via canon.
func canonicalizeTokens(tokens []string, canon func(string) string) {
	for i, tok := range tokens {
		tokens[i] = canon(tok)
	}
}

// resolveAlias trims+lowercases a token then maps it through aliases (identity
// when absent). Canonical targets are never themselves alias keys, so applying
// resolveAlias twice is a fixed point — the source of Normalize's idempotency.
func resolveAlias(tok string, aliases map[string]string) string {
	tok = strings.ToLower(strings.TrimSpace(tok))
	if canon, ok := aliases[tok]; ok {
		return canon
	}
	return tok
}
