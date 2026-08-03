package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/licenseterm"
)

// mapRecord converts a parsed Record into a proto-exact
// ramp.v1.ResourceEntry whose terms[] match the LicenseTerm shape the Exchange
// validates — the same contract CatalogService.PushResources accepts.
//
// Each declared offer becomes one LicenseTerm. After building a term its tokens
// are canonicalized with licenseterm.Normalize (mirroring the PushResources
// handler), so the produced terms carry canonical vocabulary and pass
// licenseterm.Validate. This function does NOT reimplement normalization or
// validation — it reuses the licenseterm package.
func mapRecord(rec Record) (*rampv1.ResourceEntry, error) {
	entry := &rampv1.ResourceEntry{
		Domain: rec.Domain,
		Path:   rec.Path,
	}
	if rec.Title != "" {
		entry.Title = strPtr(rec.Title)
	}
	if err := applyScalarMetadata(entry, rec); err != nil {
		return nil, err
	}
	if err := applyStructuredMetadata(entry, rec); err != nil {
		return nil, err
	}

	license := mapLicense(rec.License)
	for i := range rec.Terms {
		term, err := mapTerm(rec.Terms[i], license)
		if err != nil {
			return nil, fmt.Errorf("term %d: %w", i, err)
		}
		licenseterm.Normalize(term) // canonicalize tokens (handler-equivalent)
		entry.Terms = append(entry.Terms, term)
	}
	return entry, nil
}

// applyScalarMetadata maps the scalar, enum, and timestamp resource-extension
// fields onto the ResourceEntry. Optional scalars are set only when
// non-empty; the source enum and provenance timestamp fail loud on bad input
// (the mapper, not the parser, owns value validation). The structured fields
// (ext, ext_critical, attestations) are mapped separately.
func applyScalarMetadata(entry *rampv1.ResourceEntry, rec Record) error {
	if rec.ContentID != "" {
		entry.ContentId = strPtr(rec.ContentID)
	}
	entry.WordCount = rec.WordCount
	entry.EstimatedQuantity = rec.EstimatedQuantity
	if rec.ContentHash != "" {
		entry.ContentHash = strPtr(rec.ContentHash)
	}
	if rec.HashMethod != "" {
		entry.HashMethod = strPtr(rec.HashMethod)
	}
	if rec.Source != "" {
		src, err := mapIngestionSource(rec.Source)
		if err != nil {
			return err
		}
		entry.Source = &src
	}
	if rec.ResourceMutability != "" {
		m, err := mapResourceMutability(rec.ResourceMutability)
		if err != nil {
			return err
		}
		entry.ResourceMutability = &m
	}
	if rec.ProvenanceSource != "" {
		entry.ProvenanceSource = strPtr(rec.ProvenanceSource)
	}
	if rec.ProvenanceTimestamp != "" {
		ts, err := time.Parse(time.RFC3339, rec.ProvenanceTimestamp)
		if err != nil {
			return fmt.Errorf("malformed provenance_timestamp %q (expected RFC3339): %w", rec.ProvenanceTimestamp, err)
		}
		entry.ProvenanceTimestamp = timestamppb.New(ts)
	}
	return nil
}

// applyStructuredMetadata maps the structured resource-extension fields
// onto the ResourceEntry: ext and attestation claims become
// *structpb.Struct (object-shape validated, non-objects rejected), ext_critical
// passes through verbatim, and attestations are carried as opaque pass-through
// (no signature verification happens here). previews still rides inside ext and
// is promoted to a typed Offer field downstream, not here (its typed promotion
// is a separate follow-up); resource_mutability is now a typed scalar field,
// mapped in applyScalarMetadata.
func applyStructuredMetadata(entry *rampv1.ResourceEntry, rec Record) error {
	if len(rec.Ext) > 0 {
		ext, err := rawToStruct(rec.Ext)
		if err != nil {
			return fmt.Errorf("ext must be a JSON object: %w", err)
		}
		entry.Ext = ext
	}
	entry.ExtCritical = rec.ExtCritical
	if len(rec.Attestations) == 0 {
		return nil
	}
	atts := make([]*rampv1.ResourceAttestation, 0, len(rec.Attestations))
	for i := range rec.Attestations {
		a, err := mapAttestation(rec.Attestations[i])
		if err != nil {
			return fmt.Errorf("attestation %d: %w", i, err)
		}
		atts = append(atts, a)
	}
	entry.Attestations = atts
	return nil
}

// mapAttestation maps one parsed attestation onto a proto ResourceAttestation,
// parsing attested_at (RFC3339) and converting claims to a *structpb.Struct.
// Both fail loud on bad input; the attestation is otherwise carried verbatim.
func mapAttestation(a Attestation) (*rampv1.ResourceAttestation, error) {
	out := &rampv1.ResourceAttestation{
		Verifier:  a.Verifier,
		Keyid:     a.Kid,
		Uri:       a.URI,
		Signature: a.Signature,
	}
	if a.AttestedAt != "" {
		ts, err := time.Parse(time.RFC3339, a.AttestedAt)
		if err != nil {
			return nil, fmt.Errorf("malformed attested_at %q (expected RFC3339): %w", a.AttestedAt, err)
		}
		out.AttestedAt = timestamppb.New(ts)
	}
	if len(a.Claims) > 0 {
		claims, err := rawToStruct(a.Claims)
		if err != nil {
			return nil, fmt.Errorf("attestation claims must be a JSON object: %w", err)
		}
		out.Claims = claims
	}
	return out, nil
}

// rawToStruct converts a raw JSON object into a *structpb.Struct via protojson
// for fidelity. A non-object value (string, array, number) fails — the mapper
// is where wrong-typed ext/claims are rejected (the parser keeps them raw).
func rawToStruct(raw json.RawMessage) (*structpb.Struct, error) {
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	return s, nil
}

// mapLicense builds the governing License message shared by a record's terms.
// License.uri is required for REFERENCE_ONLY terms (enforced by Validate).
func mapLicense(l *License) *rampv1.License {
	if l == nil {
		return nil
	}
	out := &rampv1.License{}
	if l.ID != "" {
		out.Id = strPtr(l.ID)
	}
	if l.URI != "" {
		out.Uri = strPtr(l.URI)
	}
	// uri_digest is REQUIRED whenever uri is set (protovalidate CEL
	// license.digest_required_with_uri); the feed must supply it.
	if l.URIDigest != "" {
		out.UriDigest = strPtr(l.URIDigest)
	}
	if l.Name != "" {
		out.Name = strPtr(l.Name)
	}
	return out
}

// mapTerm builds one LicenseTerm from a parsed Term. Machine fields
// (restrictions/quotas/obligations) are mapped for BOTH semantics: under
// ENUMERATED they are authoritative, under REFERENCE_ONLY they are an advisory
// readable summary of the License document (flexible model, ADR-014) — the feed
// decides whether to provide them.
func mapTerm(t Term, license *rampv1.License) (*rampv1.LicenseTerm, error) {
	semantics, err := mapSemantics(t.Semantics)
	if err != nil {
		return nil, err
	}
	pricing, err := mapPricing(t.Pricing)
	if err != nil {
		return nil, err
	}

	term := &rampv1.LicenseTerm{
		License:   license,
		Semantics: semantics,
		Pricing:   pricing,
		Scopes:    t.Scopes,
	}

	if r := functionRestriction(t.Functions, t.ProhibitedFunctions); r != nil {
		term.Restrictions = append(term.Restrictions, r)
	}
	if r := permittedRestriction(rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE, t.UserTypes); r != nil {
		term.Restrictions = append(term.Restrictions, r)
	}
	if r := permittedRestriction(rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, t.Geos); r != nil {
		term.Restrictions = append(term.Restrictions, r)
	}

	quotas, err := mapQuotas(t.Quotas)
	if err != nil {
		return nil, err
	}
	term.Quotas = quotas

	obligations, err := mapObligations(t.Obligations)
	if err != nil {
		return nil, err
	}
	term.Obligations = obligations

	return term, nil
}

// mapSemantics resolves the source semantics spelling to the proto enum,
// failing loud on an unknown value (never an UNSPECIFIED sentinel).
func mapSemantics(s string) (rampv1.TermSemantics, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enumerated":
		return rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, nil
	case "reference_only":
		return rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, nil
	default:
		return 0, fmt.Errorf("unknown term semantics %q", s)
	}
}

// mapPricing resolves the source pricing into a proto Pricing over the closed
// FREE/PER_UNIT/FLAT set. PER_UNIT carries its unit; FLAT and FREE carry none;
// FREE's rate is forced to 0.
func mapPricing(p *Pricing) (*rampv1.Pricing, error) {
	if p == nil {
		return nil, fmt.Errorf("term has no pricing (pricing is required on every term)")
	}
	out := &rampv1.Pricing{Currency: p.Currency}
	switch strings.ToLower(strings.TrimSpace(p.Model)) {
	case "free":
		out.Model = rampv1.PricingModel_PRICING_MODEL_FREE
		// free REQUIRES rate == 0: an
		// omitted rate means 0, any declared rate must literally be zero.
		if p.Rate != "" {
			rate, err := rateString(p.Rate)
			if err != nil {
				return nil, err
			}
			if rate != "0" {
				return nil, fmt.Errorf(`free pricing requires rate "0", got %q`, p.Rate)
			}
		}
		out.Rate = "0"
	case "per_unit":
		out.Model = rampv1.PricingModel_PRICING_MODEL_PER_UNIT
		rate, err := rateString(p.Rate)
		if err != nil {
			return nil, err
		}
		out.Rate = rate
		if p.Unit == "" {
			return nil, fmt.Errorf("per_unit pricing requires a unit")
		}
		out.Unit = strPtr(p.Unit)
	case "flat":
		out.Model = rampv1.PricingModel_PRICING_MODEL_FLAT
		rate, err := rateString(p.Rate)
		if err != nil {
			return nil, err
		}
		out.Rate = rate
	default:
		return nil, fmt.Errorf("unknown pricing model %q", p.Model)
	}
	return out, nil
}

// rateString validates the feed's rate string and normalizes it to the
// canonical wire form (proto ramp.v1.Pricing.rate). CanonicalizeMoney rejects
// anything outside the wire pattern — signs, exponents, a leading dot, empty
// (a priced model requires an explicit rate) — and strips insignificant
// trailing zeros, e.g. "0.050" -> "0.05", "5.0" -> "5".
func rateString(rate string) (string, error) {
	s, err := helpers.CanonicalizeMoney(rate)
	if err != nil {
		return "", fmt.Errorf("pricing rate: %w", err)
	}
	return s, nil
}

// functionRestriction folds permitted/prohibited function tokens into a single
// Restriction{kind=FUNCTION}, or nil when both are empty.
func functionRestriction(permitted, prohibited []string) *rampv1.Restriction {
	if len(permitted) == 0 && len(prohibited) == 0 {
		return nil
	}
	return &rampv1.Restriction{
		Kind:       rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
		Permitted:  cloneTokens(permitted),
		Prohibited: cloneTokens(prohibited),
	}
}

// permittedRestriction builds a single-axis Restriction carrying permitted
// tokens, or nil when there are none.
func permittedRestriction(kind rampv1.RestrictionKind, permitted []string) *rampv1.Restriction {
	if len(permitted) == 0 {
		return nil
	}
	return &rampv1.Restriction{
		Kind:      kind,
		Permitted: cloneTokens(permitted),
	}
}

// mapQuotas converts source quotas to proto Quotas, failing loud on an unknown
// window spelling.
func mapQuotas(qs []Quota) ([]*rampv1.Quota, error) {
	if len(qs) == 0 {
		return nil, nil
	}
	out := make([]*rampv1.Quota, 0, len(qs))
	for _, q := range qs {
		window, err := mapQuotaWindow(q.Window)
		if err != nil {
			return nil, err
		}
		out = append(out, &rampv1.Quota{
			Metric: q.Metric,
			Limit:  q.Limit,
			Window: window,
		})
	}
	return out, nil
}

func mapQuotaWindow(w string) (rampv1.QuotaWindow, error) {
	switch strings.ToLower(strings.TrimSpace(w)) {
	case "hourly":
		return rampv1.QuotaWindow_QUOTA_WINDOW_HOURLY, nil
	case "daily":
		return rampv1.QuotaWindow_QUOTA_WINDOW_DAILY, nil
	case "monthly":
		return rampv1.QuotaWindow_QUOTA_WINDOW_MONTHLY, nil
	case "total":
		return rampv1.QuotaWindow_QUOTA_WINDOW_TOTAL, nil
	default:
		return 0, fmt.Errorf("unknown quota window %q", w)
	}
}

// mapObligations converts source obligations to proto Obligations, failing loud
// on unknown kind/trigger spellings.
func mapObligations(os []Obligation) ([]*rampv1.Obligation, error) {
	if len(os) == 0 {
		return nil, nil
	}
	out := make([]*rampv1.Obligation, 0, len(os))
	for _, o := range os {
		kind, err := mapObligationKind(o.Kind)
		if err != nil {
			return nil, err
		}
		trigger, err := mapObligationTrigger(o.Trigger)
		if err != nil {
			return nil, err
		}
		obl := &rampv1.Obligation{Kind: kind, Trigger: trigger}
		if o.ScopeLicense != "" {
			// scope_license is a License now; the feed carries the SPDX short-id.
			obl.ScopeLicense = &rampv1.License{Id: strPtr(o.ScopeLicense)}
		}
		if o.Detail != "" {
			obl.Detail = strPtr(o.Detail)
		}
		out = append(out, obl)
	}
	return out, nil
}

func mapObligationKind(k string) (rampv1.ObligationKind, error) {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "attribution":
		return rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION, nil
	case "contribution":
		return rampv1.ObligationKind_OBLIGATION_KIND_CONTRIBUTION, nil
	case "share_alike":
		return rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, nil
	case "network_copyleft":
		return rampv1.ObligationKind_OBLIGATION_KIND_NETWORK_COPYLEFT, nil
	case "notice":
		return rampv1.ObligationKind_OBLIGATION_KIND_NOTICE, nil
	case "other":
		return rampv1.ObligationKind_OBLIGATION_KIND_OTHER, nil
	default:
		return 0, fmt.Errorf("unknown obligation kind %q", k)
	}
}

func mapObligationTrigger(tr string) (rampv1.ObligationTrigger, error) {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "on_use":
		return rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, nil
	case "on_distribution":
		return rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_DISTRIBUTION, nil
	case "on_network_service":
		return rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_NETWORK_SERVICE, nil
	case "on_derivative":
		return rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_DERIVATIVE, nil
	default:
		return 0, fmt.Errorf("unknown obligation trigger %q", tr)
	}
}

// cloneTokens returns a fresh slice so Normalize's in-place canonicalization
// never mutates the parser's record slices.
func cloneTokens(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// strPtr returns a pointer to s, for the proto's optional scalar fields.
func strPtr(s string) *string { return &s }
