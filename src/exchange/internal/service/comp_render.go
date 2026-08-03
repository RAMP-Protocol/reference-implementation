package service

import (
	"fmt"
	"slices"
	"strings"
	"time"

	compv1 "github.com/RAMP-Protocol/protocol/gen/go/comp/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	protobuf "google.golang.org/protobuf/proto" // aliased: tests define a local generic proto[T] helper that shadows the package name
	"google.golang.org/protobuf/types/known/structpb"
)

// profileCoMPV1 is the supported_profiles vocab string for the CoMP V1 extension
// profile (ADR-014). It encodes the CoMP version the renderer targets.
const profileCoMPV1 = "ramp-comp-v1"

// compRenderInput names everything the CoMP renderer projects for one offer: the
// selected headline term, the resource id + that term's ORIGINAL stored index
// (together the CoMP package_id), and the resource-intrinsic
// metadata. Grouping them keeps applyCompProfile within the argument-count cap.
type compRenderInput struct {
	term       *rampv1.LicenseTerm
	resourceID string
	termIndex  int
	md         *rampv1.ResourceEntry
}

// applyCompProfile merges the rebuild-time CoMP projection (cached) into
// offer.Ext under "comp" when the effective profile set requests ramp-comp-v1
// and a blob is cached; otherwise it is a no-op (send-all base preserved,
// ADR-014). The render itself happens once at snapshot rebuild
// (renderRowProfiles); only the per-offer deep-merge is here.
//
// It must run AFTER applyMetadata and BEFORE SignOffer so the comp ext is
// signature-covered (canonicalOfferPayload marshals the whole Offer). It CLONES
// offer.Ext before writing: applyMetadata aliases the snapshot's rebuild-time
// metadata struct (metadata_codec.go: offer.Ext = md.Ext), so mutating it in
// place would corrupt that shared cache across requests.
func applyCompProfile(offer *rampv1.Offer, cached *structpb.Struct, profiles []string) {
	if cached == nil || !slices.Contains(profiles, profileCoMPV1) {
		return
	}
	// Term-authoritative shadow rule (ADR-014): deep-merge the term-rendered comp
	// (cached = the blob precomputed at snapshot rebuild) OVER any
	// publisher-supplied ext.comp — publisher keys survive, term-owned (rendered)
	// fields WIN on conflict (e.g. comp.scope.unitprice). base is the publisher's
	// comp (nil-safe), aliased onto offer.Ext by applyMetadata. Only the merge is
	// per-discovery now; the render moved to rebuild (renderRowProfiles).
	base := offer.Ext.GetFields()["comp"].GetStructValue()
	merged := mergeStruct(base, cached)
	offer.Ext = withField(offer.Ext, "comp", structpb.NewStructValue(merged))
}

// mergeStruct returns a deep merge of overlay OVER base: every base key is kept,
// every overlay key wins on conflict, and when both sides hold a Struct at the
// same key they merge recursively (so a term-rendered comp.scope.unitprice
// overrides the publisher's while sibling publisher scope keys survive). Like
// withField it is copy-on-write — neither base nor overlay is mutated — but the
// result may SHARE immutable *structpb.Value refs with both, so callers must not
// mutate the returned tree. A nil base yields a copy of overlay; nil overlay a
// copy of base.
func mergeStruct(base, overlay *structpb.Struct) *structpb.Struct {
	out := map[string]*structpb.Value{}
	for k, v := range base.GetFields() {
		out[k] = v
	}
	for k, ov := range overlay.GetFields() {
		if bv, ok := out[k]; ok {
			if bs, ovs := bv.GetStructValue(), ov.GetStructValue(); bs != nil && ovs != nil {
				out[k] = structpb.NewStructValue(mergeStruct(bs, ovs))
				continue
			}
		}
		out[k] = ov
	}
	return &structpb.Struct{Fields: out}
}

// withField returns a COPY of src with key=val set. It never mutates src — which
// may be the snapshot cache's Ext pointer aliased in by applyMetadata.
func withField(src *structpb.Struct, key string, val *structpb.Value) *structpb.Struct {
	fields := map[string]*structpb.Value{}
	for k, v := range src.GetFields() {
		fields[k] = v
	}
	fields[key] = val
	return &structpb.Struct{Fields: fields}
}

// renderCompProfile projects the selected license term into a canonical CoMP V1
// Package, returned as a structpb.Struct for embedding under Offer.Ext["comp"].
// PROTO-FIRST (epic PATH REVERSAL): a typed comp.v1.Package is built then
// protojson-marshalled with INTEGER enums (UseEnumNumbers) and proto field names
// (UseProtoNames) — the encoding canonical CoMP consumers and the comptest
// conformance oracle expect. Deterministic from the term alone (no clock, no
// per-request state), so discovery and tx-reconstruction render identical bytes
// (signature parity).
func renderCompProfile(in compRenderInput) (*structpb.Struct, error) {
	scope, err := scopeFromPricing(in.term.GetPricing())
	if err != nil {
		return nil, fmt.Errorf("project comp scope: %w", err)
	}
	if ause, ok := auseFromRestrictions(in.term); ok {
		scope.Ause = ause.Enum()
	}
	if country := countryFromRestrictions(in.term); len(country) > 0 {
		scope.Country = country
	}
	if text := textFromMetadata(in.md); text != nil {
		scope.Text = []*compv1.Text{text}
	}
	pkg := &compv1.Package{
		Id:    fmt.Sprintf("%s#%d", in.resourceID, in.termIndex),
		Scope: scope,
	}
	if citation, ok := citationFromObligations(in.term); ok {
		pkg.Citation = citation
	}
	if unmapped := unmappedConstructs(in.term); len(unmapped) > 0 {
		pkg.Ext = unmappedExt(unmapped)
	}
	raw, err := protojson.MarshalOptions{UseEnumNumbers: true, UseProtoNames: true}.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal comp package: %w", err)
	}
	var out structpb.Struct
	if err := protojson.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode comp package: %w", err)
	}
	return &out, nil
}

// scopeFromPricing maps a RAMP Pricing onto a CoMP Scope: rate->unitprice,
// currency->cur (default USD), model/unit->pricetype (the expressibility-matrix
// crosswalk). unitprice is always set (present even when 0 for FREE).
func scopeFromPricing(p *rampv1.Pricing) (*compv1.Scope, error) {
	cur := p.GetCurrency()
	if cur == "" {
		cur = "USD"
	}
	// Rate is now a canonical decimal STRING on the wire (exact-decimal money
	// spine). CoMP unitprice is a float64 — a lossy, display-only projection — so
	// parse the exact decimal and narrow to float64 here. Empty (FREE) maps to
	// decimal.Zero via moneyOrZero, matching the unitprice-0-conveys-free contract
	// above; a malformed price surfaces as an error rather than silently pricing 0.
	rate, err := moneyOrZero(p.GetRate())
	if err != nil {
		return nil, fmt.Errorf("parse comp unitprice: %w", err)
	}
	scope := &compv1.Scope{
		Unitprice: protobuf.Float64(rate.InexactFloat64()),
		Cur:       protobuf.String(cur),
	}
	if pt, ok := priceTypeFor(p); ok {
		scope.Pricetype = pt.Enum()
	}
	return scope, nil
}

// priceTypeFor crosswalks a RAMP PricingModel (+ PER_UNIT unit basis) to a CoMP
// PriceType. FREE/UNSPECIFIED has no CoMP price type (ok=false -> pricetype
// omitted; unitprice 0 conveys free). FLAT->Flat; PER_UNIT by unit:
// tokens->Per-Token, queries->Per-Query, otherwise Per-Use.
func priceTypeFor(p *rampv1.Pricing) (compv1.PriceType, bool) {
	switch p.GetModel() {
	case rampv1.PricingModel_PRICING_MODEL_FLAT:
		return compv1.PriceType_PRICE_TYPE_FLAT, true
	case rampv1.PricingModel_PRICING_MODEL_PER_UNIT:
		switch p.GetUnit() {
		case "tokens":
			return compv1.PriceType_PRICE_TYPE_PER_TOKEN, true
		case "queries":
			return compv1.PriceType_PRICE_TYPE_PER_QUERY, true
		default:
			return compv1.PriceType_PRICE_TYPE_PER_USE, true
		}
	default:
		return compv1.PriceType_PRICE_TYPE_PER_USE, false
	}
}

// auseUserType crosswalks RAMP USER_TYPE restriction tokens to a CoMP AllowedUse
// (N4). A token with no clean class is absent (prefer omission over OTHER).
var auseUserType = map[string]compv1.AllowedUse{
	"commercial":        compv1.AllowedUse_ALLOWED_USE_COMMERCIAL,
	"commercial_entity": compv1.AllowedUse_ALLOWED_USE_COMMERCIAL,
	"advertising":       compv1.AllowedUse_ALLOWED_USE_COMMERCIAL,
	"non_profit":        compv1.AllowedUse_ALLOWED_USE_NON_COMMERCIAL,
	"academic":          compv1.AllowedUse_ALLOWED_USE_EDUCATIONAL,
	"research":          compv1.AllowedUse_ALLOWED_USE_EDUCATIONAL,
	"educational":       compv1.AllowedUse_ALLOWED_USE_EDUCATIONAL,
	"government":        compv1.AllowedUse_ALLOWED_USE_GOVERNMENT,
	"individual":        compv1.AllowedUse_ALLOWED_USE_PERSONAL,
}

// auseFromRestrictions resolves CoMP Scope.ause from the term's USER_TYPE
// restriction. ause is a SINGLE value: tokens are scanned in Permitted[] order
// (deterministic — a stored slice, NOT map iteration) and the FIRST that maps
// wins, so discovery and tx-reconstruction collapse identically (parity).
func auseFromRestrictions(term *rampv1.LicenseTerm) (compv1.AllowedUse, bool) {
	for _, r := range term.GetRestrictions() {
		if r.GetKind() != rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE {
			continue
		}
		for _, tok := range r.GetPermitted() {
			if use, ok := auseUserType[tok]; ok {
				return use, true
			}
		}
	}
	return compv1.AllowedUse_ALLOWED_USE_COMMERCIAL, false
}

// alpha2ToNumeric is the MINIMAL ISO-3166-1 alpha-2 -> numeric map (N7). It
// covers only the codes exercised so far; the full table + EU/EEA regional-alias
// member expansion is deferred to a follow-up. An unmapped
// code (incl. the "*" wildcard and regional aliases) is OMITTED, never guessed.
var alpha2ToNumeric = map[string]int32{
	"US": 840,
	"DE": 276,
}

// countryFromRestrictions resolves CoMP Scope.country (ISO-3166 numeric) from the
// term's GEOGRAPHY restriction Permitted[] (allow-list; Prohibited is omitted).
// Unknown/"*" codes are dropped; the result is sorted ascending for determinism.
func countryFromRestrictions(term *rampv1.LicenseTerm) []int32 {
	var out []int32
	for _, r := range term.GetRestrictions() {
		if r.GetKind() != rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY {
			continue
		}
		for _, tok := range r.GetPermitted() {
			if code, ok := alpha2ToNumeric[tok]; ok {
				out = append(out, code)
			}
		}
	}
	slices.Sort(out)
	return out
}

// citationFromObligations sets CoMP Package.citation=1 iff the term carries an
// ATTRIBUTION obligation (the only obligation kind with a canonical CoMP home;
// all others are omitted and stay on Offer.terms[]).
func citationFromObligations(term *rampv1.LicenseTerm) (*int32, bool) {
	for _, o := range term.GetObligations() {
		if o.GetKind() == rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION {
			return protobuf.Int32(1), true
		}
	}
	return nil, false
}

// textFromMetadata projects resource-intrinsic resource-intrinsic metadata (md) into a
// single CoMP Text media object (Q7: one offer = one media). CoMP-homed
// fields land at canonical paths (word_count->wordcount, provenance_timestamp->
// pubdate, provenance_source->provent + provenance=1); RAMP-only facts ride under
// the opaque media ext. Returns nil when md carries no projectable field, so
// metadata-free offers emit no text[] (empty-media guard). md is the rebuild-time
// snapshot cache — read ONLY (the ext is a fresh struct), keeping render
// deterministic for signature parity.
func textFromMetadata(md *rampv1.ResourceEntry) *compv1.Text {
	if md == nil {
		return nil
	}
	t := &compv1.Text{}
	present := false
	if wc := md.GetWordCount(); wc > 0 {
		t.Wordcount = []int32{wc}
		present = true
	}
	if ts := md.GetProvenanceTimestamp(); ts != nil {
		t.Pubdate = protobuf.String(ts.AsTime().UTC().Format(time.RFC3339))
		present = true
	}
	if src := md.GetProvenanceSource(); src != "" {
		t.Provent = protobuf.String(src)
		t.Provenance = protobuf.Int32(1)
		present = true
	}
	if ext := textExtFromMetadata(md); ext != nil {
		t.Ext = ext
		present = true
	}
	if !present {
		return nil
	}
	return t
}

// textExtFromMetadata builds the Text media's opaque ext from resource-metadata facts with
// no canonical CoMP home (Q3): content_hash/hash_method and resource_mutability
// come from typed md fields; previews is lifted read-only from md.Ext (a separate
// follow-up will give it a typed field).
// Returns nil when none are present. Values are copied into a fresh Struct —
// md.Ext (the snapshot alias) is never mutated.
func textExtFromMetadata(md *rampv1.ResourceEntry) *structpb.Struct {
	fields := map[string]*structpb.Value{}
	if h := md.GetContentHash(); h != "" {
		fields["content_hash"] = structpb.NewStringValue(h)
	}
	if hm := md.GetHashMethod(); hm != "" {
		fields["hash_method"] = structpb.NewStringValue(hm)
	}
	if md.ResourceMutability != nil {
		fields["resource_mutability"] = structpb.NewStringValue(md.GetResourceMutability().String())
	}
	if v, ok := md.GetExt().GetFields()["previews"]; ok {
		fields["previews"] = v
	}
	if len(fields) == 0 {
		return nil
	}
	return &structpb.Struct{Fields: fields}
}

// unmappedConstructs returns the sorted, deduped RAMP term constructs that have
// NO CoMP projection (transparency flag). Classification is by
// EMITTED RESULT: a USER_TYPE/GEOGRAPHY restriction is "mapped" only if it
// contributed a recognized token (ause / numeric country); every other
// restriction kind, every quota, every non-ATTRIBUTION obligation, and every
// term scope is unmapped. Empty -> nil (fully-mappable terms add no flag). The
// canonical LicenseTerm always remains on Offer.terms[] regardless.
func unmappedConstructs(term *rampv1.LicenseTerm) []string {
	set := map[string]struct{}{}
	for _, r := range term.GetRestrictions() {
		if !restrictionMapped(r) {
			set["restriction:"+kindToken(r.GetKind().String(), "RESTRICTION_KIND_")] = struct{}{}
		}
	}
	for _, q := range term.GetQuotas() {
		set["quota:"+q.GetMetric()] = struct{}{}
	}
	for _, o := range term.GetObligations() {
		if o.GetKind() != rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION {
			set["obligation:"+kindToken(o.GetKind().String(), "OBLIGATION_KIND_")] = struct{}{}
		}
	}
	for _, s := range term.GetScopes() {
		set["scope:"+s] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// restrictionMapped reports whether r contributed a recognized token to the CoMP
// Scope (an ause for USER_TYPE, a numeric country for GEOGRAPHY). Other kinds
// never map; allow-list only, so a Prohibited-only restriction contributes
// nothing and is therefore unmapped.
func restrictionMapped(r *rampv1.Restriction) bool {
	switch r.GetKind() {
	case rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE:
		for _, t := range r.GetPermitted() {
			if _, ok := auseUserType[t]; ok {
				return true
			}
		}
	case rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY:
		for _, t := range r.GetPermitted() {
			if _, ok := alpha2ToNumeric[t]; ok {
				return true
			}
		}
	}
	return false
}

// kindToken renders an enum String() (e.g. "OBLIGATION_KIND_SHARE_ALIKE") as a
// lowercase token without its prefix ("share_alike").
func kindToken(enumName, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(enumName, prefix))
}

// unmappedExt wraps the unmapped-construct list as the comp Package's opaque ext
// under "ramp_unmapped" (oracle-opaque -> conformance-safe).
func unmappedExt(items []string) *structpb.Struct {
	vals := make([]*structpb.Value, len(items))
	for i, s := range items {
		vals[i] = structpb.NewStringValue(s)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"ramp_unmapped": structpb.NewListValue(&structpb.ListValue{Values: vals}),
	}}
}

// effectiveProfiles is the intersection of the requester's declared profiles and
// the Exchange's advertised set: the Exchange never projects a profile it does
// not advertise (single source of truth = WellKnownManifest.supported_profiles).
func effectiveProfiles(requested, supported []string) []string {
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		if slices.Contains(supported, r) {
			out = append(out, r)
		}
	}
	return out
}
