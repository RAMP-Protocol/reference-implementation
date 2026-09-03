package service

import (
	"context"
	"log/slog"
	"slices"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	radix "github.com/armon/go-radix"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// CatalogSnapshot is the published, read-only view consumed by the
// Exchange service. Built by the CatalogService and swapped atomically.
type CatalogSnapshot struct {
	trie *radix.Tree
	// byURI is the execute-time binding index: exact-match on the stored
	// catalog.uri (globally UNIQUE), keyed by the signed offer's
	// Identity.canonical_url. Distinct from the trie, which keys on URIPrefix
	// and serves discovery's longest-prefix lookup.
	byURI  map[string]repo.CatalogEntry
	tenant map[string]string // resource_id -> tenant_id (redundant, for readability)
	// terms caches each row's protojson-decoded license terms, decoded ONCE at
	// rebuild rather than on every discovery/billing read. Keyed by resource_id.
	// DecodedTerms is the read accessor; nothing on the hot path calls
	// unmarshalTerms per request anymore.
	terms map[string][]*rampv1.LicenseTerm
	// metadata caches each row's protojson-decoded resource extension metadata,
	// decoded ONCE at rebuild() rather than per discovery read (mirrors terms).
	// Keyed by resource_id. DecodedMetadata is the read accessor; a row
	// without metadata (NULL column) is simply absent from the map.
	metadata map[string]*rampv1.ResourceEntry
	// rendered caches the CoMP projection precomputed ONCE at rebuild,
	// keyed [resourceID][stored-term-index][profile]. Moving the render off
	// the discovery hot path; RenderedProfile is the read accessor. The per-offer
	// deep-merge over publisher ext stays on the discovery path.
	rendered map[string]map[int]map[string]*structpb.Struct
}

// newEmptySnapshot constructs an empty CatalogSnapshot with all index maps
// (including the rebuild-time decoded-terms cache) initialized.
func newEmptySnapshot() *CatalogSnapshot {
	return &CatalogSnapshot{
		trie:     radix.New(),
		byURI:    map[string]repo.CatalogEntry{},
		tenant:   map[string]string{},
		terms:    map[string][]*rampv1.LicenseTerm{},
		metadata: map[string]*rampv1.ResourceEntry{},
		rendered: map[string]map[int]map[string]*structpb.Struct{},
	}
}

// DecodedTerms returns the license terms cached for resourceID at rebuild time,
// without a per-call decode. Returns nil for an unknown id or a row that
// failed to decode at rebuild — both surface as "no terms", which the discovery
// path treats as "no offer".
func (s *CatalogSnapshot) DecodedTerms(resourceID string) []*rampv1.LicenseTerm {
	if s == nil {
		return nil
	}
	return s.terms[resourceID]
}

// DecodedMetadata returns the resource extension metadata cached for resourceID
// at rebuild time, without a per-call decode (mirrors DecodedTerms). Returns nil
// for an unknown id, a row with no metadata (NULL column), or a row whose
// metadata failed to decode at rebuild — all surface as "no metadata", which the
// discovery path treats as an Offer with empty metadata.
func (s *CatalogSnapshot) DecodedMetadata(resourceID string) *rampv1.ResourceEntry {
	if s == nil {
		return nil
	}
	return s.metadata[resourceID]
}

// RenderedProfile returns the CoMP projection precomputed at rebuild for
// (resourceID, the selected headline term's stored index, profile), or nil for
// any missing level (unknown resource/index/profile, or a row not rendered).
// Nil-receiver safe and nil-safe through the nested maps, so the discovery path
// treats "not cached" as "no comp blob". Mirrors DecodedMetadata.
func (s *CatalogSnapshot) RenderedProfile(resourceID string, termIndex int, profile string) *structpb.Struct {
	if s == nil {
		return nil
	}
	return s.rendered[resourceID][termIndex][profile]
}

// renderRowProfiles precomputes the CoMP projection for every stored term of a
// row at rebuild when ramp-comp-v1 is advertised — the only profile
// with a renderer today. The render is a pure fn of stored state (term[i] +
// metadata), keyed on the term's ORIGINAL stored index, so the discovery path
// looks up the headline term's blob by index. A render error is logged and the
// term is skipped (no cached blob -> that offer emits no comp ext); unlike the
// old inline path which failed the discovery, but renderCompProfile is
// effectively infallible for an ingest-validated term (mirrors decodeRowMetadata
// "one bad row must not poison rebuild").
func renderRowProfiles(ctx context.Context, snap *CatalogSnapshot, resourceID string, profiles []string) {
	if !slices.Contains(profiles, profileCoMPV1) {
		return
	}
	md := snap.metadata[resourceID]
	byIndex := map[int]map[string]*structpb.Struct{}
	for i, term := range snap.terms[resourceID] {
		rendered, err := renderCompProfile(compRenderInput{term: term, resourceID: resourceID, termIndex: i, md: md})
		if err != nil {
			reqctx.FromContext(ctx).WarnContext(
				ctx,
				"catalog snapshot: skipping comp render for term; offer emits no comp ext",
				slog.String("resource_id", resourceID),
				slog.Int("term_index", i),
				slog.Any("error", err),
			)
			continue
		}
		byIndex[i] = map[string]*structpb.Struct{profileCoMPV1: rendered}
	}
	if len(byIndex) > 0 {
		snap.rendered[resourceID] = byIndex
	}
}

// decodeRowTerms decodes one catalog row's persisted terms JSONB ONCE at
// snapshot-rebuild time. The stored JSONB is UNTRUSTED on read: a row
// whose document fails to decode MUST NOT poison the whole snapshot, so a decode
// error is logged and the row is cached with zero terms rather than aborting
// rebuild. A zero-term row simply yields no offer on the discovery path,
// exactly as an entry whose terms all filtered out would. Decoding here (vs
// per-discovery-call) does not make the JSONB trusted — the error is still
// handled gracefully; it only moves the cost off the hot read path.
func decodeRowTerms(ctx context.Context, row repo.CatalogEntry) []*rampv1.LicenseTerm {
	terms, err := unmarshalTerms(row.TermsJSON)
	if err != nil {
		reqctx.FromContext(ctx).WarnContext(
			ctx,
			"catalog snapshot: skipping undecodable terms for resource; treating as zero terms",
			slog.String("resource_id", row.ResourceID),
			slog.String("tenant_id", row.TenantID),
			slog.Any("error", err),
		)
		return nil
	}
	return terms
}

// decodeRowMetadata decodes one catalog row's persisted metadata JSONB ONCE at
// snapshot-rebuild time (mirrors decodeRowTerms). A NULL/empty column yields nil
// (the common legacy case). The stored JSONB is UNTRUSTED on read: a row whose
// document fails to decode is logged and cached as nil rather than aborting
// rebuild, so one bad row cannot poison the snapshot. A nil result surfaces as
// an Offer with empty metadata on the discovery path.
func decodeRowMetadata(ctx context.Context, row repo.CatalogEntry) *rampv1.ResourceEntry {
	md, err := unmarshalResourceMetadata(row.MetadataJSON)
	if err != nil {
		reqctx.FromContext(ctx).WarnContext(
			ctx,
			"catalog snapshot: skipping undecodable metadata for resource; treating as no metadata",
			slog.String("resource_id", row.ResourceID),
			slog.String("tenant_id", row.TenantID),
			slog.Any("error", err),
		)
		return nil
	}
	return md
}
