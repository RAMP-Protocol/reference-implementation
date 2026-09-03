package service

import (
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	protobuf "google.golang.org/protobuf/proto" // aliased: tests define a local generic proto[T] helper that shadows the package name
	"google.golang.org/protobuf/types/known/structpb"
)

// marshalResourceMetadata serializes the resource extension metadata of a
// ResourceEntry into the JSONB document stored in catalog.metadata. It projects
// ONLY the metadata fields (never domain/path/title/terms — those live in their
// own columns) so the persisted document is a focused, self-describing record
// that unmarshalResourceMetadata round-trips back into a ResourceEntry carrying
// just the metadata. Rendered with protojson snake_case, mirroring marshalTerms.
//
// When the entry carries no metadata the result is nil, so the nullable
// catalog.metadata column stays NULL (no empty-object sentinel).
func marshalResourceMetadata(e *rampv1.ResourceEntry) ([]byte, error) {
	proj := &rampv1.ResourceEntry{
		ContentId:           e.ContentId,
		WordCount:           e.WordCount,
		EstimatedQuantity:   e.EstimatedQuantity,
		ContentHash:         e.ContentHash,
		HashMethod:          e.HashMethod,
		Source:              e.Source,
		ProvenanceSource:    e.ProvenanceSource,
		ProvenanceTimestamp: e.ProvenanceTimestamp,
		Attestations:        e.Attestations,
		ResourceMutability:  e.ResourceMutability,
		Ext:                 e.Ext,
		ExtCritical:         e.ExtCritical,
	}
	if protobuf.Equal(proj, &rampv1.ResourceEntry{}) {
		return nil, nil
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(proj)
	if err != nil {
		return nil, fmt.Errorf("marshal resource metadata: %w", err)
	}
	return b, nil
}

// applyMetadata projects a row's decoded resource extension metadata onto the
// Offer. It must be called BEFORE the offer is signed so every field
// is signature-covered, and it derives ONLY from the stored metadata (no clock,
// no requester state), so a snapshot rebuild renders the same projection for
// the same stored row. resource_mutability is sourced from the typed
// ingest field; previews is still promoted from ext (its typed promotion is a
// separate follow-up); the full ext is also carried verbatim.
func applyMetadata(offer *rampv1.Offer, md *rampv1.ResourceEntry) {
	if offer.Identity == nil {
		offer.Identity = &rampv1.ResourceIdentity{}
	}
	offer.Identity.ContentHash = md.ContentHash
	offer.Identity.HashMethod = md.HashMethod
	// Mutability is OVERRIDDEN only when the publisher explicitly supplied a typed
	// resource_mutability value; otherwise the offer keeps buildOffer's STATIC
	// default. buildOffer documents that default as the value that satisfies the
	// proto rule ResourceIdentity.resource_mutability {not_in:[0]} (now enforced at
	// the execute request boundary). The typed field is an optional pointer, so a
	// nil (omitted) value leaves the default in place rather than downgrading it to
	// UNSPECIFIED — which would produce an offer that fails its OWN
	// ExecuteTransaction validation. Only an explicit publisher value moves it.
	if md.ResourceMutability != nil {
		offer.Identity.ResourceMutability = md.GetResourceMutability()
	}
	offer.Previews = extPreviews(md.Ext)
	offer.Attestations = md.Attestations
	offer.Ext = md.Ext
	offer.ExtCritical = md.ExtCritical
	offer.DataAsOf = md.ProvenanceTimestamp
}

// extPreviews promotes the ext.previews array into typed Offer previews. An
// absent or empty array yields nil (no previews).
func extPreviews(ext *structpb.Struct) []*rampv1.Preview {
	lv := ext.GetFields()["previews"].GetListValue()
	if lv == nil {
		return nil
	}
	out := make([]*rampv1.Preview, 0, len(lv.GetValues()))
	for _, v := range lv.GetValues() {
		if s := v.GetStructValue(); s != nil {
			out = append(out, previewFromStruct(s))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// previewFromStruct maps one ext.previews element into a typed Preview. Optional
// dimensions (width/height/duration/size) are set only when present so the
// emitted preview is proto-equal to what the publisher pushed.
func previewFromStruct(s *structpb.Struct) *rampv1.Preview {
	f := s.GetFields()
	p := &rampv1.Preview{
		Url:       f["url"].GetStringValue(),
		MediaType: f["media_type"].GetStringValue(),
	}
	if v, ok := f["width"]; ok {
		w := int32(v.GetNumberValue())
		p.Width = &w
	}
	if v, ok := f["height"]; ok {
		h := int32(v.GetNumberValue())
		p.Height = &h
	}
	if v, ok := f["duration"]; ok {
		d := int32(v.GetNumberValue())
		p.Duration = &d
	}
	if v, ok := f["size"]; ok {
		sz := v.GetStringValue()
		p.Size = &sz
	}
	return p
}

// unmarshalResourceMetadata decodes the catalog.metadata JSONB document
// (produced by marshalResourceMetadata) back into a ResourceEntry carrying only
// the metadata fields. A NULL/empty column decodes to nil — the read-side
// inverse used by discovery to project persisted metadata onto the Offer.
func unmarshalResourceMetadata(raw []byte) (*rampv1.ResourceEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var e rampv1.ResourceEntry
	if err := protojson.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("decode resource metadata: %w", err)
	}
	return &e, nil
}
