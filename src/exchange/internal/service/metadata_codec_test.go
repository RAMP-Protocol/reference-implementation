package service

import (
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// timeRFC parses an RFC3339 timestamp for the codec tests, failing the test on
// a malformed value.
func timeRFC(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

// metadataEntry builds a ResourceEntry carrying every metadata field (and
// domain/path/terms that must NOT survive the projection) for the codec tests.
func metadataEntry(t *testing.T) *rampv1.ResourceEntry {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{
		"previews": []any{map[string]any{"url": "https://cdn/x.jpg", "media_type": "image/jpeg"}},
	})
	if err != nil {
		t.Fatalf("ext struct: %v", err)
	}
	claims, err := structpb.NewStruct(map[string]any{"language": "de"})
	if err != nil {
		t.Fatalf("claims struct: %v", err)
	}
	wc, eq := int32(812), int32(1072)
	return &rampv1.ResourceEntry{
		Domain:              "publisher.example",
		Path:                "/article/meta",
		Terms:               []*rampv1.LicenseTerm{{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED}},
		ContentId:           proto("pub-rt-0001"),
		WordCount:           &wc,
		EstimatedQuantity:   &eq,
		ContentHash:         proto("sha256:abc"),
		HashMethod:          proto("sha256"),
		Source:              rampv1.IngestionSource_INGESTION_SOURCE_CMS_API.Enum(),
		ProvenanceSource:    proto("wordpress-plugin"),
		ProvenanceTimestamp: timestamppb.New(timeRFC(t, "2026-03-18T09:30:00Z")),
		ResourceMutability:  rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC.Enum(),
		Ext:                 ext,
		ExtCritical:         []string{"previews"},
		Attestations: []*rampv1.ResourceAttestation{{
			Verifier: "publisher.example", Keyid: "pub-key-1", Uri: "https://publisher.example/article/meta",
			AttestedAt: timestamppb.New(timeRFC(t, "2026-03-18T09:31:00Z")), Claims: claims, Signature: "FIXTURE_SIG",
		}},
	}
}

// TestMarshalResourceMetadataRoundTrip asserts the metadata projection
// round-trips: every metadata field survives marshal->unmarshal, and the
// non-metadata fields (domain/path/terms) are intentionally absent.
func TestMarshalResourceMetadataRoundTrip(t *testing.T) {
	in := metadataEntry(t)
	raw, err := marshalResourceMetadata(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if raw == nil {
		t.Fatal("expected non-nil metadata JSON for a metadata-bearing entry")
	}
	got, err := unmarshalResourceMetadata(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The projection must preserve EVERY metadata field and drop ONLY the
	// non-metadata columns (domain/path/title/terms). Deriving want from in —
	// rather than re-listing the metadata fields — means a field that
	// marshalResourceMetadata forgets to project fails this test instead of
	// passing by parallel omission.
	want := protobuf.Clone(in).(*rampv1.ResourceEntry)
	want.Domain = ""
	want.Path = ""
	want.Title = nil
	want.Terms = nil
	if !protobuf.Equal(got, want) {
		t.Errorf("round-trip mismatch:\n got=%v\nwant=%v", got, want)
	}
	if got.GetDomain() != "" || got.GetPath() != "" || len(got.GetTerms()) != 0 {
		t.Errorf("projection leaked non-metadata fields: domain=%q path=%q terms=%d",
			got.GetDomain(), got.GetPath(), len(got.GetTerms()))
	}
}

// TestMarshalResourceMetadataEmpty asserts an entry without metadata marshals to
// nil so the nullable catalog.metadata column stays NULL.
func TestMarshalResourceMetadataEmpty(t *testing.T) {
	raw, err := marshalResourceMetadata(&rampv1.ResourceEntry{Domain: "d", Path: "/p"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil metadata for an entry with no metadata fields, got %s", raw)
	}
	got, err := unmarshalResourceMetadata(nil)
	if err != nil {
		t.Fatalf("unmarshal(nil): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil entry decoding nil metadata, got %v", got)
	}
}
