package service

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestDecodeRowMetadata asserts a catalog row's metadata JSONB decodes once at
// rebuild: a row carrying metadata decodes to the projected ResourceEntry, and a
// row with no metadata (NULL column) decodes to nil.
func TestDecodeRowMetadata(t *testing.T) {
	raw, err := marshalResourceMetadata(metadataEntry(t))
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	withMeta := decodeRowMetadata(context.Background(), repo.CatalogEntry{ResourceID: "r1", MetadataJSON: raw})
	if withMeta == nil {
		t.Fatal("decodeRowMetadata returned nil for a metadata-bearing row")
	}
	if withMeta.GetContentHash() != "sha256:abc" || withMeta.GetHashMethod() != "sha256" {
		t.Errorf("decoded metadata = hash %q method %q", withMeta.GetContentHash(), withMeta.GetHashMethod())
	}

	if got := decodeRowMetadata(context.Background(), repo.CatalogEntry{ResourceID: "r2"}); got != nil {
		t.Errorf("expected nil metadata for a NULL-column row, got %v", got)
	}
}

// TestSnapshotDecodedMetadata asserts the DecodedMetadata accessor returns the
// cached entry for a known resource, nil for an unknown id, and is nil-safe.
func TestSnapshotDecodedMetadata(t *testing.T) {
	snap := newEmptySnapshot()
	want := metadataEntry(t)
	snap.metadata["r1"] = want

	if got := snap.DecodedMetadata("r1"); got != want {
		t.Errorf("DecodedMetadata(r1) = %v, want the cached entry", got)
	}
	if got := snap.DecodedMetadata("unknown"); got != nil {
		t.Errorf("DecodedMetadata(unknown) = %v, want nil", got)
	}
	var nilSnap *CatalogSnapshot
	if got := nilSnap.DecodedMetadata("r1"); got != nil {
		t.Errorf("nil snapshot DecodedMetadata = %v, want nil", got)
	}
}

// TestSnapshotRenderedProfile asserts the RenderedProfile accessor returns the
// CoMP blob rendered ONCE at rebuild for a known (resourceID, termIndex, profile)
// triple, nil for any unknown level of the lookup, and is nil-receiver-safe. This
// is the render-once-at-rebuild proof for the Slice 7 refactor: the
// per-(term,profile) render moves off the discovery hot path into the snapshot
// rebuild cache, and RenderedProfile is the production read surface CatalogSnapshot
// exposes for that cache — mirroring DecodedMetadata exactly (white-box, package
// service, populated directly via newEmptySnapshot).
func TestSnapshotRenderedProfile(t *testing.T) {
	snap := newEmptySnapshot()
	want, err := structpb.NewStruct(map[string]any{"id": "r1#0"})
	if err != nil {
		t.Fatalf("build rendered struct: %v", err)
	}
	snap.rendered["r1"] = map[int]map[string]*structpb.Struct{
		0: {profileCoMPV1: want},
	}

	if got := snap.RenderedProfile("r1", 0, profileCoMPV1); got != want {
		t.Errorf("RenderedProfile(r1,0,%s) = %v, want the cached struct", profileCoMPV1, got)
	}
	if got := snap.RenderedProfile("unknown", 0, profileCoMPV1); got != nil {
		t.Errorf("RenderedProfile(unknown resource) = %v, want nil", got)
	}
	if got := snap.RenderedProfile("r1", 99, profileCoMPV1); got != nil {
		t.Errorf("RenderedProfile(unknown termIndex) = %v, want nil", got)
	}
	if got := snap.RenderedProfile("r1", 0, "ramp-news-v1"); got != nil {
		t.Errorf("RenderedProfile(unknown profile) = %v, want nil", got)
	}
	var nilSnap *CatalogSnapshot
	if got := nilSnap.RenderedProfile("r1", 0, profileCoMPV1); got != nil {
		t.Errorf("nil snapshot RenderedProfile = %v, want nil", got)
	}
}
