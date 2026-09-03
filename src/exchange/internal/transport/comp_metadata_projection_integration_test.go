//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/comptest"
)

// metadataResourceProvenanceSource is the provenance_source pushed on the metadata
// metadata entry; it must surface at comp.scope.text[0].provent (matrix §1h) and
// flip comp.scope.text[0].provenance to 1.
const metadataResourceProvenanceSource = "wordpress-plugin"

// TestComp_ResourceMetadataProjection is the resource-metadata-projection RED baseline: it pins
// the projection of RESOURCE-INTRINSIC resource-intrinsic metadata (word_count, provenance,
// content_hash/hash_method, resource_mutability, previews) into the CoMP package
// as a SINGLE Text media object, observed END-TO-END through DiscoverResources
// only (no DB/internal access — Testing Doctrine pt 9). Per the Core Invariant the
// media object is built ONLY from the rebuild-time snapshot's decoded metadata (no
// clock, no requester), so a rebuild renders the same bytes for the same stored
// row.
//
// Two legs run through the public RPC surface:
//
//	FULL (TestComp_ResourceMetadataProjection itself): a publisher pushes ONE
//	  priced entry carrying the metadata fixture (ContentHash
//	  "sha256:abc", HashMethod "sha256", WordCount 812, ProvenanceTimestamp,
//	  ProvenanceSource, ResourceMutability STATIC (typed field), Ext=metadataExt
//	  (previews) + a priced term. Discover WITH SupportedProfiles=["ramp-comp-v1"];
//	  the returned Offer carries offer.Ext["comp"] whose scope.text is a single
//	  Text object with: CoMP-homed fields at canonical paths
//	  (wordcount==[812], pubdate==RFC3339 of the provenance ts, provent set,
//	  provenance==1); RAMP-only facts ONLY under the opaque media ext
//	  (ext.content_hash=="sha256:abc", ext.hash_method=="sha256",
//	  ext.resource_mutability=="RESOURCE_MUTABILITY_STATIC", ext.previews present);
//	  and NO cattax/cat/language keys (no RAMP taxonomy source — matrix line 213).
//	  comptest.Validate accepts the richer Package; assertTransactParity proves
//	  the presented signed bytes (comp ext included) verify at execute.
//
//	EMPTY-MEDIA GUARD (sub-test): a publisher pushes an entry whose metadata
//	  is PRESENT but carries ZERO projectable fields (only a non-promoted
//	  editorial_desk ext key — no word_count/provenance/hash/mutability/previews)
//	  + a priced term. Discover WITH the profile; the comp package has NO "text"
//	  key at all (textFromMetadata returns nil → scope.Text stays nil), and tx
//	  parity still holds. This pins the nil-return branch — a regression that
//	  emitted an empty Text object would change the signed bytes and is caught.
//
// It FAILS on current HEAD: the slice-1/2 renderer (comp_render.go) emits only a
// term-derived Scope and never reads the resource snapshot's metadata, so NO
// scope.text array is produced — the FULL leg's text[0] lookup is absent (an
// assertion failure, not a compile/collection error; every RPC and field it uses
// already exists).
func TestComp_ResourceMetadataProjection(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const metaPath = "/articles/comp-resource-metadata"
	entry := &rampv1.ResourceEntry{
		ContentId:           proto.String("res-" + uuid.NewString()),
		Domain:              h.publisherDom,
		Path:                metaPath,
		ContentHash:         proto.String("sha256:abc"),
		HashMethod:          proto.String("sha256"),
		WordCount:           proto.Int32(812),
		ProvenanceTimestamp: timestamppb.New(mustRFC(t, metadataProvenanceTS)),
		ProvenanceSource:    proto.String(metadataResourceProvenanceSource),
		ResourceMutability:  rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC.Enum(),
		Ext:                 metadataExt(t),
		Terms:               []*rampv1.LicenseTerm{seedPricedTerm()},
	}

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{entry})))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want 1/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	uri := "https://" + h.publisherDom + metaPath

	// FULL: profile-aware discover renders the resource-metadata Text media object.
	compOffer := discoverCompOffer(t, h, uri)
	assertCompResourceMetadataProjection(t, compOffer)

	// PARITY: the signed (now metadata-bearing) comp ext verifies unchanged at execute.
	assertTransactParity(t, h, compOffer)

	// R1 — EMPTY-MEDIA GUARD as a distinct leg.
	t.Run("EmptyMediaGuard", func(t *testing.T) {
		assertCompEmptyMediaGuard(t, h, callerID, priv)
	})
}

// assertCompResourceMetadataProjection verifies the FULL leg: the single Text
// media object the slice-3 renderer must emit. CoMP-homed fields land at canonical
// media paths (oracle-clean); RAMP-only facts ride ONLY under the opaque media ext;
// no RAMP taxonomy keys appear; comptest.Validate accepts the Package.
func assertCompResourceMetadataProjection(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	comp := o.GetExt().GetFields()["comp"].GetStructValue()
	if comp == nil {
		t.Fatalf("offer.ext has no comp Struct under ramp-comp-v1: ext=%v", o.GetExt())
	}

	scope := comp.GetFields()["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", comp.GetFields()["scope"])
	}

	// scope.text is a 1-element array (one offer = one media object, Q7).
	textList := scope.GetFields()["text"].GetListValue()
	if textList == nil || len(textList.GetValues()) != 1 {
		t.Fatalf("comp.scope.text = %v, want a 1-element array", scope.GetFields()["text"])
	}
	text := textList.GetValues()[0].GetStructValue()
	if text == nil {
		t.Fatalf("comp.scope.text[0] is not a Struct: %v", textList.GetValues()[0])
	}
	tf := text.GetFields()

	// CoMP-homed canonical fields.
	gotWC := numberList(tf["wordcount"])
	if !floatSliceEqual(gotWC, []float64{812}) {
		t.Errorf("comp.scope.text[0].wordcount = %v, want [812]", gotWC)
	}
	wantPubdate := mustRFC(t, metadataProvenanceTS).Format(time.RFC3339)
	if got := tf["pubdate"].GetStringValue(); got != wantPubdate {
		t.Errorf("comp.scope.text[0].pubdate = %q, want %q (RFC3339 of provenance ts)", got, wantPubdate)
	}
	// provenance_source pushed -> provent set + provenance == 1.
	if got := tf["provent"].GetStringValue(); got != metadataResourceProvenanceSource {
		t.Errorf("comp.scope.text[0].provent = %q, want %q", got, metadataResourceProvenanceSource)
	}
	if got := tf["provenance"].GetNumberValue(); got != 1 {
		t.Errorf("comp.scope.text[0].provenance = %v, want 1 (provenance available)", got)
	}

	// RAMP-only facts ride ONLY under the opaque media ext (oracle-opaque).
	textExt := tf["ext"].GetStructValue()
	if textExt == nil {
		t.Fatalf("comp.scope.text[0].ext missing or not a Struct: %v", tf["ext"])
	}
	ef := textExt.GetFields()
	if got := ef["content_hash"].GetStringValue(); got != "sha256:abc" {
		t.Errorf("comp.scope.text[0].ext.content_hash = %q, want %q", got, "sha256:abc")
	}
	if got := ef["hash_method"].GetStringValue(); got != "sha256" {
		t.Errorf("comp.scope.text[0].ext.hash_method = %q, want %q", got, "sha256")
	}
	if got := ef["resource_mutability"].GetStringValue(); got != "RESOURCE_MUTABILITY_STATIC" {
		t.Errorf("comp.scope.text[0].ext.resource_mutability = %q, want %q", got, "RESOURCE_MUTABILITY_STATIC")
	}
	if _, ok := ef["previews"]; !ok {
		t.Errorf("comp.scope.text[0].ext.previews missing: ext=%v", textExt)
	}

	// ABSENCE: NO RAMP taxonomy/language keys (no RAMP source today — matrix 213).
	for _, key := range []string{"cattax", "cat", "language"} {
		if _, ok := tf[key]; ok {
			t.Errorf("comp.scope.text[0] carries %q, but RAMP has no taxonomy/language source", key)
		}
	}

	// The metadata-bearing comp Struct must validate as canonical CoMP V1.
	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil", err)
	}
}

// assertCompEmptyMediaGuard verifies R1: an offer whose metadata is PRESENT but
// carries ZERO projectable fields (only a non-promoted editorial_desk ext key)
// must produce a comp package with NO "text" key at all — proving textFromMetadata
// returns nil rather than emitting an empty Text object — and tx parity still holds
// (the signed bytes are unchanged by the non-projectable metadata).
func assertCompEmptyMediaGuard(t *testing.T, h *pushHarness, callerID string, priv ed25519.PrivateKey) {
	t.Helper()
	const emptyMediaPath = "/articles/comp-empty-media"
	ext, err := structpb.NewStruct(map[string]any{"editorial_desk": "science"})
	if err != nil {
		t.Fatalf("build empty-media ext: %v", err)
	}
	entry := &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      emptyMediaPath,
		Ext:       ext, // present metadata, NO projectable field
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	}

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{entry})))
	if err != nil {
		t.Fatalf("push (empty-media): %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("empty-media accepted=%d rejected=%d, want 1/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	uri := "https://" + h.publisherDom + emptyMediaPath
	o := discoverCompOffer(t, h, uri)

	comp := o.GetExt().GetFields()["comp"].GetStructValue()
	if comp == nil {
		t.Fatalf("offer.ext has no comp Struct under ramp-comp-v1: ext=%v", o.GetExt())
	}
	scope := comp.GetFields()["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", comp.GetFields()["scope"])
	}
	if _, ok := scope.GetFields()["text"]; ok {
		t.Errorf("comp.scope.text present for non-projectable metadata (empty-media guard breached): %v", scope.GetFields()["text"])
	}

	// PARITY: the comp ext (no text[]) verifies unchanged at execute.
	assertTransactParity(t, h, o)
}
