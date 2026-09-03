//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

const metadataProvenanceTS = "2026-03-18T09:30:00Z"

// metadataExt builds the ext Struct a publisher pushes: a previews array
// (promoted to typed Offer previews downstream) plus a non-promoted editorial_desk
// key that must survive verbatim on Offer.ext. resource_mutability is now a typed
// ResourceEntry field, set directly on the pushed entry, not carried in ext.
func metadataExt(t *testing.T) *structpb.Struct {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{
		"editorial_desk": "science",
		"previews": []any{
			map[string]any{"url": "https://cdn/x.jpg", "media_type": "image/jpeg", "width": 150, "height": 100},
			map[string]any{"url": "https://cdn/x.txt", "media_type": "text/plain"},
		},
	})
	if err != nil {
		t.Fatalf("build ext: %v", err)
	}
	return ext
}

// wantPreviews is the typed Offer.previews the metadataExt previews promote to.
func wantPreviews() []*rampv1.Preview {
	w, h := int32(150), int32(100)
	return []*rampv1.Preview{
		{Url: "https://cdn/x.jpg", MediaType: "image/jpeg", Width: &w, Height: &h},
		{Url: "https://cdn/x.txt", MediaType: "text/plain"},
	}
}

// wantAttestations is the attestation set pushed on the metadata entry; the
// discovered Offer must carry it proto-equal (opaque pass-through).
func wantAttestations(t *testing.T) []*rampv1.ResourceAttestation {
	t.Helper()
	claims, err := structpb.NewStruct(map[string]any{"language": "de"})
	if err != nil {
		t.Fatalf("build claims: %v", err)
	}
	return []*rampv1.ResourceAttestation{{
		Verifier:   "publisher.example",
		Keyid:      "pub-key-1",
		AttestedAt: timestamppb.New(mustRFC(t, "2026-03-18T09:31:00Z")),
		Uri:        "https://example/att",
		Claims:     claims,
		Signature:  "FIXTURE_SIG",
	}}
}

func mustRFC(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

// TestPushResources_MetadataRoundTrip is the resource-metadata capstone: a publisher pushes
// a metadata-bearing ResourceEntry and a metadata-free sibling (identical terms)
// via CatalogService.PushResources, and the pushed metadata is observed on the
// discovered Offer through DiscoverResources — proto-equal, NULL rows unaffected,
// and with offer/term/price selection unchanged. It then drives
// ExecuteTransaction on the metadata offer to prove the presented signed bytes
// (metadata included) verify at execute. No DB/SQL access
// (Testing Doctrine pt 9): every assertion reads back through the public RPC.
func TestPushResources_MetadataRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const metaPath = "/articles/with-metadata"
	const basePath = "/articles/no-metadata"
	metaEntry := &rampv1.ResourceEntry{
		ContentId:           proto.String("res-" + uuid.NewString()),
		Domain:              h.publisherDom,
		Path:                metaPath,
		ContentHash:         proto.String("sha256:abc"),
		HashMethod:          proto.String("sha256"),
		WordCount:           proto.Int32(812),
		Source:              rampv1.IngestionSource_INGESTION_SOURCE_CMS_API.Enum(),
		ProvenanceTimestamp: timestamppb.New(mustRFC(t, metadataProvenanceTS)),
		ResourceMutability:  rampv1.ResourceMutability_RESOURCE_MUTABILITY_DYNAMIC.Enum(),
		Ext:                 metadataExt(t),
		ExtCritical:         []string{"previews"},
		Attestations:        wantAttestations(t),
		Terms:               []*rampv1.LicenseTerm{seedPricedTerm()},
	}
	baseEntry := &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      basePath,
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	}

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{metaEntry, baseEntry})))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 2 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want 2/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	offerMeta := singleOffer(t, h, "https://"+h.publisherDom+metaPath)
	offerBase := singleOffer(t, h, "https://"+h.publisherDom+basePath)

	assertOfferMetadata(t, offerMeta)
	assertOfferNoMetadata(t, offerBase)
	assertSelectionUnchanged(t, offerMeta, offerBase)
	assertTransactParity(t, h, offerMeta)
}

// singleOffer discovers uri and asserts exactly one offer is returned.
func singleOffer(t *testing.T, h *pushHarness, uri string) *rampv1.Offer {
	t.Helper()
	offers := discoverOffers(t, h, uri)
	if len(offers) != 1 {
		t.Fatalf("discover %s: got %d offers, want 1", uri, len(offers))
	}
	return offers[0]
}

// assertOfferMetadata verifies every pushed metadata field surfaced on the Offer.
func assertOfferMetadata(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	if o.GetIdentity().GetContentHash() != "sha256:abc" || o.GetIdentity().GetHashMethod() != "sha256" {
		t.Errorf("identity hashes = %q / %q", o.GetIdentity().GetContentHash(), o.GetIdentity().GetHashMethod())
	}
	if o.GetIdentity().GetResourceMutability() != rampv1.ResourceMutability_RESOURCE_MUTABILITY_DYNAMIC {
		t.Errorf("resource_mutability = %v, want DYNAMIC (explicit typed value honored)", o.GetIdentity().GetResourceMutability())
	}
	if !previewsEqual(o.GetPreviews(), wantPreviews()) {
		t.Errorf("previews mismatch:\n got=%v\nwant=%v", o.GetPreviews(), wantPreviews())
	}
	if len(o.GetAttestations()) != 1 || !proto.Equal(o.GetAttestations()[0], wantAttestations(t)[0]) {
		t.Errorf("attestations mismatch: got=%v", o.GetAttestations())
	}
	// resource_mutability is a typed Offer.identity field now; it must NOT leak back
	// into the opaque offer.ext bag.
	if _, present := o.GetExt().GetFields()["resource_mutability"]; present {
		t.Errorf("offer.ext should not carry resource_mutability (it is a typed field): %v", o.GetExt())
	}
	if o.GetExt().GetFields()["editorial_desk"].GetStringValue() != "science" {
		t.Errorf("offer.ext missing non-promoted editorial_desk key: %v", o.GetExt())
	}
	if got := o.GetDataAsOf().AsTime().Format(time.RFC3339); got != metadataProvenanceTS {
		t.Errorf("data_as_of = %q, want %q", got, metadataProvenanceTS)
	}
}

// assertOfferNoMetadata verifies a legacy (NULL-metadata) row yields an Offer
// with no metadata — the additive column leaves existing resources unaffected.
func assertOfferNoMetadata(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	if o.GetIdentity().GetContentHash() != "" || o.GetIdentity().GetHashMethod() != "" {
		t.Errorf("legacy offer carries identity hashes: %v", o.GetIdentity())
	}
	// A legacy / no-metadata offer keeps buildOffer's STATIC default: the publisher
	// supplied no resource_mutability, so applyMetadata leaves the default in place
	// (it overrides ONLY on an explicit publisher value). Under the current proto
	// pin, ResourceIdentity.resource_mutability {not_in:[0]} makes UNSPECIFIED an
	// INVALID offer at the execute boundary — so a legacy offer MUST carry the
	// STATIC default to remain transactable, not UNSPECIFIED. (The earlier
	// UNSPECIFIED expectation predated that proto rule.)
	if o.GetIdentity().GetResourceMutability() != rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC {
		t.Errorf("legacy offer resource_mutability = %v, want STATIC (buildOffer default)", o.GetIdentity().GetResourceMutability())
	}
	if len(o.GetPreviews()) != 0 || len(o.GetAttestations()) != 0 {
		t.Errorf("legacy offer carries previews/attestations: %d / %d", len(o.GetPreviews()), len(o.GetAttestations()))
	}
	if o.GetDataAsOf() != nil {
		t.Errorf("legacy offer data_as_of = %v, want unset", o.GetDataAsOf())
	}
}

// assertSelectionUnchanged proves metadata is pure pass-through: the metadata
// offer's projected terms and derived price are identical to the metadata-free
// sibling built from the same term (the entanglement invariant).
func assertSelectionUnchanged(t *testing.T, meta, base *rampv1.Offer) {
	t.Helper()
	if !proto.Equal(meta.GetPricing(), base.GetPricing()) {
		t.Errorf("pricing diverged with metadata:\n meta=%v\n base=%v", meta.GetPricing(), base.GetPricing())
	}
	if len(meta.GetTerms()) != len(base.GetTerms()) {
		t.Fatalf("terms len = %d vs %d", len(meta.GetTerms()), len(base.GetTerms()))
	}
	for i := range meta.GetTerms() {
		if !proto.Equal(meta.GetTerms()[i], base.GetTerms()[i]) {
			t.Errorf("term[%d] diverged with metadata", i)
		}
	}
}

// assertTransactParity drives ExecuteTransaction on the discovered metadata
// offer: success proves the presented signed bytes (metadata included) verify
// at execute — the signature-parity invariant.
func assertTransactParity(t *testing.T, h *pushHarness, o *rampv1.Offer) {
	t.Helper()
	parityTransact(t, h, o, nil)
}

// parityTransact executes the offer through the multisig path (agent
// sig1 + broker sig2). A direct single-sig call by the harness's broker key
// would trip the lone-broker guard (authz.go); a per-call AGENT co-signs so the
// transaction is a legitimate two-signature relay. Billing is the FreeAdapter,
// so no balance seeding is needed — this asserts signature parity, not billing.
func parityTransact(t *testing.T, h *pushHarness, o *rampv1.Offer, scopes []string) {
	t.Helper()
	items := parityExecute(t, h, o, scopes)
	// The transaction id now lives per-item (top-level TransactionResponse dropped
	// the single-offer transaction_id); assert it is present on the lone result
	// item — same strength as the original "transaction id empty" guard.
	if len(items) != 1 {
		t.Fatalf("response carried %d items, want 1", len(items))
	}
	if items[0].GetTransactionId() == "" {
		t.Fatal("transaction id empty after executing metadata offer")
	}
}

// parityExecute runs the same multisig execute as parityTransact but returns the
// result items instead of asserting success on them. A per-item denial (a
// tampered offer, for instance) is an in-body result of a request that succeeds
// at the transport level, so a caller testing rejection needs the items rather
// than a fatal.
func parityExecute(t *testing.T, h *pushHarness, o *rampv1.Offer, scopes []string) []*rampv1.TransactionResultItem {
	t.Helper()
	return parityExecuteVia(t, h, o, scopes, false)
}

// parityExecuteVia is parityExecute with an explicit transport topology. direct
// selects the agent-direct (single-signature) client; false keeps the
// two-signature broker relay. The tampered-offer title test uses the direct path:
// with a broken offer signature the broker-relay authorization gate fails closed
// (an unresolvable item cannot be attributed to a tenant), which would mask the
// per-item SIGNATURE_INVALID denial the title assertion is actually about.
func parityExecuteVia(
	t *testing.T, h *pushHarness, o *rampv1.Offer, scopes []string, direct bool,
) []*rampv1.TransactionResultItem {
	t.Helper()
	agentID := "agent-parity-" + uuid.NewString()
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("parity agent keygen: %v", err)
	}
	// httpsig resolver keys by RFC 7638 thumbprint (WBA keyid); agents row by
	// the directory identity (agentID).
	h.resolver.Put(rwtestutil.MustThumbprintPriv(agentPriv), agentPub)
	seedAgent(t, h.ctx, h.queries, agentID, agentPub)
	// The paid parity transaction charges through the FreeAdapter, but the service
	// still requires the agent to hold a billing_ref: register it for billing
	// through the public Register RPC (it signs for itself; its key is already in
	// the httpsig resolver above).
	registerCaller(t, h.ctx, h.selfActingExchangeClient(agentID, agentPriv))
	var client rampconnect.ExchangeServiceClient
	if direct {
		client = h.selfActingExchangeClient(agentID, agentPriv)
	} else {
		client = newMultisigClient(h.baseTransport, h.server.URL, agentID, agentPriv, h.discoverKeyID, h.discoverPriv)
	}
	txID := "tx-" + uuid.NewString()
	requester := newRequester(agentID, "agent.example", scopes...)
	// ITEMS-ONLY spine: the offer + its detached agent acceptance ride
	// in items[]; single-offer mode is gone. The acceptance is signed by the
	// per-call agent key over the GENUINE presented offer bytes, requester, and
	// the enclosing idempotency_key, so this remains a legitimate two-signature
	// relay (agent body acceptance + agent sig1 + broker sig2 on the transport).
	resp, err := client.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: txID,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: o, AgentAcceptance: signAcceptanceFor(t, agentPriv, o, requester, txID)},
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction on metadata offer (signature parity broken?): %v", err)
	}
	return resp.Msg.GetItems()
}

// previewsEqual compares two preview slices element-wise with proto.Equal.
func previewsEqual(got, want []*rampv1.Preview) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !proto.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

const (
	pushedTitle  = "Thales of Miletus"
	revisedTitle = "Thales of Miletus, Revised"
)

// TestPushResources_TitleRoundTrip drives the resource title through the public
// RPC surfaces end to end: a publisher pushes one titled and one untitled
// ResourceEntry, and DiscoverResources shows the title on the first offer and
// no title on the second. It then re-pushes the same resource twice — once with
// a changed title, once with none — to pin that the stored title follows the
// latest push in both directions. Finally it alters the title on a signed offer
// and executes it, proving the title is inside the signed payload.
//
// No DB or SQL access (Testing Doctrine pt 9): every assertion reads back
// through PushResources, DiscoverResources, and ExecuteTransaction.
func TestPushResources_TitleRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const titledPath = "/articles/titled"
	const barePath = "/articles/untitled"
	// A stable content_id is what makes the later pushes upsert the SAME row
	// rather than mint a second resource — the re-push assertions below depend
	// on it.
	titledID := "res-" + uuid.NewString()
	titledURI := "https://" + h.publisherDom + titledPath

	pushTitled := func(title *string) {
		t.Helper()
		entry := &rampv1.ResourceEntry{
			ContentId: proto.String(titledID),
			Domain:    h.publisherDom,
			Path:      titledPath,
			Title:     title,
			Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
		}
		pushEntries(t, h, client, callerID, entry)
	}

	pushTitled(proto.String(pushedTitle))
	pushEntries(t, h, client, callerID, &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      barePath,
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	})

	titledOffer := singleOffer(t, h, titledURI)
	if got := titledOffer.GetTitle(); got != pushedTitle {
		t.Errorf("offer title = %q, want %q", got, pushedTitle)
	}
	// Absence must stay absence: an untitled push leaves the field UNSET, not
	// filled with the resource id, the URI, or an empty string. Checking the
	// pointer rather than GetTitle() is what separates unset from empty.
	bareOffer := singleOffer(t, h, "https://"+h.publisherDom+barePath)
	if bareOffer.Title != nil {
		t.Errorf("untitled push produced offer title %q, want unset", bareOffer.GetTitle())
	}

	// A re-push with a changed title must overwrite the stored one. This is the
	// assertion that fails if the upsert's ON CONFLICT DO UPDATE list omits the
	// title column: the first push would then pin the title forever.
	pushTitled(proto.String(revisedTitle))
	if got := singleOffer(t, h, titledURI).GetTitle(); got != revisedTitle {
		t.Errorf("after re-push, offer title = %q, want %q", got, revisedTitle)
	}

	// The other direction of the same rule: a re-push carrying no title clears
	// the stored one.
	pushTitled(nil)
	if cleared := singleOffer(t, h, titledURI); cleared.Title != nil {
		t.Errorf("after titleless re-push, offer title = %q, want unset", cleared.GetTitle())
	}

	assertTitleIsSigned(t, h)
}

// assertTitleIsSigned pushes a titled resource, discovers its signed offer, then
// changes only the title and executes the altered offer. The Exchange must
// refuse it with SIGNATURE_INVALID, which is what proves the title falls inside
// the signed payload rather than riding alongside it.
func assertTitleIsSigned(t *testing.T, h *pushHarness) {
	t.Helper()
	callerID := "caller.example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	const signedPath = "/articles/signed-title"
	pushEntries(t, h, h.signedCat(callerID, priv), callerID, &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      signedPath,
		Title:     proto.String(pushedTitle),
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	})

	genuine := singleOffer(t, h, "https://"+h.publisherDom+signedPath)
	tampered, ok := proto.Clone(genuine).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	tampered.Title = proto.String("Some Other Article")

	// Agent-direct: a tampered offer has a broken signature, so through a broker
	// relay the authorization gate fails closed (it cannot attribute an
	// unverifiable item to a tenant). This test is about the title being inside
	// the signed payload, so it drives the per-item SIGNATURE_INVALID denial on
	// the agent-direct path, where the relay gate does not apply.
	items := parityExecuteVia(t, h, tampered, nil, true)
	if len(items) != 1 {
		t.Fatalf("tampered execute returned %d items, want 1", len(items))
	}
	if got := items[0].GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Errorf("altered-title offer denial = %v, want SIGNATURE_INVALID", got)
	}
	if items[0].GetRetrievalEndpoint() != "" {
		t.Error("altered-title offer was granted a retrieval endpoint")
	}
}

// pushEntries pushes entries through the public PushResources RPC and asserts
// every one was accepted.
func pushEntries(t *testing.T, h *pushHarness, client rampconnect.CatalogServiceClient, callerID string, entries ...*rampv1.ResourceEntry) {
	t.Helper()
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, entries)))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if int(resp.Msg.GetAccepted()) != len(entries) || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want %d/0",
			resp.Msg.GetAccepted(), resp.Msg.GetRejected(), len(entries))
	}
}

// TestExecuteTransaction_ResourceTitleEchoesSignedOffer pins where the
// transaction result's title comes from. The protocol defines resource_title as
// echoed from the Offer, so the value must be read off the signed offer the
// agent accepted, never re-read from the catalog row.
//
// Three cases. A titled offer produces a result carrying that title. An
// untitled offer produces a result with the field unset — no resource id or URI
// substituted. And the case that separates the two possible implementations:
// the catalog title is changed AFTER the offer is signed, and executing the
// original offer must still return the ORIGINALLY OFFERED title. A
// catalog-sourced implementation passes the first two cases and fails this one.
//
// No DB or SQL access: the catalog is changed through PushResources and the
// result is read from the ExecuteTransaction response.
func TestExecuteTransaction_ResourceTitleEchoesSignedOffer(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const titledPath = "/articles/tx-titled"
	const barePath = "/articles/tx-untitled"
	titledID := "res-" + uuid.NewString()
	titledURI := "https://" + h.publisherDom + titledPath

	pushEntries(t, h, client, callerID, &rampv1.ResourceEntry{
		ContentId: proto.String(titledID),
		Domain:    h.publisherDom,
		Path:      titledPath,
		Title:     proto.String(pushedTitle),
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	}, &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      barePath,
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	})

	titledOffer := singleOffer(t, h, titledURI)
	if got := soleResult(t, h, titledOffer).GetResourceTitle(); got != pushedTitle {
		t.Errorf("resource_title = %q, want %q", got, pushedTitle)
	}

	// An offer with no title yields a result with no title. The old behavior put
	// the resource id here, which is a bare content URL — checking the pointer
	// catches both that and an empty-string stand-in.
	bareResult := soleResult(t, h, singleOffer(t, h, "https://"+h.publisherDom+barePath))
	if bareResult.ResourceTitle != nil {
		t.Errorf("untitled offer produced resource_title %q, want unset", bareResult.GetResourceTitle())
	}

	// The catalog drifts after the offer is signed. The agent accepted an offer
	// naming pushedTitle, so that is what the transaction must report — reading
	// the live catalog row here would return revisedTitle instead.
	pushEntries(t, h, client, callerID, &rampv1.ResourceEntry{
		ContentId: proto.String(titledID),
		Domain:    h.publisherDom,
		Path:      titledPath,
		Title:     proto.String(revisedTitle),
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	})
	if got := singleOffer(t, h, titledURI).GetTitle(); got != revisedTitle {
		t.Fatalf("catalog did not drift: new offer title = %q, want %q", got, revisedTitle)
	}
	if got := soleResult(t, h, titledOffer).GetResourceTitle(); got != pushedTitle {
		t.Errorf("after catalog drift, resource_title = %q, want the originally offered %q", got, pushedTitle)
	}
}

// soleResult executes one offer and returns its single result item.
func soleResult(t *testing.T, h *pushHarness, o *rampv1.Offer) *rampv1.TransactionResultItem {
	t.Helper()
	items := parityExecute(t, h, o, nil)
	if len(items) != 1 {
		t.Fatalf("execute returned %d items, want 1", len(items))
	}
	if items[0].GetTransactionId() == "" {
		t.Fatalf("execute denied the offer: %v", items[0].GetDenialReason())
	}
	return items[0]
}
