//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// TestPushResources_DuplicateURIUnderDifferentResourceIDRejected proves that
// a single URI belongs to exactly one catalog row. The catalog URI is
// materialized server-side from (domain, path), and the domain pins the URI to
// exactly one tenant (tenants.domain is UNIQUE). The residual exposure
// is therefore SAME-tenant: one contributor pushing the SAME (domain, path) under
// a DIFFERENT content_id — which namespaces to a DIFFERENT resource_id — would,
// without ownership enforcement, INSERT a second row carrying the same URI and
// shadow the first in the discovery trie's longest-prefix lookup. A requester for
// that URI would then resolve to the shadowing row's terms + signing identity.
//
// Enforced behavior: the second push (same URI, different resource_id) is rejected
// per-entry; the original owner's row — its URI binding and its terms — is
// unchanged when read back.
//
// Round-trip honesty: both writes go through the public PushResources RPC; both
// reads go through the public DiscoverResources RPC. No DB/sqlc/Redis access.
// Every leg traverses transport→service→repo→DB and back through the same surface.
func TestPushResources_DuplicateURIUnderDifferentResourceIDRejected(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const path = "/articles/duplicate-uri"
	uri := "https://" + h.publisherDom + path

	// First push: the owner claims the URI under content_id "original".
	if resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		ContentId: proto.String("original"),
		Domain:    h.publisherDom, Path: path,
		Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
	}}))); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("owner push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	before := discoverOffers(t, h, uri)
	if len(before) != 1 {
		t.Fatalf("owner offers = %d, want 1", len(before))
	}

	// Second push: SAME (domain, path) -> SAME URI, but a DIFFERENT content_id, so
	// a DIFFERENT resource_id. This must be rejected, not silently shadow the owner.
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		ContentId: proto.String("shadow"),
		Domain:    h.publisherDom, Path: path,
		Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)},
	}})))
	// All-or-nothing: a duplicate-URI (shadow) entry rejects the whole push.
	if err == nil {
		t.Fatalf("want rejection, got accepted=%d (duplicate URI must be rejected)", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)

	// The owner's offer is intact: still exactly one offer, bound to the owner's
	// URI and still carrying the owner's term. offer_id is minted fresh per
	// issued offer, so row identity is observed through the signed content: the
	// shadow entry's term sets estimated_quantity=1 while the owner's sets none,
	// so any leak of the shadow row is visible on the projected pricing.
	after := discoverOffers(t, h, uri)
	if len(after) != 1 {
		t.Fatalf("after shadow push: owner offers = %d, want 1", len(after))
	}
	if got := after[0].GetIdentity().GetCanonicalUrl(); got != uri {
		t.Fatalf("owner offer canonical_url = %q, want %q — shadow push overwrote the URI", got, uri)
	}
	if est := after[0].GetPricing().GetEstimatedQuantity(); est != 0 {
		t.Fatalf("owner offer now carries estimated_quantity=%d (the shadow entry's term) — shadow push overwrote the URI", est)
	}
}

// TestPushResources_RepushSameResourceUpsertsCleanly proves the ownership
// constraint does NOT block a legitimate re-push: the SAME resource (same
// resource_id, derived from the same content_id, hence the same URI) updates in
// place. Only a DIFFERENT resource_id colliding on URI is a conflict; a re-push
// of the same content carrying updated terms must succeed and replace the terms.
//
// Round-trip: both writes via PushResources; the terms are read back via
// DiscoverResources. transport→service→repo→DB on every leg.
func TestPushResources_RepushSameResourceUpsertsCleanly(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const path = "/articles/repush"
	uri := "https://" + h.publisherDom + path

	push := func(est int32) *connect.Response[rampv1.PushResourcesResponse] {
		resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
			ContentId: proto.String("stable"),
			Domain:    h.publisherDom, Path: path,
			Terms: []*rampv1.LicenseTerm{seedPricedTermEst(est)},
		}})))
		if err != nil {
			t.Fatalf("push est=%d: %v", est, err)
		}
		return resp
	}

	if resp := push(1); resp.Msg.GetAccepted() != 1 {
		t.Fatalf("first push accepted=%d, want 1", resp.Msg.GetAccepted())
	}
	// Re-push of the SAME resource (same content_id -> same resource_id -> same
	// URI) must upsert cleanly, not be rejected as a URI conflict.
	if resp := push(7); resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("re-push accepted=%d rejected=%d, want 1/0 (same resource upserts)",
			resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	if got := discoverOfferCount(t, h, uri); got != 1 {
		t.Fatalf("offers = %d, want 1 (re-push did not duplicate)", got)
	}
}

// TestPushResources_URIMoveRejectedOfferKeepsBinding proves the catalog URI is
// IMMUTABLE for an existing resource_id. Execute binds a presented offer to its
// catalog row via the signed Identity.canonical_url, so if a re-push could move
// a resource's URI, the old URI would be freed for another resource to claim
// and a still-valid signed offer for the mover would silently resolve to that
// other resource — right price, wrong delivery, wrong payee, wrong evidence.
//
// The chain drives every step of that scenario through the public surfaces and
// asserts each hole is closed:
//  1. Resource A claims /old; a signed offer for it is discovered and held.
//  2. A re-push of A (same content_id, hence same resource_id) at /new is
//     rejected whole with the uri_immutable_for_resource reason.
//  3. A push of resource B at /old is rejected: /old is still owned by A.
//  4. Discovery still answers /old with A's offer and answers /new with none.
//  5. The held offer from step 1 still executes — its canonical URL binds to
//     A, the row it was signed for.
//
// Round-trip honesty: writes via PushResources, reads via DiscoverResources,
// the redemption via ExecuteTransaction (multisig parity path). Every leg
// traverses transport→service→repo→DB; no leg reaches past a layer.
func TestPushResources_URIMoveRejectedOfferKeepsBinding(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const oldPath = "/articles/move-old"
	const newPath = "/articles/move-new"
	oldURI := "https://" + h.publisherDom + oldPath
	newURI := "https://" + h.publisherDom + newPath

	push := func(contentID, path string, term *rampv1.LicenseTerm) (*connect.Response[rampv1.PushResourcesResponse], error) {
		return client.PushResources(h.ctx, connect.NewRequest(newPushRequest(
			h.tenantID, callerID, []*rampv1.ResourceEntry{{
				ContentId: proto.String(contentID),
				Domain:    h.publisherDom, Path: path,
				Terms: []*rampv1.LicenseTerm{term},
			}})))
	}

	// Step 1: A claims /old; hold a signed offer for it.
	if resp, err := push("mover", oldPath, seedPricedTerm()); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("A claims /old: err=%v accepted=%d, want 1", err, accepted(resp))
	}
	held := discoverOffers(t, h, oldURI)
	if len(held) != 1 {
		t.Fatalf("offers at /old = %d, want 1", len(held))
	}

	// Step 2: the URI move is rejected up front, whole push, named reason.
	if _, err := push("mover", newPath, seedPricedTerm()); err == nil {
		t.Fatal("URI move accepted — an existing resource_id must not change its URI")
	} else {
		assertConnectError(t, err, connect.CodeInvalidArgument, "uri_immutable_for_resource")
	}

	// Step 3: /old was not freed — B's claim on it is still an ownership conflict.
	if _, err := push("claimer", oldPath, seedPricedTermEst(1)); err == nil {
		t.Fatal("B claimed /old — the rejected move must not free the URI")
	} else {
		assertConnectError(t, err, connect.CodeInvalidArgument, "uri_owned_by_other_resource")
	}

	// Step 4: discovery still binds /old to A (its term carries no
	// estimated_quantity; B's discriminator term sets 1) and /new to nothing.
	after := discoverOffers(t, h, oldURI)
	if len(after) != 1 {
		t.Fatalf("offers at /old = %d, want 1", len(after))
	}
	if got := after[0].GetIdentity().GetCanonicalUrl(); got != oldURI {
		t.Fatalf("offer at /old carries canonical_url %q, want %q", got, oldURI)
	}
	if est := after[0].GetPricing().GetEstimatedQuantity(); est != 0 {
		t.Fatalf("offer at /old carries estimated_quantity=%d (B's term) — binding moved", est)
	}
	if got := discoverOfferCount(t, h, newURI); got != 0 {
		t.Fatalf("offers at /new = %d, want 0 (the move was rejected)", got)
	}

	// Step 5: the held signed offer still redeems — its canonical URL binds to
	// the row it was signed for.
	assertTransactParity(t, h, held[0])
}
