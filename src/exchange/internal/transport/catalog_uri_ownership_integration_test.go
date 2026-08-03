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
// per-entry; the original owner's offer — its opaque offer_id (signing identity)
// and its terms — is unchanged when read back.
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
	if resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID, CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			ContentId: proto.String("original"),
			Domain:    h.publisherDom, Path: path,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("owner push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	before := discoverOffers(t, h, uri)
	if len(before) != 1 {
		t.Fatalf("owner offers = %d, want 1", len(before))
	}
	ownerOfferID := before[0].GetOfferId()

	// Second push: SAME (domain, path) -> SAME URI, but a DIFFERENT content_id, so
	// a DIFFERENT resource_id. This must be rejected, not silently shadow the owner.
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID, CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			ContentId: proto.String("shadow"),
			Domain:    h.publisherDom, Path: path,
			Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)},
		}},
	}))
	// All-or-nothing: a duplicate-URI (shadow) entry rejects the whole push.
	if err == nil {
		t.Fatalf("want rejection, got accepted=%d (duplicate URI must be rejected)", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)

	// The owner's offer is intact: still exactly one offer with the same opaque
	// offer_id (the signing identity is unchanged — no shadowing occurred).
	after := discoverOffers(t, h, uri)
	if len(after) != 1 {
		t.Fatalf("after shadow push: owner offers = %d, want 1", len(after))
	}
	if after[0].GetOfferId() != ownerOfferID {
		t.Fatalf("owner offer_id changed (%q -> %q) — shadow push overwrote the URI",
			ownerOfferID, after[0].GetOfferId())
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
		resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
			TenantId: h.tenantID, CallerId: callerID,
			Entries: []*rampv1.ResourceEntry{{
				ContentId: proto.String("stable"),
				Domain:    h.publisherDom, Path: path,
				Terms: []*rampv1.LicenseTerm{seedPricedTermEst(est)},
			}},
		}))
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
