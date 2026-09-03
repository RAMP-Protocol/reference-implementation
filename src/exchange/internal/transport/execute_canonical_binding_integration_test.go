//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// Execute-time catalog binding rides on the signed offer's Identity.canonical_url,
// not on offer_id: offer_id is an opaque per-offer identifier and carries no
// resource semantics, so the catalog lookup keys on the URL the Exchange signed
// into the offer at discovery. These tests pin the three edges of that contract
// through the public ExecuteTransaction surface: the lookup ignores offer_id,
// requires a non-empty canonical URL, and matches the stored URI exactly.

// resignedOffer clones a genuine discovered offer, applies mutate, and re-signs
// the result with the harness's own Exchange offer key, producing a VALIDLY
// SIGNED offer with attacker-free provenance. This simulates "the Exchange
// issued an offer shaped like this" — the only way to get past signature
// verification (which runs before the catalog binding under test) with a
// mutated field, since every bound field is signature-covered.
func resignedOffer(t *testing.T, h *testHarness, genuine *rampv1.Offer, mutate func(*rampv1.Offer)) *rampv1.Offer {
	t.Helper()
	o, ok := proto.Clone(genuine).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	mutate(o)
	o.Signature = ""
	sig, err := h.offerSigner.SignOffer(o)
	if err != nil {
		t.Fatalf("re-sign offer: %v", err)
	}
	o.Signature = sig
	return o
}

// TestExecuteTransaction_BindsCatalogByCanonicalURL proves the execute path
// binds a presented offer to its catalog entry via the signed canonical URL and
// NOT via offer_id: an offer whose offer_id matches nothing in the catalog but
// whose canonical_url names the seeded resource executes successfully. This is
// the property that lets offer_id be a random per-offer UUID.
func TestExecuteTransaction_BindsCatalogByCanonicalURL(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	genuine := discoverFirst(t, h)[0]

	opaque := resignedOffer(t, h, genuine, func(o *rampv1.Offer) {
		o.OfferId = "0f30a915-not-a-resource-id"
	})
	resp, err := executeSingleItem(t, h, "tx-canon-bind", opaque)
	if err != nil {
		t.Fatalf("execute with opaque offer_id: %v (catalog binding must key on canonical_url, not offer_id)", err)
	}
	// Full delivery: the item carries the signed retrieval URL for the resource
	// the canonical URL names.
	_ = itemSignedURL(t, resp)
}

// TestExecuteTransaction_EmptyCanonicalURLRejected drives the negative path:
// the signed canonical URL is REQUIRED at execute. An offer presenting no
// canonical URL cannot be bound to a catalog entry, so the request is rejected
// as invalid (an envelope InvalidArgument, not an in-body denial) with zero
// side effects — no billing calls and no rows written.
func TestExecuteTransaction_EmptyCanonicalURLRejected(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	genuine := discoverFirst(t, h)[0]

	unbound := resignedOffer(t, h, genuine, func(o *rampv1.Offer) {
		o.Identity.CanonicalUrl = nil
	})
	const txID = "tx-canon-empty"
	_, err := executeSingleItem(t, h, txID, unbound)
	assertConnectError(t, err, connect.CodeInvalidArgument, "canonical_url")
	assertNoTransaction(t, h, derivedTxKey(txID, unbound))
	assertBalanceUnchanged(t, h)
}

// TestExecuteTransaction_CanonicalURLExactMatchOnly pins that the execute-time
// binding is an EXACT match on the stored catalog URI, not the longest-prefix
// match the discovery trie performs: a canonical URL that extends a seeded URI
// by a suffix binds to nothing, so the item is denied with zero side effects.
//
// The denial reason is CONTENT_UNAVAILABLE. The Exchange cannot tell an offer
// naming a URI the catalog never held from an offer whose resource the publisher
// has since withdrawn — both arrive as the same catalog miss on a signed
// canonical_url — so both take the reason the protocol defines for a resource
// that is no longer available.
func TestExecuteTransaction_CanonicalURLExactMatchOnly(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	genuine := discoverFirst(t, h)[0]

	extended := resignedOffer(t, h, genuine, func(o *rampv1.Offer) {
		u := o.GetIdentity().GetCanonicalUrl() + "/nested"
		o.Identity.CanonicalUrl = &u
	})
	const txID = "tx-canon-prefix"
	resp, err := executeSingleItem(t, h, txID, extended)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_CONTENT_UNAVAILABLE)
	assertNoTransaction(t, h, derivedTxKey(txID, extended))
	assertBalanceUnchanged(t, h)
}
