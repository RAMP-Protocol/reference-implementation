//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestPushResources_ImpersonationRejectedAsUnauthenticated proves the catalog
// push handler rejects a signer that claims another contributor's identity, and
// that the rejection surfaces as Unauthenticated — NOT PermissionDenied. The
// keyid is never compared to caller_id; the request signature is verified against
// the key the caller_id directory pins, and a signer holding a different key
// simply fails that verification, which is an authentication failure.
//
// Threat model exercised, driven end-to-end through the real RPC + RFC 9421 stack:
//   - "attacker.example" and "victim.example" are BOTH legitimately registered
//     contributors the target publisher lists (so Gate 2's
//     AuthorizesContributor(manifest, caller_id) passes for either).
//   - The attacker signs the push with ITS OWN key but sets req.caller_id =
//     "victim.example" — impersonating the victim.
//
// After the WBA split identity keys on the Signature-Agent directory: the catalog
// verifier resolves the key PINNED for caller_id (victim) and checks the request
// signature against THAT key. The attacker signed with its own key, so the
// verification fails against victim's pinned key → Unauthenticated, and NO catalog
// row is attributed to the victim. (The keyid is only an RFC 7638 thumbprint /
// proof of possession; it is never compared to caller_id directly.)
//
// Round-trip honesty: this is a full PROTOCOL round-trip on both legs. The write
// leg drives CatalogService/PushResources through the Connect-Go router + RFC 9421
// verification + service authz + repository + DB. The side-effect assertion reads
// back through ExchangeService/DiscoverResources (the public discovery surface the
// sibling ContributorAdmitted test uses) — never raw sqlc/SQL/DB (Testing Doctrine 9).
func TestPushResources_ImpersonationRejectedAsUnauthenticated(t *testing.T) {
	h := newPushHarness(t)

	const attackerID = "attacker.example"
	const victimID = "victim.example"

	// The target publisher lists BOTH contributors, so Gate 2 would authorize a
	// push naming either of them.
	h.publisher.setContributors(attackerID, victimID)

	// The attacker is legitimately registered: publish its agent manifest, then
	// drive one honest self-push so the lazy self-signup path stores the attacker's
	// real key in the agents repo.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker key: %v", err)
	}
	h.publishAgent(t, attackerID, attackerPub)
	attackerClient := h.signedCat(attackerID, attackerPriv)
	if _, err := attackerClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: attackerID, // honest: signer == claimed identity
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/attacker-own",
		}},
	})); err != nil {
		t.Fatalf("attacker honest self-push (registration warm-up): %v", err)
	}

	// The victim is ALSO a real contributor: publish its manifest so the catalog
	// verifier can learn victim's own key when a push claims caller_id=victim.
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen victim key: %v", err)
	}
	h.publishAgent(t, victimID, victimPub)

	uri := "https://" + h.publisherDom + "/articles/impersonated"

	// Now the attack: sign with the ATTACKER's key but set caller_id =
	// victim.example. A priced term makes a successful push materialize a
	// discoverable offer, giving the no-side-effect assertion a public read surface.
	_, err = attackerClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: victimID, // forged: signer is attacker, claimed identity is victim
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/impersonated",
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))

	// WBA: the request signature is checked against victim's PINNED key; the
	// attacker signed with its own key, so verification fails → Unauthenticated.
	assertConnectCode(t, err, connect.CodeUnauthenticated)

	// And the impersonation must leave NO trace: no catalog row attributed to the
	// victim, so the entry resolves to zero offers through the public surface.
	if got := discoverOfferCount(t, h, uri); got != 0 {
		t.Fatalf("impersonated entry offers = %d, want 0 (push must be rejected, no row written)", got)
	}
}
