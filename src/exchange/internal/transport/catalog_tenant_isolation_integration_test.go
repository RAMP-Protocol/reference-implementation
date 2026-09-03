//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// TestPushResources_ForeignTenantIdRejected proves the server-side tenant derivation: a caller that is a
// legitimate contributor for one publisher domain cannot write a catalog row
// under a DIFFERENT tenant by naming that tenant on the wire. The server derives
// the owning tenant_id from the entry's publisher domain (tenants.domain is
// UNIQUE) and rejects the disagreeing client tenant_id, rather than honouring it
// and binding the row to the victim tenant's downstream signing key.
//
// Round-trip: write attempt goes through the public PushResources RPC and is
// rejected (count); the absence of the side effect is confirmed through the
// public DiscoverResources RPC (the URI resolves to zero offers).
func TestPushResources_ForeignTenantIdRejected(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	// A victim tenant the caller has no authority over.
	victimTenant, _ := seedTenant(t, h)

	const path = "/articles/cross-tenant"
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(victimTenant, callerID, []*rampv1.ResourceEntry{{
		Domain: h.publisherDom, Path: path,
		Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
	}})))
	// All-or-nothing: a foreign tenant_id rejects the whole push (InvalidArgument).
	if err == nil {
		t.Fatalf("want rejection, got accepted=%d (foreign tenant_id must be rejected)", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	// The rejected push left no row: the URI is not discoverable under any tenant.
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+path); got != 0 {
		t.Fatalf("offers = %d, want 0 (rejected push must not persist)", got)
	}
	// The operator's half. The caller sees the reason in the refusal message;
	// this gate refused in silence until the audit line covered every reason,
	// so an operator investigating a publisher's report had nothing to grep.
	assertCatalogRejectLogged(t, h, path, service.RejectionReasonTenantMismatch)
}

// TestPushResources_CollidingContentIdDoesNotOverwriteVictim proves that a
// caller cannot overwrite a victim tenant's catalog row by reusing the victim's
// content_id. resource_id is namespaced server-side by the owning tenant, so
// two tenants pushing the SAME content_id produce two DISTINCT rows — the
// attacker can neither address nor clobber the victim's row.
//
// Round-trip: both pushes go through PushResources; both rows are observed
// through DiscoverResources. Row identity is observed through each offer's
// signed canonical_url and projected term (offer_id is a random per-offer UUID
// and carries no resource identity): the victim's offer still binds to the
// victim's URI and still carries the victim's term after the attacker push.
func TestPushResources_CollidingContentIdDoesNotOverwriteVictim(t *testing.T) {
	h := newPushHarness(t)

	// Victim: a second tenant whose publisher ramp.json lists a victim caller.
	victimTenant, victimDom := seedTenant(t, h)
	victimCaller := "victim.example"
	h.publishPublisher(t, victimDom, victimCaller)
	vpub, vpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen victim: %v", err)
	}
	h.publishAgent(t, victimCaller, vpub)
	victimClient := h.signedCat(victimCaller, vpriv)

	const sharedContentID = "shared-content-id"
	const victimPath = "/victim/article"
	if resp, err := victimClient.PushResources(h.ctx, connect.NewRequest(newPushRequest(victimTenant, victimCaller, []*rampv1.ResourceEntry{{
		ContentId: proto.String(sharedContentID),
		Domain:    victimDom, Path: victimPath,
		Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
	}}))); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("victim push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	victimURI := "https://" + victimDom + victimPath
	before := discoverOffers(t, h, victimURI)
	if len(before) != 1 {
		t.Fatalf("victim offers = %d, want 1", len(before))
	}

	// Attacker: a legitimate contributor for the harness's primary publisher,
	// reusing the victim's content_id in an attempt to clobber the victim row.
	attackerCaller := "caller.example"
	h.publisher.setContributors(attackerCaller)
	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker: %v", err)
	}
	h.publishAgent(t, attackerCaller, apub)
	attackerClient := h.signedCat(attackerCaller, apriv)

	const attackerPath = "/attacker/article"
	if resp, err := attackerClient.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, attackerCaller, []*rampv1.ResourceEntry{{
		ContentId: proto.String(sharedContentID),
		Domain:    h.publisherDom, Path: attackerPath,
		Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
	}}))); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("attacker push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	// The victim row is untouched: its URI still resolves to exactly one offer
	// bound to the victim URI. Had the attacker's push clobbered the victim row
	// (same content_id, no tenant namespacing), the row's URI would now be the
	// attacker's and this lookup would come back empty. offer_id is minted fresh
	// per issued offer, so row identity is observed through the signed
	// canonical URL, never through offer_id stability.
	after := discoverOffers(t, h, victimURI)
	if len(after) != 1 {
		t.Fatalf("victim row overwritten: offers=%d, want 1 for %q", len(after), victimURI)
	}
	if got := after[0].GetIdentity().GetCanonicalUrl(); got != victimURI {
		t.Fatalf("victim offer canonical_url = %q, want %q — victim row overwritten", got, victimURI)
	}
	// The attacker row is a distinct resource bound to its own URI.
	attackerOffers := discoverOffers(t, h, "https://"+h.publisherDom+attackerPath)
	if len(attackerOffers) != 1 {
		t.Fatalf("attacker offers = %d, want 1", len(attackerOffers))
	}
	if got, want := attackerOffers[0].GetIdentity().GetCanonicalUrl(), "https://"+h.publisherDom+attackerPath; got != want {
		t.Fatalf("attacker offer canonical_url = %q, want %q — resource_id namespacing failed", got, want)
	}
}

// accepted unwraps the accepted count from a PushResources response, tolerating
// a nil response so the *err || accepted != 1* guards above format cleanly.
func accepted(resp *connect.Response[rampv1.PushResourcesResponse]) int32 {
	if resp == nil {
		return -1
	}
	return resp.Msg.GetAccepted()
}
