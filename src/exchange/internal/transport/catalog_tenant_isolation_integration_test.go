//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// seedTenant inserts a fresh tenant under a random publisher domain and returns
// the pair. It seeds ONLY the tenants row — the caller adds a publisher origin +
// contributor list separately when the tenant needs to accept pushes. Used by
// the catalog tenant-isolation tests to stand up a "victim" tenant distinct from
// the harness's primary tenant.
func seedTenant(t *testing.T, h *pushHarness) (tenantID, domain string) {
	t.Helper()
	domain = "pub-" + uuid.NewString() + ".example"
	return seedTenantForDomain(t, h, domain), domain
}

// seedTenantForDomain inserts a tenant bound to the given publisher domain
// through the same InsertTenant query production uses (no raw SQL), returning the
// new tenant_id. Catalog rows are owned by the tenant whose domain matches the
// entry's publisher domain (server-side derivation), so any test that pushes for
// a specific domain must first register that domain as a tenant here.
func seedTenantForDomain(t *testing.T, h *pushHarness, domain string) string {
	t.Helper()
	tenantID := "t_" + uuid.NewString()
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          domain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   "secret://ed25519/" + tenantID,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tenantID
}

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
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		// The caller is authorized for h.publisherDom (= h.tenantID) but claims
		// the victim tenant on the wire.
		TenantId: victimTenant,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: path,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))
	// All-or-nothing: a foreign tenant_id rejects the whole push (InvalidArgument).
	if err == nil {
		t.Fatalf("want rejection, got accepted=%d (foreign tenant_id must be rejected)", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	// The rejected push left no row: the URI is not discoverable under any tenant.
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+path); got != 0 {
		t.Fatalf("offers = %d, want 0 (rejected push must not persist)", got)
	}
}

// TestPushResources_CollidingContentIdDoesNotOverwriteVictim proves that a
// caller cannot overwrite a victim tenant's catalog row by reusing the victim's
// content_id. resource_id (== the public offer_id) is namespaced server-side by
// the owning tenant, so two tenants pushing the SAME content_id produce two
// DISTINCT rows — the attacker can neither address nor clobber the victim's row.
//
// Round-trip: both pushes go through PushResources; both rows are observed
// through DiscoverResources. The victim's offer is unchanged after the attacker
// push and the two offer_ids differ.
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
	if resp, err := victimClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: victimTenant, CallerId: victimCaller,
		Entries: []*rampv1.ResourceEntry{{
			ContentId: proto.String(sharedContentID),
			Domain:    victimDom, Path: victimPath,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("victim push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	victimURI := "https://" + victimDom + victimPath
	before := discoverOffers(t, h, victimURI)
	if len(before) != 1 {
		t.Fatalf("victim offers = %d, want 1", len(before))
	}
	victimOfferID := before[0].GetOfferId()

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
	if resp, err := attackerClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID, CallerId: attackerCaller,
		Entries: []*rampv1.ResourceEntry{{
			ContentId: proto.String(sharedContentID),
			Domain:    h.publisherDom, Path: attackerPath,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil || resp.Msg.GetAccepted() != 1 {
		t.Fatalf("attacker push: err=%v accepted=%d, want 1", err, accepted(resp))
	}

	// The victim row is untouched: same single offer, same opaque offer_id.
	after := discoverOffers(t, h, victimURI)
	if len(after) != 1 || after[0].GetOfferId() != victimOfferID {
		t.Fatalf("victim row overwritten: offers=%d, want 1 with offer_id %q", len(after), victimOfferID)
	}
	// The attacker row is a distinct resource: own URI, different offer_id.
	attackerOffers := discoverOffers(t, h, "https://"+h.publisherDom+attackerPath)
	if len(attackerOffers) != 1 {
		t.Fatalf("attacker offers = %d, want 1", len(attackerOffers))
	}
	if attackerOffers[0].GetOfferId() == victimOfferID {
		t.Fatalf("attacker offer_id collided with victim's (%q) — resource_id namespacing failed", victimOfferID)
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
