//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
)

// ADR-009 D2: the first inbound request whose keyID is absent from
// ramp.agents triggers lazy registration — pull the caller's own
// /.well-known/ramp.json, verify the asserted key is published there,
// persist the row, then proceed with authorization. These tests drive that
// path through the real ExecuteTransaction surface in resolveCaller.
//
// Precondition shared by every case: the agent's transport-signing pubkey is
// registered in the global-httpsig static resolver (so the RFC 9421 signature
// verifies) while its ramp.agents row is deliberately absent (so resolveCaller
// meets ErrAgentNotFound and must lazily register or refuse).

// seedFreeEntryViaBroker has the pre-registered broker push one free resource
// entry against the publisher tenant and returns its discoverable URI. The
// broker (discoverKeyID) is already an agents row, so this setup does not
// register the agent under test.
func seedFreeEntryViaBroker(t *testing.T, h *pushHarness) string {
	t.Helper()
	uri := "https://" + h.publisherDom + "/articles/free-lazy"
	h.publisher.setContributors(h.discoverKeyID)
	pushCat := h.signedCat(h.discoverKeyID, h.discoverPriv)
	resp, err := pushCat.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: h.discoverKeyID,
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/free-lazy"}},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 {
		t.Fatalf("seed accepted=%d, want 1 (rejected=%d)", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
	return uri
}

// discoverFreeOffer runs DiscoverResources for uri via the supplied client and
// returns the first offer.
func discoverFreeOffer(
	t *testing.T, h *pushHarness, client rampconnect.ExchangeServiceClient, agentID, uri string,
) *rampv1.Offer {
	t.Helper()
	resp, err := client.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q-" + uuid.NewString(),
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: []string{uri},
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	offers := resp.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("offers len=%d, want 1", len(offers))
	}
	return offers[0]
}

// TestLazyCallerRegistration_PublishedKeyAdmitted is the happy path: an unknown
// keyID whose key IS published at its own /.well-known/ramp.json is registered
// on first contact and the ExecuteTransaction proceeds. The agents row and a
// transaction_log row both land as side effects.
func TestLazyCallerRegistration_PublishedKeyAdmitted(t *testing.T) {
	h := newPushHarness(t)
	uri := seedFreeEntryViaBroker(t, h)

	agentID := "lazy-caller-" + uuid.NewString() + ".example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	// Publish the agent's manifest carrying its key, and register the same key
	// in the httpsig resolver so its transport signature verifies.
	h.publishAgent(t, agentID, pub)
	h.resolver.Put(agentID, pub)

	// Precondition: no agents row yet.
	if _, err := h.queries.GetAgent(h.ctx, agentID); err == nil {
		t.Fatal("agent row exists before lazy registration; setup bug")
	}

	client := h.selfActingExchangeClient(agentID, priv)
	offer := discoverFreeOffer(t, h, client, agentID, uri)

	offerID, offerSig := offer.GetOfferId(), offer.GetSignature()
	execResp, err := client.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-" + uuid.NewString(),
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction (lazy-registered caller): %v", err)
	}
	if execResp.Msg.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}

	// Side effect: the agents row now carries the manifest's pubkey.
	row, err := h.queries.GetAgent(h.ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent after lazy registration: %v", err)
	}
	if string(row.PublicKey) != string(pub) {
		t.Fatal("stored pubkey != manifest pubkey")
	}
}

// Negative paths: an unknown keyID whose manifest fetch fails is refused and no
// agents/transaction row is written. Each case drives a distinct
// mapLazyRegisterError branch through the real ExchangeService surface, asserting
// the Connect code the caller observes. The transport signature still verifies
// (resolver.Put) so the failure surfaces at the service's lazy-registration
// fetch, not at the httpsig middleware.

// TestLazyCallerRegistration_UnpublishedKeyRefused — origin 404s: the key is not
// published anywhere the Exchange can anchor it → Unauthenticated.
func TestLazyCallerRegistration_UnpublishedKeyRefused(t *testing.T) {
	runLazyExecuteExpectingCode(t, func(o *pushAgentOrigin) { o.missing = true }, connect.CodeUnauthenticated)
}

// TestLazyCallerRegistration_MalformedManifestRefused — origin serves a
// schema-invalid body → Unauthenticated (not a registrable identity).
func TestLazyCallerRegistration_MalformedManifestRefused(t *testing.T) {
	runLazyExecuteExpectingCode(t, func(o *pushAgentOrigin) { o.malformed = true }, connect.CodeUnauthenticated)
}

// TestLazyCallerRegistration_NoValidKeyRefused — origin publishes only a key
// outside its validity window → Unauthenticated.
func TestLazyCallerRegistration_NoValidKeyRefused(t *testing.T) {
	runLazyExecuteExpectingCode(t, func(o *pushAgentOrigin) { o.expired = true }, connect.CodeUnauthenticated)
}

// TestLazyCallerRegistration_TransientManifestUnavailable — origin 503s: a
// transient transport failure → Unavailable/retryable, distinct from the
// caller-fault Unauthenticated cases above.
func TestLazyCallerRegistration_TransientManifestUnavailable(t *testing.T) {
	runLazyExecuteExpectingCode(t, func(o *pushAgentOrigin) { o.unavailable = true }, connect.CodeUnavailable)
}

// runLazyExecuteExpectingCode seeds a free entry, mints a fresh agent whose
// transport key is injected (so its signature verifies) but whose manifest
// origin is mutated by configure, then drives ExecuteTransaction and asserts the
// Connect code plus that no agents row was persisted.
func runLazyExecuteExpectingCode(t *testing.T, configure func(*pushAgentOrigin), want connect.Code) {
	t.Helper()
	h := newPushHarness(t)
	uri := seedFreeEntryViaBroker(t, h)

	agentID := "lazy-fail-" + uuid.NewString() + ".example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	origin := h.publishAgent(t, agentID, pub)
	origin.mu.Lock()
	configure(origin)
	origin.mu.Unlock()
	h.resolver.Put(agentID, pub)

	client := h.selfActingExchangeClient(agentID, priv)
	offer := discoverFreeOffer(t, h, client, agentID, uri)

	offerID, offerSig := offer.GetOfferId(), offer.GetSignature()
	_, err = client.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-" + uuid.NewString(),
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	assertCode(t, err, want)

	if _, err := h.queries.GetAgent(h.ctx, agentID); err == nil {
		t.Fatalf("agent %q must not be registered after a failed manifest fetch", agentID)
	}
}
