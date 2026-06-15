//go:build integration

package transport_test

import (
	"net/url"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampthumbprint"
)

// TestExecuteTransaction_SignatureInvalid asserts that a tampered offer
// signature is rejected with Unauthenticated.
func TestExecuteTransaction_SignatureInvalid(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx

	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	bogus := offers[0].GetSignature() + "00"
	offerID := offers[0].GetOfferId()

	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-bad",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(bogus),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	assertConnectCode(t, err, connect.CodeUnauthenticated)
}

// TestExecuteTransaction_BillingDenied confirms denial when the agent has
// no balance configured.
func TestExecuteTransaction_BillingDenied(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	_, _ = h.billing.Authorize(ctx, tenantDrain(t))
	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-drain",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	assertConnectCode(t, err, connect.CodePermissionDenied)
}

// TestExecuteTransaction_Idempotency rejects duplicate tx_request_id replays.
func TestExecuteTransaction_Idempotency(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	req := &rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-dup",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}
	if _, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	assertConnectError(t, err, connect.CodeAlreadyExists, "tx_request_id")
}

// TestExecuteTransaction_SurfacesRetrievalEndpoint pins the canonical wire
// contract: a successful transaction surfaces the signed delivery URL on the
// RAMP-native TransactionResponse.retrieval_endpoint field (field 18), not the
// legacy ext["signed_url"] struct slot, with ExpiresAt carrying its expiry.
func TestExecuteTransaction_SurfacesRetrievalEndpoint(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-retrieval-endpoint",
		OfferId:        stringPtr(offer.GetOfferId()),
		OfferSignature: stringPtr(offer.GetSignature()),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	msg := resp.Msg

	// extractSignedURL asserts retrieval_endpoint is set AND the legacy
	// ext["signed_url"] carrier is gone. This test additionally pins that the
	// value is the minted Ed25519 signed URL for the seeded resource and that
	// ExpiresAt carries its expiry.
	got := extractSignedURL(t, msg)
	if !strings.Contains(got, "/articles/hello") {
		t.Errorf("retrieval_endpoint = %q, want the signed URL for the seeded resource", got)
	}
	if !strings.Contains(got, "sig=") {
		t.Errorf("retrieval_endpoint = %q, want an Ed25519 sig query param", got)
	}
	if msg.GetExpiresAt() == nil {
		t.Error("expires_at not set alongside retrieval_endpoint")
	}
}

// TestExecuteTransaction_BindsAgentIdentity pins the delivery-URL identity
// binding (ADR-013): a successful transaction echoes the RFC 7638 thumbprint of
// the proven caller key on agent_identity_hash (base64url-no-pad), and embeds
// the SAME value as the signed URL's agent_id query param. Both the response
// field and the URL param flow from agentBindingFor's single encode, so this
// equality is guaranteed at the source, not coincidental (ADR-013 D4).
func TestExecuteTransaction_BindsAgentIdentity(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-bind",
		OfferId:        stringPtr(offer.GetOfferId()),
		OfferSignature: stringPtr(offer.GetSignature()),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	msg := resp.Msg

	want, err := rampthumbprint.Thumbprint(h.callerPub)
	if err != nil {
		t.Fatalf("expected thumbprint: %v", err)
	}
	if got := msg.GetAgentIdentityHash(); got != want {
		t.Errorf("agent_identity_hash = %q, want base64url thumbprint %q", got, want)
	}
	// The wire value must be base64url-no-pad, not the old hex encoding.
	if strings.ContainsAny(msg.GetAgentIdentityHash(), "+/=") {
		t.Errorf("agent_identity_hash %q is not base64url-no-pad", msg.GetAgentIdentityHash())
	}

	signedURL := extractSignedURL(t, msg)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse retrieval_endpoint: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != want {
		t.Errorf("URL agent_id = %q, want %q (must equal agent_identity_hash)", got, want)
	}
}

// ---- helpers --------------------------------------------------------------

func seedCatalog(t *testing.T, h *testHarness) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries:  []*rampv1.ResourceEntry{{Domain: h.tenantDomain, Path: "/articles/hello"}},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
}

func discoverFirst(t *testing.T, h *testHarness) []*rampv1.Offer {
	t.Helper()
	resp, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q", Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: []string{"https://" + h.tenantDomain + "/articles/hello"},
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatal("no offers returned")
	}
	return resp.Msg.GetOffers()
}
