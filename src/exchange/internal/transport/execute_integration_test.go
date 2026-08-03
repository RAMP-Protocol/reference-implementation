//go:build integration

package transport_test

import (
	"net/url"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestExecuteTransaction_SignatureInvalid asserts that a tampered offer
// signature surfaces as an in-body per-item denial after the C4 items-only
// collapse: SIGNATURE_INVALID is a denial-map kind, so a single-item batch
// returns HTTP 200 with items[0].denial_reason == SIGNATURE_INVALID and no
// retrieval_endpoint (Flag #1), rather than a connect Unauthenticated error.
func TestExecuteTransaction_SignatureInvalid(t *testing.T) {
	h := newTestHarness(t)

	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	bogus := offers[0].GetSignature() + "00"
	offerID := offers[0].GetOfferId()

	bogusOffer := &rampv1.Offer{OfferId: offerID, Signature: bogus}
	resp, err := executeSingleItem(t, h, "tx-bad", bogusOffer)
	// The offer-signature guard fires in resolveOfferForTx (KindSignatureInvalid),
	// before the body acceptance is verified; the kind is in the denial map.
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
}

// TestExecuteTransaction_BillingDenied confirms denial when the agent has
// no balance configured. INSUFFICIENT_BALANCE (KindBillingDenied) is a
// denial-map kind → in-body per-item denial after the C4 collapse (was a
// top-level PermissionDenied connect error before items-only).
func TestExecuteTransaction_BillingDenied(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	_, _ = h.billing.Authorize(ctx, tenantDrain(t, h.billingRef))
	resp, err := executeSingleItem(t, h, "tx-drain", offer)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
}

// TestExecuteTransaction_SurfacesRetrievalEndpoint pins the canonical wire
// contract on the items[] path: a successful single-item transaction surfaces
// the signed delivery URL on the per-item retrieval_endpoint (TransactionResultItem
// field), not the legacy ext["signed_url"] struct slot, with the item's
// ExpiresAt carrying its expiry. (Top-level single-mode result fields are gone
// after the C4 collapse — buildBatchTxResponse is the sole builder.)
func TestExecuteTransaction_SurfacesRetrievalEndpoint(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	resp, err := executeSingleItem(t, h, "tx-retrieval-endpoint", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// The legacy ext["signed_url"] carrier must remain unpopulated.
	if ext := resp.Msg.GetExt(); ext != nil {
		if _, ok := ext.GetFields()["signed_url"]; ok {
			t.Fatalf(`legacy ext["signed_url"] must no longer be populated; keys=%v`, ext.GetFields())
		}
	}
	item := singleResultItem(t, resp)
	got := item.GetRetrievalEndpoint()
	if got == "" {
		t.Fatal("retrieval_endpoint missing from the single batch item")
	}
	if !strings.Contains(got, "/articles/hello") {
		t.Errorf("retrieval_endpoint = %q, want the signed URL for the seeded resource", got)
	}
	if !strings.Contains(got, "sig=") {
		t.Errorf("retrieval_endpoint = %q, want an Ed25519 sig query param", got)
	}
	if item.GetExpiresAt() == nil {
		t.Error("expires_at not set alongside retrieval_endpoint")
	}
}

// TestExecuteTransaction_BindsAgentIdentity pins the delivery-URL identity
// binding (ADR-013) on the items[] path: a successful transaction echoes the
// RFC 7638 thumbprint of the proven caller key on the SHARED top-level
// agent_identity_hash (base64url-no-pad, set once per batch), and embeds the
// SAME value as the per-item signed URL's agent_id query param. Both flow from
// agentBindingFor's single encode, so this equality is guaranteed at the source
// (ADR-013 D4).
func TestExecuteTransaction_BindsAgentIdentity(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	resp, err := executeSingleItem(t, h, "tx-bind", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	msg := resp.Msg

	want, err := helpers.Thumbprint(h.callerPub)
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

	signedURL := itemSignedURL(t, resp)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse retrieval_endpoint: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != want {
		t.Errorf("URL agent_id = %q, want %q (must equal agent_identity_hash)", got, want)
	}
}

// NOTE: the superseded multisig-EXECUTE tests TestExecuteTransaction_MultisigBindsToAgent
// and TestExecuteTransaction_MultisigRejectsBrokerWithoutAllowRelay were retired
// in the v1.1 merge.
// Their orthogonal behavior (delivery URL binds to the AGENT key, not the broker;
// broker relay refused when allow_broker_relay=false) is covered against OUR
// re-package execute model by TestExecuteRelayR4_BrokerRelayBindsAgentNotBroker
// and TestExecuteRelayR4_BrokerRelayDeniedWhenDisabled in
// execute_relay_r4_integration_test.go.

// ---- helpers --------------------------------------------------------------

func seedCatalog(t *testing.T, h *testHarness) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain,
			Path:   "/articles/hello",
			// Pricing is derived from the selected term: an entry needs
			// at least one eligible priced term to yield an offer. This unrestricted
			// PER_UNIT term projects for any requester.
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
}

// seedPricedTerm is the minimal unrestricted, priced LicenseTerm the
// catalog-seeding helpers attach so an offer is produced under term-derived
// pricing. It carries no restrictions, so it projects for every
// requester, and a concrete PER_UNIT price the billing path can charge.
func seedPricedTerm() *rampv1.LicenseTerm { return seedPricedTermEst(0) }

// seedPricedTermEst is seedPricedTerm with an estimated_quantity on the term's
// Pricing (the source the reporting-tolerance check reads now that pricing is
// term-derived). est <= 0 omits the field.
func seedPricedTermEst(est int32) *rampv1.LicenseTerm {
	unit := "accesses"
	p := &rampv1.Pricing{
		Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
		Rate:     "0.05",
		Currency: "USD",
		Unit:     &unit,
	}
	if est > 0 {
		p.EstimatedQuantity = &est
	}
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   p,
	}
}

// seedFreeTerm is the unrestricted FREE LicenseTerm the free-resource-path suite
// ingests through the public PushResources surface. PRICING_MODEL_FREE with no
// rate (an absent rate reads as zero, satisfying the proto's pricing.free.zero_rate
// rule) projects pricing.UnitCost == 0, which drives ExecuteTransaction's billing
// bypass (ADR-009 D2). FREE requires no unit (only PER_UNIT does). It carries no
// restrictions, so it projects for every requester.
func seedFreeTerm() *rampv1.LicenseTerm {
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_FREE,
			Currency: "USD",
		},
	}
}

// seedZeroRatePerUnitTerm is a PER_UNIT term priced at rate 0.00 — a non-FREE
// model that still projects pricing.UnitCost == 0, so it exercises the price-zero
// billing bypass (ADR-009 D2) through a model other than FREE. It pins that the
// bypass keys off unit_cost, not the pricing model. PER_UNIT requires a unit
// (proto pricing.per_unit.requires_unit); rate "0.00" is valid (no positive-rate
// rule) and parses to zero. Unrestricted, so it projects for every requester.
func seedZeroRatePerUnitTerm() *rampv1.LicenseTerm {
	unit := "accesses"
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
			Rate:     "0.00",
			Currency: "USD",
			Unit:     &unit,
		},
	}
}

// discoverPath discovers the offers for a single URI under the harness tenant.
// Generalized from discoverFirst so the free-resource-path suite can discover a
// seeded path other than the default /articles/hello.
func discoverPath(t *testing.T, h *testHarness, path string) []*rampv1.Offer {
	t.Helper()
	uri := "https://" + h.tenantDomain + path
	resp, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0",
		// v1.1's generalized uri (discoverFirst delegates here with a path), but
		// WITHOUT v1.1's Id: ResourceQuery.Id was removed in the WBA-split proto.
		Uris: []string{uri},
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover %s: %v", uri, err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatalf("no offers returned for %s", uri)
	}
	return resp.Msg.GetOffers()
}

func discoverFirst(t *testing.T, h *testHarness) []*rampv1.Offer {
	t.Helper()
	return discoverPath(t, h, "/articles/hello")
}
