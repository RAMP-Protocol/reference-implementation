//go:build integration

package transport_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // CloudFront canned policies use RSA-SHA1; required to verify.
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// TestPublisherOnboarding_HappyPath walks the onboarding happy path
// end-to-end, exercising the RAMP-native bootstrap with no admin-plane
// assistance:
//
//  1. Real Postgres via testcontainers-go, migrations applied.
//  2. Exchange wired by startExchangeServer (shared with the other e2e
//     tests) with FreeAdapter; a second tenant configured for
//     AWS_CLOUDFRONT_RSA so ExecuteTransaction mints CloudFront canned-
//     policy URLs against the RSA key the fixture holds (RAMP v1 no longer
//     serves it at a well-known route; CloudFront verifies natively).
//  3. Publisher origin (agentCombinedOrigin) serves both ramp.json and
//     ramp.json: ramp.json lists the Exchange as authorized
//     exchange and the publisher itself as the sole
//     catalog_contributor; ramp.json carries the publisher's
//     Ed25519 pubkey.
//  4. Publisher calls PushResources for three URIs under its own domain,
//     RFC 9421-signed with its private key. CatalogHandler's lazy
//     self-signup path (§5.3) fetches the agent manifest and registers
//     the key before admitting the entries.
//  5. A separate agent generates its own Ed25519 keys, publishes a
//     ramp.json, and uses POST /exchange/v1/agents/register
//     (non-admin per §5.3) to land its pubkey in ramp.agents.
//  6. Agent calls DiscoverResources for the three URIs — three signed
//     offers come back.
//  7. Agent verifies each offer's Ed25519 signature against the offer key in
//     the Exchange's Web Bot Auth directory.
//  8. Agent calls ExecuteTransaction; the returned retrieval_endpoint is a
//     CloudFront canned-policy URL whose RSA-SHA1 signature verifies
//     against the RSA key the fixture holds.
//  9. Agent calls ReportUsage, response Accepted == true.
//  10. The agent harness's admin-guard RoundTripper asserts zero
//     /admin/* paths were ever requested against the Exchange server.
func TestPublisherOnboarding_HappyPath(t *testing.T) {
	h := newAgentHarness(t)

	// A dedicated CloudFront-scheme publisher tenant. pushHarness seeds an
	// ED25519-scheme tenant already; this one takes the AWS_CLOUDFRONT_RSA
	// code path when ExecuteTransaction mints a URL.
	const publisherDomain = "cf-publisher.example"
	publisherTenantID := "t_" + uuid.NewString()
	insertCloudFrontTenant(t, h.pushHarness, publisherTenantID, publisherDomain)

	// Publisher's combined origin: ramp.json lists itself as sole
	// contributor and the Exchange as exchange; ramp.json carries
	// its Ed25519 pubkey for lazy signup on first PushResources contact.
	pubPub, pubPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("publisher keypair: %v", err)
	}
	pubOrigin := newAgentCombinedOrigin(t,
		publisherDomain, []string{publisherDomain}, publisherDomain, pubPub)
	h.registerHost(publisherDomain, pubOrigin.server.URL)

	// Step 4: signed push. Lazy self-signup runs implicitly; accepted = 3.
	// Each entry carries a priced term (pricing is term-derived, and an
	// entry needs an eligible priced term to yield an offer). The term's
	// Pricing.estimated_quantity is set so the zero-estimate strict-reject branch
	// of the validator (implementation plan Q2) does not fire when the e2e flow
	// later reports ConsumedQuantity = 1.
	entries := []*rampv1.ResourceEntry{
		{Domain: publisherDomain, Path: "/articles/one", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: publisherDomain, Path: "/articles/two", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: publisherDomain, Path: "/articles/three", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
	}
	pushResp, err := h.signedCat(publisherDomain, pubPriv).PushResources(h.ctx,
		connect.NewRequest(&rampv1.PushResourcesRequest{
			TenantId: publisherTenantID, CallerId: publisherDomain, Entries: entries,
		}))
	if err != nil {
		t.Fatalf("PushResources: %v", err)
	}
	if got := pushResp.Msg.GetAccepted(); got != 3 {
		// PushResourcesResponse no longer carries a per-entry Rejections
		// slice (W4 of the proto-rename wave); surface the count split instead.
		t.Fatalf("accepted = %d, want 3 (rejected=%d)",
			got, pushResp.Msg.GetRejected())
	}
	if got := pushResp.Msg.GetRejected(); got != 0 {
		t.Fatalf("rejected = %d, want 0", got)
	}

	// Step 5: fresh agent publishes ramp.json and registers.
	const agentID = "agent.demo.test"
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	h.publishAgentOrigin(t, agentID, agentPub)
	registerAgentViaPublicEndpoint(t, h, agentID)
	// Directory registration does not mint a billing_ref; a paid transaction needs
	// one, so billing-register the agent through the public Register RPC.
	h.registerForBilling(t, agentID, agentPub, agentPriv)

	// Step 6: DiscoverResources for the three URIs.
	uris := make([]string, len(entries))
	for i, e := range entries {
		uris[i] = "https://" + e.GetDomain() + e.GetPath()
	}
	discResp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Uris: uris,
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	offers := discResp.Msg.GetOffers()
	if len(offers) != 3 {
		t.Fatalf("offers len = %d, want 3", len(offers))
	}

	// Step 7: each offer's signature verifies against JWKS.
	jwksPub := fetchExchangeOfferKey(t, h.pushHarness)
	for i, offer := range offers {
		if offer.GetSignatureAlgorithm() != "EdDSA" {
			t.Fatalf("offer[%d] alg = %q, want EdDSA", i, offer.GetSignatureAlgorithm())
		}
		if err := helpers.VerifyOffer(offer, offer.GetSignature(), jwksPub); err != nil {
			t.Fatalf("offer[%d] signature verify: %v", i, err)
		}
	}

	// Step 8: execute first offer → CloudFront signed URL.
	// Items-only contract (C4 collapse) with body AgentAcceptance binding
	// The agent key was learned via the well-known manifest fetch
	// during onboarding/self-signup, so no manual resolver seeding or multisig
	// transport client is needed here.
	first := offers[0]
	execTxID := "tx-" + uuid.NewString()
	execReqr := &rampv1.Requester{Id: agentID, Domain: agentID, Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT}
	execResp, err := h.exchange.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", IdempotencyKey: execTxID,
		Requester: execReqr,
		// R4: body acceptance signed by the registered agent key.
		Items: []*rampv1.TransactionItem{
			{Offer: first, AgentAcceptance: signAcceptanceFor(t, agentPriv, first, execReqr, execTxID)},
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction: %v", err)
	}
	item := singleResultItem(t, execResp)
	signedURL := item.GetRetrievalEndpoint()
	if signedURL == "" {
		t.Fatal("retrieval_endpoint missing from the single batch item")
	}
	rsaPub := exchangeCloudFrontKey(h.pushHarness)
	if err := verifyCloudFrontCannedPolicy(signedURL, rsaPub); err != nil {
		t.Fatalf("cloudfront signed url verify: %v", err)
	}

	// Step 9: report usage → accepted=true.
	repResp, err := h.exchange.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-" + uuid.NewString(),
		TransactionId: item.GetTransactionId(),
		BillingId:     item.GetBillingId(),
		Usage:         &rampv1.Usage{ConsumedQuantity: 1, Function: []string{"ai_input"}},
	}))
	if err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if repResp.Msg.GetReportId() == "" {
		t.Fatalf("accepted report missing report_id")
	}

	// Step 10 is provided automatically by the agentHarness's admin-guard
	// transport: any /admin/* request would have failed the test via
	// t.Errorf inside the RoundTripper.
}

// --------------------------------------------------------------------
// Helpers specific to publisher onboarding. Everything else comes from
// pushHarness + agentHarness in the sibling e2e tests.
// --------------------------------------------------------------------

// insertCloudFrontTenant seeds a tenant configured for AWS_CLOUDFRONT_RSA
// URL signing. The RsaKeyRef and CloudFrontKeyPairID match the kid
// startExchangeServer registers in deps.keystore, so mintSignedURL resolves
// the same RSA key the fixture exposes as rsaPub for the verification step.
func insertCloudFrontTenant(t *testing.T, h *pushHarness, tenantID, domain string) {
	t.Helper()
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:            tenantID,
		Domain:              domain,
		HmacSecretRef:       "unused",
		Ed25519KeyRef:       "secret://ed25519/" + tenantID,
		ReportingPolicy:     []byte(`{}`),
		SigningScheme:       sqlc.RampSigningSchemeAWSCLOUDFRONTRSA,
		RsaKeyRef:           pgtype.Text{String: "cf-test", Valid: true},
		CloudfrontKeyPairID: pgtype.Text{String: "cf-test", Valid: true},
	}); err != nil {
		t.Fatalf("insert cloudfront tenant: %v", err)
	}
	// The push harness's discover signer is registered as a BROKER (see
	// newPushHarness); the per-test publisher tenant must opt in to broker
	// relay so onboarding ExecuteTransaction calls pass the new
	// caller-identity authorization gate.
	if err := h.queries.SetTenantAllowBrokerRelay(h.ctx, sqlc.SetTenantAllowBrokerRelayParams{
		TenantID:         tenantID,
		AllowBrokerRelay: true,
	}); err != nil {
		t.Fatalf("enable cloudfront tenant broker relay: %v", err)
	}
}

// registerAgentViaPublicEndpoint POSTs /exchange/v1/agents/register
// using the harness's admin-guarded base transport, matching the sibling
// self-signup test's approach.
func registerAgentViaPublicEndpoint(t *testing.T, h *agentHarness, agentID string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"agent_id": agentID, "discovery_url": agentID,
	})
	if err != nil {
		t.Fatalf("marshal register body: %v", err)
	}
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost,
		h.server.URL+"/exchange/v1/agents/register",
		strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build register request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: h.baseRT}).Do(req)
	if err != nil {
		t.Fatalf("register do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
}

// fetchExchangeOfferKey reads the Exchange's Ed25519 offer-signing key from its
// Web Bot Auth directory, where it is named by RFC 7638 thumbprint rather than by
// a kid. There is no separate jwks.json, and the ramp.json overlay carries no keys.
func fetchExchangeOfferKey(t *testing.T, h *pushHarness) ed25519.PublicKey {
	t.Helper()
	// After the WBA split the offer key lives in the exchange's pure WBA directory
	// (keyed by RFC 7638 thumbprint), not in the keyless ramp.json overlay.
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.server.URL+rampwellknown.WBAPath, nil)
	if err != nil {
		t.Fatalf("build WBA directory request: %v", err)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET WBA directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("WBA directory status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read WBA directory: %v", err)
	}
	f, err := rampwellknown.ParseWBA(body)
	if err != nil {
		t.Fatalf("parse WBA directory: %v", err)
	}
	pub, err := resolvers.ActiveEd25519Key(f, time.Now())
	if err != nil {
		t.Fatalf("active offer key absent from WBA directory: %v", err)
	}
	return pub
}

// exchangeCloudFrontKey returns the RSA CloudFront verify key the fixture
// minted. RAMP v1 drops the cdn-keys.json route (CloudFront verifies natively
// against a trusted key group), so the test reads the key from the harness.
func exchangeCloudFrontKey(h *pushHarness) *rsa.PublicKey {
	return h.rsaPub
}

// verifyCloudFrontCannedPolicy runs the RSA-SHA1 signature check
// CloudFront performs over the canonical canned-policy JSON. Mirror of
// tests/e2e/aws-edge/server.mjs so the Go test verifier and the edge
// runtime agree on the canonical bytes.
func verifyCloudFrontCannedPolicy(rawURL string, pub *rsa.PublicKey) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	expires := q.Get("Expires")
	kid := q.Get("Key-Pair-Id")
	sigEnc := q.Get("Signature")
	if expires == "" || kid == "" || sigEnc == "" {
		return fmt.Errorf("missing CloudFront params Expires/Signature/Key-Pair-Id")
	}
	if _, err := strconv.ParseInt(expires, 10, 64); err != nil {
		return fmt.Errorf("parse Expires: %w", err)
	}
	q.Del("Expires")
	q.Del("Signature")
	q.Del("Key-Pair-Id")
	u.RawQuery = q.Encode()
	resource := u.String()
	policy := fmt.Sprintf(
		`{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%s}}}]}`,
		resource, expires,
	)
	sig, err := cfBase64Decode(sigEnc)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	hashed := sha1.Sum([]byte(policy)) //nolint:gosec // CloudFront signature uses SHA1 by protocol.
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], sig); err != nil {
		return fmt.Errorf("signature mismatch over canonical policy=%q: %w", policy, err)
	}
	return nil
}

// cfBase64Decode reverses the CloudFront base64 alphabet (+ -> -, / -> ~,
// = -> _) into standard base64 then decodes.
func cfBase64Decode(s string) ([]byte, error) {
	std := strings.NewReplacer("-", "+", "~", "/", "_", "=").Replace(s)
	return base64.StdEncoding.DecodeString(std)
}
