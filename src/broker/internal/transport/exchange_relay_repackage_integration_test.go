//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// -----------------------------------------------------------------------------
// re-package model — RED regression test.
//
// The triage resolved the open-proxy join condition to OPTION (a): the agent transport-signs
// sig1 over the BROKER relay route URL (NOT the Exchange execute URL), the broker
// verifies that sig1 as an open-proxy guard, RESOLVES the Exchange endpoint from
// the SIGNED Offer.exchange host's /.well-known/ramp.json (registry = trust
// allowlist only), then RE-PACKAGES a fresh broker->Exchange ExecuteTransaction
// — assigning the parsed Offer/Requester/AgentAcceptance sub-messages wholesale +
// IdempotencyKey/Ver/OfferId — and signs it with the BROKER key ALONE, so the
// Exchange receives EXACTLY ONE transport signature (the broker's), not the old
// agent-sig1 + broker-sig2 chain.
//
// This test FAILS against the current verbatim-relay handler because:
//   - the handler reconstructs the EXCHANGE @target-uri to verify sig1, so a
//     request whose sig1 is signed over the BROKER ROUTE URL is REJECTED_AUTHZ
//     (401) — never reaching the upstream;
//   - even if it did relay, it forwards the agent's sig1 verbatim and appends
//     sig2, so the upstream would see TWO transport signatures, not one;
//   - it routes from the registry endpoint column, not from the offer.exchange
//     well-known manifest.

// startEndpointManifestProvider serves /.well-known/ramp.json with a TOP-LEVEL
// "endpoint" field (the shape resolvers.WellKnownEndpointResolver reads — see SDK
// endpointresolver.go wellKnownDoc.Endpoint). The existing startProviderFixture
// emits exchanges[].endpoint, which the endpoint resolver does NOT read; the
// re-package router needs the manifest's own endpoint. Test-only helper added for
// the re-package contract.
func startEndpointManifestProvider(tb testing.TB, exchangeEndpoint string) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoint":"`+exchangeEndpoint+`"}`)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// signedSig1OverBrokerRoute signs sig1 over the BROKER relay route URL (the
// actual POST target) using the SDK signer — the option-(a) contract. It is the
// re-package successor to signedRelayRequestForEndpoint, which signs over the
// EXCHANGE execute URL. Test-only helper.
func signedSig1OverBrokerRoute(
	t *testing.T, brokerURL, agentKID string, agentPriv ed25519.PrivateKey, body []byte,
) *http.Request {
	t.Helper()
	return signedSig1OverBrokerRouteAt(t, brokerURL, agentKID, agentPriv, body, clock.System{}.Now().Unix())
}

// signedSig1OverBrokerRouteAt is signedSig1OverBrokerRoute with an EXPLICIT sig1
// `created` timestamp. A distinct `created` yields a distinct signature value, so
// two requests over the SAME body get DISTINCT signatures — the way a legitimate
// application-level replay (same idempotency_key, re-signed transport) clears the
// broker's per-signature anti-replay guard, which dedups on the signature itself.
func signedSig1OverBrokerRouteAt(
	t *testing.T, brokerURL, agentKID string, agentPriv ed25519.PrivateKey, body []byte, created int64,
) *http.Request {
	t.Helper()
	routeURL := brokerURL + "/broker/v1/exchange/execute"
	req, err := http.NewRequest(http.MethodPost, routeURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create relay request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	signer, err := helpers.NewEd25519Signer(agentKID, agentPriv)
	if err != nil {
		t.Fatalf("new agent signer: %v", err)
	}
	opts := helpers.SignOptions{Created: created, Expires: created + 300}
	if err := helpers.SignRequest(req.Context(), req, body, signer, opts); err != nil {
		t.Fatalf("agent sign over broker route: %v", err)
	}
	return req
}

// TestExchangeRelay_RePackagesFromWellKnownEndpoint pins the re-package
// model end-to-end through the REAL broker route POST /broker/v1/exchange/execute,
// asserting back through the broker's HTTP response and the captured UPSTREAM
// request (the body + transport signatures the Exchange actually received).
//
// Round-trip legs (named honestly):
//   - agent -> broker route (real HTTP): sig1 signed over the BROKER ROUTE URL.
//   - broker -> Exchange (real HTTP): the broker resolves offer.exchange via the
//     provider's /.well-known/ramp.json (real fetch), re-packages, broker-signs.
//   - assertions read the broker's HTTP response + the captured upstream headers
//     and body (a protocol round-trip, not a persistence peek).
func TestExchangeRelay_RePackagesFromWellKnownEndpoint(t *testing.T) {
	ctx := context.Background()

	// Agent + broker + Exchange (offer-issuer) keys.
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentKID := "agent.repackage.example"
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate broker key: %v", err)
	}
	brokerKID := rwtestutil.MustThumbprint(t, brokerPub)
	exchangePub, exchangePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate exchange key: %v", err)
	}

	// Upstream Exchange (captures the transport signatures + body it receives).
	mockExch, captured, exchangeURL := startCapturingExchange(t)

	// The Exchange advertises its OWN endpoint via /.well-known/ramp.json. The
	// offer.exchange canonical domain is this provider's host:port, so the broker's
	// well-known resolver fetches http://<host:port>/.well-known/ramp.json with no
	// host rewrite (Scheme="http" in the docker/test profile).
	provider := startEndpointManifestProvider(t, exchangeURL)
	exchangeDom := strings.TrimPrefix(provider.URL, "http://") // host:port

	// Registry is a TRUST ALLOWLIST only: it must contain the resolved endpoint so
	// the post-resolve SSRF gate passes, seeded via the production repo surface.
	exchangeRepo := seedRelayRegistry(t, ctx, exchangeDom, exchangeURL)

	// Broker outbound signing transport: with NO incoming Signature header on the
	// freshly re-packaged request, it stamps a SINGLE broker sig1.
	relayKey := &xclient.RelayKey{KeyID: brokerKID, Private: brokerPriv}
	signingRT, err := xclient.NewSigningTransport(nil, relayKey, "broker.test.example", 30*time.Second, clock.System{})
	if err != nil {
		t.Fatalf("new signing transport: %v", err)
	}
	xpool := xclient.NewPool(&http.Client{Transport: signingRT})

	// Boundary verifier knows the agent key (sig1 open-proxy guard, option (a)).
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{agentKID: agentPub})
	// Endpoint resolver fetches the offer.exchange host's well-known over http.
	// Inject the unguarded http.DefaultClient: the exchange is a loopback httptest
	// server the production SSRF guard would correctly refuse (prod injects
	// NewGuardedClientFromEnv and resolves a real https/opted-out host).
	endpoints := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})
	replayStore := replay.NewMemoryStore(nil)
	relay := transport.NewExchangeRelayHandler(xpool, resolver, endpoints, exchangeRepo, clock.System{}, replayStore)

	brokerMux := http.NewServeMux()
	brokerMux.Handle("POST /broker/v1/exchange/execute", relay)
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	brokerServer := httptest.NewServer(transport.WrapPublicSurface(logger, brokerMux, runhttp.PublicSurfaceOptions{}))
	t.Cleanup(brokerServer.Close)

	// Build a SIGNED Offer whose exchange == the provider's canonical domain. The
	// offer signature (issued by the Exchange) covers the ENTIRE Offer incl.
	// Offer.exchange, so re-package fidelity is verifiable: a broker that drops or
	// re-defaults any Offer field breaks this signature.
	unitCost := mustMoney(0.10)
	canonicalURL := "https://acme.example/article-42"
	offer := &rampv1.Offer{
		OfferId:        "offer-repack-1",
		Exchange:       exchangeDom,
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		Pricing: &rampv1.Pricing{
			Rate:     unitCost,
			Currency: "USD",
			UnitCost: &unitCost,
			Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
			Unit:     stringPtr("accesses"),
		},
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl:       &canonicalURL,
			ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
		},
	}
	offerSig, err := helpers.SignOffer(exchangePriv, offer)
	if err != nil {
		t.Fatalf("sign offer: %v", err)
	}
	offer.Signature = offerSig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm

	requester := &rampv1.Requester{
		Id:     agentKID,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	const idemKey = "tx-repackage-1"
	// Always-batch (the items-only collapse): the agent sends a 1-item items[] body, never a
	// top-level offer. The sole item carries the signed Offer + a per-item
	// acceptance over the shared requester + idempotency_key, exactly as the agent
	// (MCP) emits. Re-package fidelity is asserted on the item's offer below.
	acceptanceSig, err := helpers.SignOfferAcceptance(agentPriv, offer, requester, idemKey)
	if err != nil {
		t.Fatalf("sign offer acceptance: %v", err)
	}
	txReq := &rampv1.TransactionRequest{
		Ver:            "0.3",
		IdempotencyKey: idemKey,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{{
			Offer: offer,
			AgentAcceptance: &rampv1.AgentAcceptance{
				Signature:          acceptanceSig,
				SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
			},
		}},
	}
	body, err := protojson.Marshal(txReq)
	if err != nil {
		t.Fatalf("marshal TransactionRequest: %v", err)
	}

	// Agent transport-signs sig1 over the BROKER ROUTE URL (option (a)).
	req := signedSig1OverBrokerRoute(t, brokerServer.URL, agentKID, agentPriv, body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// (1) The broker must verify sig1 over the BROKER ROUTE URL and relay -> 200.
	// Today verifyAgentSignature reconstructs the EXCHANGE @target-uri, so this
	// sig1 fails to verify and the broker returns 401 — the primary red.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-package relay: status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}
	if mockExch.executeCalls != 1 {
		t.Fatalf("Exchange.ExecuteTransaction called %d times, want 1", mockExch.executeCalls)
	}

	// (2) Routing derived from offer.exchange well-known manifest, not the registry
	// endpoint column. (Implicit: the upstream that fired is the one the manifest
	// advertised; mockExch is reached only via the resolved endpoint.)

	// (3) The upstream must carry EXACTLY ONE transport signature (the broker's),
	// not the agent-sig1 + broker-sig2 chain.
	capturedSigInput, capturedSig, capturedBody := captured.get()
	if capturedSigInput == "" || capturedSig == "" {
		t.Fatal("Exchange did not receive Signature-Input/Signature headers")
	}
	keyIDs := keyIDsFromSignatureInput(capturedSigInput)
	if len(keyIDs) != 1 {
		t.Fatalf("upstream transport signatures = %d (%v), want exactly 1 (broker only)", len(keyIDs), keyIDs)
	}
	if keyIDs[0] != brokerKID {
		t.Errorf("sole upstream signature keyid = %q, want broker %q", keyIDs[0], brokerKID)
	}

	// (4) Re-package fidelity: the upstream-received TransactionRequest preserves
	// the agent's Offer (incl. signature), Requester, and IdempotencyKey unchanged
	// — and the offer STILL verifies under the issuing Exchange key (proving no
	// field was dropped/re-defaulted during re-package). The broker re-packages via
	// the typed Connect client, so the upstream wire body is protobuf BINARY (not
	// the agent's JSON) — re-package re-marshals by design; the SIGNED sub-messages
	// are what must survive, which proto.Unmarshal + VerifyOffer below check. Under
	// always-batch (the items-only collapse) the offer rides on the sole items[] entry of the
	// fanned-out sub-request, not a top-level offer.
	var upstream rampv1.TransactionRequest
	if err := proto.Unmarshal(capturedBody, &upstream); err != nil {
		t.Fatalf("parse upstream TransactionRequest: %v", err)
	}
	if got := upstream.GetIdempotencyKey(); got != idemKey {
		t.Errorf("upstream IdempotencyKey = %q, want %q", got, idemKey)
	}
	if got := upstream.GetRequester().GetId(); got != agentKID {
		t.Errorf("upstream Requester.Id = %q, want agent %q", got, agentKID)
	}
	if len(upstream.GetItems()) != 1 {
		t.Fatalf("upstream items = %d, want 1 (1-item fan-out)", len(upstream.GetItems()))
	}
	upstreamOffer := upstream.GetItems()[0].GetOffer()
	if got := upstreamOffer.GetSignature(); got != offerSig {
		t.Errorf("upstream Offer.signature = %q, want agent's %q (re-package altered the offer)", got, offerSig)
	}
	if err := helpers.VerifyOffer(upstreamOffer, upstreamOffer.GetSignature(), exchangePub); err != nil {
		t.Errorf("re-packaged offer no longer verifies under the issuing Exchange key: %v", err)
	}

	// Success response carries the signed URL the Exchange returned, on the sole
	// merged item (always-batch merges per-item results).
	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(respBody, &txResp); err != nil {
		t.Fatalf("parse TransactionResponse: %v", err)
	}
	if len(txResp.GetItems()) != 1 {
		t.Fatalf("merged items = %d, want 1", len(txResp.GetItems()))
	}
	if txResp.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Error("merged item missing retrieval_endpoint (signed URL)")
	}
}
