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
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// discoverRelayTestEnv wires a broker DISCOVER relay handler in front of a mock
// Exchange, with a real (testcontainers) exchange registry holding the mock
// Exchange as the only allowlisted endpoint. It reuses the execute-relay test
// fixtures (capturedHeaders, lockedBuffer, seedRelayRegistry, mockExchange,
// keyIDsFromSignatureInput) — only the route, body type, routing input (the
// X-RAMP-Exchange-Endpoint header, primary for discovery), and response shape
// differ.
type discoverRelayTestEnv struct {
	brokerURL   string
	exchangeURL string
	agentKID    string
	brokerKID   string
	agentPriv   ed25519.PrivateKey
	mockExch    *mockExchange
	captured    *capturedHeaders
	logs        *lockedBuffer
	// signatureAgent is written onto the agent's request BEFORE signing, so the
	// signature covers it. Empty leaves the SDK's own binding in place (it sets the
	// header to "" when absent), which is what every relay test that does not care
	// about the directory wants.
	signatureAgent string
}

// newDiscoverRelayTestEnv wires the discover-relay suite onto the mock
// Exchange stub. Doctrine justification (Testing Doctrine pt 6,
// documented-fallback): these tests assert BROKER-side discover-relay
// mechanics — httpsig admission, SSRF allowlisting, replay guarding, audit —
// against a controllable upstream whose responses are fixtures. Real-Exchange
// discovery contract coverage lives in tests/e2e/harness/.
func newDiscoverRelayTestEnv(t *testing.T) discoverRelayTestEnv {
	t.Helper()
	return newDiscoverRelayTestEnvResolvedBy(t, nil)
}

// newDiscoverRelayTestEnvResolvedBy is the single definition of the discover-relay
// environment, with a hook over how the agent's verifying key is resolved.
//
// nil gives the thumbprint-keyed static resolver every other relay test uses. A
// non-nil hook is how a test drives the OTHER resolver shape production runs —
// one that keys on the signed Signature-Agent directory, which is the only way a
// never-seen agent's key can be found at all after the WBA split.
func newDiscoverRelayTestEnvResolvedBy(
	t *testing.T, makeResolver func(agentKID string, agentPub ed25519.PublicKey) helpers.KeyResolver,
) discoverRelayTestEnv {
	t.Helper()
	ctx := context.Background()

	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentKID := "agent.test.example"
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate broker key: %v", err)
	}
	brokerKID := rwtestutil.MustThumbprint(t, brokerPub)

	mockExch, captured, exchangeURL := startCapturingExchange(t)
	exchangeRepo := seedRelayRegistry(t, ctx, "mp.acme.example", exchangeURL)

	relayKey := &xclient.RelayKey{KeyID: brokerKID, Private: brokerPriv}
	signingRT, err := xclient.NewSigningTransport(nil, relayKey, "broker.test.example", 30*time.Second, clock.System{})
	if err != nil {
		t.Fatalf("new signing transport: %v", err)
	}
	xpool := xclient.NewPool(&http.Client{Transport: signingRT})

	var resolver helpers.KeyResolver = helpers.NewStaticKeyResolver(
		map[string]ed25519.PublicKey{agentKID: agentPub})
	if makeResolver != nil {
		resolver = makeResolver(agentKID, agentPub)
	}
	replayStore := replay.NewMemoryStore(nil)
	relay := transport.NewDiscoverRelayHandler(xpool, resolver, exchangeRepo, clock.System{}, replayStore)
	brokerMux := http.NewServeMux()
	brokerMux.Handle("POST /broker/v1/exchange/discover", relay)

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	brokerServer := httptest.NewServer(transport.WrapPublicSurface(logger, brokerMux, runhttp.PublicSurfaceOptions{}))
	t.Cleanup(brokerServer.Close)

	return discoverRelayTestEnv{
		brokerURL:   brokerServer.URL,
		exchangeURL: exchangeURL,
		agentKID:    agentKID,
		brokerKID:   brokerKID,
		agentPriv:   agentPriv,
		mockExch:    mockExch,
		captured:    captured,
		logs:        logs,
	}
}

// queryBody returns a marshaled agent ResourceQuery for a known URL — the body
// the broker relays VERBATIM. The relay verifies sig1 + SSRF only (the Exchange
// is the authoritative discovery responder), so the query needs no full shape.
func (e discoverRelayTestEnv) queryBody(t *testing.T) []byte {
	t.Helper()
	q := &rampv1.ResourceQuery{
		Ver:  "0.3",
		Uris: []string{"https://acme.example/article-42"},
		Requester: &rampv1.Requester{
			Id:     e.agentKID,
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}
	body, err := protojson.Marshal(q)
	if err != nil {
		t.Fatalf("marshal ResourceQuery: %v", err)
	}
	return body
}

// signedDiscoverRequest builds a POST to the broker discover relay carrying the
// agent's sig1, signed @target-uri against the Exchange's DISCOVER URL (the real
// flow, not the broker relay path), and the X-RAMP-Exchange-Endpoint routing
// header naming the agent-chosen Exchange. setEndpointHeader=false omits the
// routing header (to drive the missing-target rejection).
func (e discoverRelayTestEnv) signedDiscoverRequest(t *testing.T, body []byte, setEndpointHeader bool) *http.Request {
	t.Helper()
	discURL := e.exchangeURL + rampv1connect.ExchangeServiceDiscoverResourcesProcedure
	signReq, err := http.NewRequest(http.MethodPost, discURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create sign request: %v", err)
	}
	signReq.Header.Set("Content-Type", "application/json")
	if e.signatureAgent != "" {
		// Set before signing, so the signature covers these exact bytes — the
		// directory a verifier reads has to be the one the agent committed to.
		signReq.Header.Set(agentid.SignatureAgentHeader, e.signatureAgent)
	}
	signer, err := helpers.NewEd25519Signer(e.agentKID, e.agentPriv)
	if err != nil {
		t.Fatalf("new agent signer: %v", err)
	}
	created := clock.System{}.Now().Unix()
	opts := helpers.SignOptions{Created: created, Expires: created + 300}
	if err := helpers.SignRequest(signReq.Context(), signReq, body, signer, opts); err != nil {
		t.Fatalf("agent sign request: %v", err)
	}

	relayReq, err := http.NewRequest(http.MethodPost,
		e.brokerURL+"/broker/v1/exchange/discover", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create relay request: %v", err)
	}
	relayReq.Header = signReq.Header.Clone()
	if setEndpointHeader {
		relayReq.Header.Set("X-RAMP-Exchange-Endpoint", e.exchangeURL)
	}
	return relayReq
}

// TestDiscoverRelay_MultisigBindsToAgent verifies the broker discover relay
// preserves the agent's sig1, appends the broker's sig2, relays the byte-identical
// body, and returns the Exchange's ResourceResponse. Round-trip: agent→broker
// discover relay route→Exchange (real HTTP); assertions read back through the
// broker's HTTP response and the Exchange's captured headers/body.
func TestDiscoverRelay_MultisigBindsToAgent(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)

	resp, err := http.DefaultClient.Do(env.signedDiscoverRequest(t, body, true))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker discover relay failed: %d %s", resp.StatusCode, bodyBytes)
	}

	if env.mockExch.discoverCalls != 1 {
		t.Errorf("Exchange.DiscoverResources called %d times, want 1", env.mockExch.discoverCalls)
	}

	// The Exchange received the agent's sig1 + the broker's sig2 over the exact
	// agent-signed bytes (reuses the execute-relay assertion helper).
	assertMultisigBinds(t, env.captured, body, env.agentKID, env.brokerKID)

	var rResp rampv1.ResourceResponse
	if err := protojson.Unmarshal(bodyBytes, &rResp); err != nil {
		t.Fatalf("parse ResourceResponse: %v", err)
	}
	if len(rResp.GetOffers()) == 0 {
		t.Error("ResourceResponse carried no offers (relay dropped the discovery result)")
	}
	if !strings.Contains(env.logs.String(), "VALIDATED") {
		t.Errorf("relay success emitted no VALIDATED audit log; got: %s", env.logs.String())
	}
}

// TestDiscoverRelay_RejectsUnsignedRequest verifies the broker refuses to relay
// (and stamp sig2 onto) a discovery request carrying no agent signature — the
// open-proxy guard.
func TestDiscoverRelay_RejectsUnsignedRequest(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)

	req, err := http.NewRequest(http.MethodPost,
		env.brokerURL+"/broker/v1/exchange/discover", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RAMP-Exchange-Endpoint", env.exchangeURL)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unsigned discover relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for an unsigned request, want 0", env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_RejectsTamperedSignature verifies a corrupted sig1 is
// rejected at the broker discover relay (open-proxy guard).
func TestDiscoverRelay_RejectsTamperedSignature(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)
	req := env.signedDiscoverRequest(t, body, true)

	req.Header.Set("Signature",
		"sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("tampered discover relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for a tampered request, want 0", env.mockExch.discoverCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_AUTHZ") {
		t.Errorf("relay rejection emitted no REJECTED_AUTHZ audit log; got: %s", env.logs.String())
	}
}

// TestDiscoverRelay_RejectsReplayedSignature verifies the per-signature replay guard for the discover
// route: the route is excluded from the httpsig middleware, so a captured valid
// relay request replayed within the sig1 window is rejected by the handler's own
// relay-scoped replay guard. The first send succeeds; the byte-identical second
// send carries the same (deterministic) sig1 and is rejected, never reaching the
// Exchange a second time.
func TestDiscoverRelay_RejectsReplayedSignature(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)

	first := env.signedDiscoverRequest(t, body, true)
	signedHeader := first.Header.Clone()

	resp1, err := http.DefaultClient.Do(first)
	if err != nil {
		t.Fatalf("send first request: %v", err)
	}
	respBody, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first discover relay failed: %d %s", resp1.StatusCode, respBody)
	}

	replayReq, err := http.NewRequest(http.MethodPost,
		env.brokerURL+"/broker/v1/exchange/discover", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create replay request: %v", err)
	}
	replayReq.Header = signedHeader

	resp2, err := http.DefaultClient.Do(replayReq)
	if err != nil {
		t.Fatalf("send replay request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("replayed discover relay: status = %d, want 401; body=%s", resp2.StatusCode, b)
	}
	if env.mockExch.discoverCalls != 1 {
		t.Errorf("Exchange called %d times across the replay, want 1 (replay not forwarded)",
			env.mockExch.discoverCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_REPLAY") {
		t.Errorf("replay rejection emitted no REJECTED_REPLAY audit log; got: %s", env.logs.String())
	}
}

// TestDiscoverRelay_RejectsMissingRoutingHeader verifies the discover relay
// rejects a request carrying no X-RAMP-Exchange-Endpoint header (400) — a
// discovery query has no signed Offer.exchange, so the header is the only routing
// input and its absence leaves no target to derive.
func TestDiscoverRelay_RejectsMissingRoutingHeader(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)
	req := env.signedDiscoverRequest(t, body, false)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("missing routing header: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for a missing routing header, want 0", env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_MissingRoutingHeader_CarriesFieldMetadata pins
// discover_relay.go:97: a discover relay request with no X-RAMP-Exchange-Endpoint
// header is rejected 400 AND its raw-relay ErrorDetail body carries
// metadata["field"]=="X-RAMP-Exchange-Endpoint" — the missing-required-header
// identity rides as TYPED metadata, never string-matched on the message
// (ADR-019 §1). FAILS on HEAD: writeBrokerError emits {Message,Domain} only
// (broker.Error has no Metadata), so GetMetadata() is empty.
func TestDiscoverRelay_MissingRoutingHeader_CarriesFieldMetadata(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)
	req := env.signedDiscoverRequest(t, body, false)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
	assertRelayErrorField(t, detail, "field", "X-RAMP-Exchange-Endpoint")

	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for a missing routing header, want 0", env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_RejectsUnregisteredExchangeEndpoint verifies the SSRF gate:
// a request whose X-RAMP-Exchange-Endpoint names an endpoint NOT in the broker's
// registry is rejected (400, REJECTED_ENDPOINT) and never relayed — a caller
// cannot steer the broker's signed POST onto an arbitrary target.
func TestDiscoverRelay_RejectsUnregisteredExchangeEndpoint(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)
	req := env.signedDiscoverRequest(t, body, true)
	req.Header.Set("X-RAMP-Exchange-Endpoint", "http://169.254.169.254")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unregistered endpoint: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for an unregistered endpoint, want 0", env.mockExch.discoverCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_ENDPOINT") {
		t.Errorf("unregistered endpoint emitted no REJECTED_ENDPOINT audit log; got: %s", env.logs.String())
	}
}

// TestDiscoverRelay_RejectsUnregisteredExchangeEndpoint_CarriesResolvedEndpointMetadata
// pins the SSRF-gate reject at relay_core.go (relayCore.preflight, endpointAllowed
// == false): a discover relay whose X-RAMP-Exchange-Endpoint names an endpoint NOT
// in the broker's registry is rejected 400 AND its raw-relay ErrorDetail body
// carries metadata["resolved_endpoint"]=="http://169.254.169.254" — the rejected
// resolved target rides as TYPED metadata (the ADR-019 §1 machine-readable axis),
// never string-matched on the message. The header value reaches the SSRF gate
// verbatim (discover_relay.go resolveEndpoint returns it directly, no GetByDomain
// short-circuit; the bare "/" trim leaves the host untouched), so the asserted
// value is the post-trim header. Round-trip: agent HTTP POST -> discover relay
// route -> relayCore.preflight -> endpointAllowed reject -> writeBrokerError
// (protojson ErrorDetail) read back through the SAME public HTTP surface.
// FAILS on HEAD: the reject is a bare broker.Newf(...) with no .WithMeta tail, so
// brokerDetail rides no metadata and GetMetadata()["resolved_endpoint"] is empty.
func TestDiscoverRelay_RejectsUnregisteredExchangeEndpoint_CarriesResolvedEndpointMetadata(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)
	body := env.queryBody(t)
	req := env.signedDiscoverRequest(t, body, true)
	req.Header.Set("X-RAMP-Exchange-Endpoint", "http://169.254.169.254")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
	assertRelayErrorField(t, detail, "resolved_endpoint", "http://169.254.169.254")

	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for an unregistered endpoint, want 0", env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_BoundsOversizedBody verifies the discover relay caps the body
// it buffers (maxAgentBodyBytes). The route is pre-auth, so an unbounded read
// would let an unauthenticated caller exhaust broker memory. A signed-but-
// oversized request is truncated on read, so sig1 verification fails and it is
// never relayed — proving the read was bounded.
func TestDiscoverRelay_BoundsOversizedBody(t *testing.T) {
	env := newDiscoverRelayTestEnv(t)

	q := &rampv1.ResourceQuery{
		Ver:  "0.3",
		Uris: []string{"https://acme.example/" + strings.Repeat("a", 80*1024)},
		Requester: &rampv1.Requester{
			Id:     env.agentKID,
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}
	body, err := protojson.Marshal(q)
	if err != nil {
		t.Fatalf("marshal oversized ResourceQuery: %v", err)
	}
	if len(body) <= 64*1024 {
		t.Fatalf("test body is not oversized: %d bytes", len(body))
	}

	resp, err := http.DefaultClient.Do(env.signedDiscoverRequest(t, body, true))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversized body accepted (status 200) — read was not bounded; body=%s", b)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange was called %d times for an oversized body, want 0", env.mockExch.discoverCalls)
	}
}
