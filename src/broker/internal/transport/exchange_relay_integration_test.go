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
	"sync"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// capturedHeaders records the RFC 9421 headers the Exchange sees, so the relay
// test can assert the broker forwarded sig1 and appended sig2.
type capturedHeaders struct {
	mu        sync.Mutex
	sigInput  string
	sig       string
	body      []byte
	requestID string
}

func (c *capturedHeaders) set(sigInput, sig string, body []byte, requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sigInput, c.sig, c.body, c.requestID = sigInput, sig, body, requestID
}

func (c *capturedHeaders) get() (string, string, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sigInput, c.sig, c.body
}

// getRequestID returns the X-Request-ID the upstream Exchange saw, empty when the
// broker forwarded none.
func (c *capturedHeaders) getRequestID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestID
}

// lockedBuffer is a concurrency-safe io.Writer the test wires as the relay's
// structured-log sink, so it can assert the audit outcome the handler emits.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// keyIDsFromSignatureInput extracts the keyid="..." of each labeled signature in
// a captured Signature-Input header, in label order. The platform exposes no
// public label parser, so the test reads the keyids directly to assert the
// agent (sig1) + broker (sig2) chain the Exchange receives.
func keyIDsFromSignatureInput(sigInput string) []string {
	var out []string
	for _, label := range strings.Split(sigInput, ",") {
		const marker = `keyid="`
		i := strings.Index(label, marker)
		if i < 0 {
			continue
		}
		rest := label[i+len(marker):]
		if j := strings.Index(rest, `"`); j >= 0 {
			out = append(out, rest[:j])
		}
	}
	return out
}

// relayTestEnv wires a broker relay handler in front of a mock Exchange, with a
// real (testcontainers) exchange registry holding the mock Exchange as the only
// allowlisted endpoint. The relay handler self-verifies sig1 (SDK verifier) and
// enforces the SSRF allowlist — mirroring the production wiring where the relay
// route is exempt from the inbound httpsig middleware.
type relayTestEnv struct {
	brokerURL    string
	exchangeURL  string
	exchangeDom  string
	agentKID     string
	brokerKID    string
	agentPriv    ed25519.PrivateKey
	mockExch     *mockExchange
	captured     *capturedHeaders
	logs         *lockedBuffer
	exchangeRepo repo.ExchangeRepo
}

// newRelayTestEnv wires the relay suite onto the mock Exchange stub. Doctrine
// justification (Testing Doctrine pt 6, documented-fallback): the relay tests
// assert BROKER-side mechanics — sig1/sig2 forwarding over byte-identical
// bodies, batch fan-out, merge/back-fill/aggregation, denial repackaging, and
// budget-offercharge arithmetic. The stub's knobs (failExecute, omitOfferIDs,
// denyOfferIDs, per-item costs) force exactly the merge and back-fill branches
// a real Exchange cannot deterministically produce. Real-Exchange contract
// coverage (execute happy path, idempotency replay) lives in tests/e2e/harness/.
func newRelayTestEnv(t *testing.T) relayTestEnv {
	t.Helper()
	return newRelayTestEnvShaped(t, false)
}

// newRelayTestEnvShaped is newRelayTestEnv with an explicit deployment shape:
// trustProxyHeaders wires the forwarded-header rewrite into WrapPublicSurface,
// the proxied topology where a TLS-terminating proxy fronts the Broker (see
// proxy_trust_integration_test.go).
func newRelayTestEnvShaped(t *testing.T, trustProxyHeaders bool) relayTestEnv {
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
	// Re-package routing: offer.exchange is the exchange's fetchable
	// canonical domain (host:port), and the broker resolves it to the endpoint the
	// exchange advertises in its OWN /.well-known/ramp.json (top-level endpoint).
	// The manifest provider's host:port IS the canonical domain, so the
	// resolver fetches it directly with no host rewrite.
	provider := startEndpointManifestProvider(t, exchangeURL)
	exchangeDom := strings.TrimPrefix(provider.URL, "http://")
	exchangeRepo := seedRelayRegistry(t, ctx, exchangeDom, exchangeURL)

	// Broker outbound signing transport. With NO incoming Signature header on the
	// re-packaged request it stamps a SINGLE broker sig1 (re-package model).
	relayKey := &xclient.RelayKey{KeyID: brokerKID, Private: brokerPriv}
	signingRT, err := xclient.NewSigningTransport(nil, relayKey, "broker.test.example", 30*time.Second, clock.System{})
	if err != nil {
		t.Fatalf("new signing transport: %v", err)
	}
	xpool := xclient.NewPool(&http.Client{Transport: signingRT})

	// SDK key resolver knows the agent key so the broker boundary can verify the
	// agent's sig1 over the broker route (open-proxy guard, option a).
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{agentKID: agentPub})
	// Endpoint resolver fetches the exchange's well-known manifest over http (test
	// profile); the canonical domain is the provider's real host:port. Inject the
	// unguarded http.DefaultClient: the exchange is a loopback httptest server the
	// production SSRF guard (NewGuardedClientFromEnv, wiring.go) would correctly
	// refuse — production resolves a real https exchange, or sets SKIP_SSRF/
	// ALLOW_INSECURE for a docker-internal host.
	endpoints := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{Scheme: "http", HTTP: http.DefaultClient})

	// In-memory relay-scoped replay store mirrors production.
	replayStore := replay.NewMemoryStore(nil)
	relay := transport.NewExchangeRelayHandler(xpool, resolver, endpoints, exchangeRepo, clock.System{}, replayStore)
	brokerMux := http.NewServeMux()
	brokerMux.Handle("POST /broker/v1/exchange/execute", relay)

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	// WrapPublicSurface mirrors production wiring (cmd/server): request-id
	// outermost, the forwarded-header rewrite only under the proxied shape.
	brokerServer := httptest.NewServer(transport.WrapPublicSurface(logger, brokerMux,
		runhttp.PublicSurfaceOptions{TrustProxyHeaders: trustProxyHeaders}))
	t.Cleanup(brokerServer.Close)

	return relayTestEnv{
		brokerURL:    brokerServer.URL,
		exchangeURL:  exchangeURL,
		exchangeDom:  exchangeDom,
		agentKID:     agentKID,
		brokerKID:    brokerKID,
		agentPriv:    agentPriv,
		mockExch:     mockExch,
		captured:     captured,
		logs:         logs,
		exchangeRepo: exchangeRepo,
	}
}

// startCapturingExchange stands up the mock Exchange Connect handler behind a
// header/body-capturing wrapper, so the test can assert the broker forwarded
// sig1+sig2 over byte-identical bytes. The capture point is the reason a stub
// is REQUIRED here (pt 6 documented-fallback): the assertion is on the exact
// bytes the broker emitted, an observation a real Exchange cannot expose.
func startCapturingExchange(t *testing.T) (*mockExchange, *capturedHeaders, string) {
	t.Helper()
	mockExch := &mockExchange{signedURL: "https://cdn.example/signed?url=1"}
	captured := &capturedHeaders{}
	exMux := http.NewServeMux()
	path, connectHandler := rampv1connect.NewExchangeServiceHandler(mockExch)
	exMux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		captured.set(r.Header.Get("Signature-Input"), r.Header.Get("Signature"), body,
			r.Header.Get(helpers.RequestIDHeader))
		r.Body = io.NopCloser(bytes.NewReader(body))
		connectHandler.ServeHTTP(w, r)
	}))
	exchServer := httptest.NewServer(exMux)
	t.Cleanup(exchServer.Close)
	return mockExch, captured, exchServer.URL
}

// seedRelayRegistry brings up a real exchange registry (testcontainers Postgres)
// and registers the mock Exchange as the sole allowlisted endpoint via the
// production repository surface (repo.UpsertFromBootstrap) — the SSRF allowlist
// source.
func seedRelayRegistry(t *testing.T, ctx context.Context, domain, exchangeURL string) repo.ExchangeRepo {
	t.Helper()
	pool := acquireTestDB(t, ctx)
	exchangeRepo := repo.NewExchangeRepo(pool)
	if _, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + domain,
		Domain:            domain,
		Endpoint:          exchangeURL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("seed exchange: %v", err)
	}
	return exchangeRepo
}

// txBody returns a marshaled agent TransactionRequest whose sole item routes to
// the env's registered Offer.exchange domain. Execute is always-batch
// (the items-only collapse): a single-offer flow is a 1-item items[] body. The relay
// verifies sig1 + SSRF only (the Exchange is the authoritative acceptance
// verifier), but the item still carries a real per-item acceptance via
// batchBodyFor so the wire shape matches what the agent (MCP) sends.
func (e relayTestEnv) txBody(t *testing.T) []byte {
	t.Helper()
	return e.txBodyForExchange(t, e.exchangeDom)
}

// txBodyForExchange marshals a 1-item items[] TransactionRequest whose sole
// item's Offer.exchange is the given domain, letting a test build distinct
// bodies that route to distinct Exchanges (multi-Exchange proof). It delegates
// to batchBodyFor (the items[] builder + per-item acceptance signer) so all
// single-flow relay tests share the always-batch wire shape; idempotency_key is
// derived from the domain so two requests in one flow do not collide.
func (e relayTestEnv) txBodyForExchange(t *testing.T, exchangeDomain string) []byte {
	t.Helper()
	return e.batchBodyFor(t, "tx-relay-"+exchangeDomain, []batchItem{
		{offerID: "offer-1", exchange: exchangeDomain},
	})
}

// signedRelayRequest builds a POST to the broker relay route carrying the agent's
// sig1 signed @target-uri against the BROKER ROUTE itself (re-package model,
// option a — the agent is topology-decoupled from the Exchange), and NO
// X-RAMP-Exchange-Endpoint header: routing is derived from the body's signed
// offer.exchange. Signing uses the SDK (helpers.SignRequest), the same path the
// agent (MCP) uses.
func (e relayTestEnv) signedRelayRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	return signedSig1OverBrokerRoute(t, e.brokerURL, e.agentKID, e.agentPriv, body)
}

// TestExchangeRelay_RePackageEmitsValidatedAudit verifies the re-package happy
// path emits a VALIDATED audit log and forwards a SINGLE broker transport
// signature (not the old agent-sig1 + broker-sig2 chain). Round-trip:
// agent→broker relay route→Exchange (real HTTP); the assertion reads back through
// the broker's HTTP response, the Exchange's captured headers, and the audit log.
// (Re-package field fidelity + well-known routing are pinned by
// TestExchangeRelay_RePackagesFromWellKnownEndpoint.)
func TestExchangeRelay_RePackageEmitsValidatedAudit(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker relay failed: %d %s", resp.StatusCode, bodyBytes)
	}

	if env.mockExch.executeCalls != 1 {
		t.Errorf("Exchange.ExecuteTransaction called %d times, want 1", env.mockExch.executeCalls)
	}

	capturedSigInput, capturedSig, _ := env.captured.get()
	if capturedSigInput == "" || capturedSig == "" {
		t.Fatal("Exchange did not receive Signature-Input/Signature headers")
	}
	keyIDs := keyIDsFromSignatureInput(capturedSigInput)
	if len(keyIDs) != 1 {
		t.Fatalf("re-package: upstream transport signatures = %d (%v), want exactly 1 (broker only)",
			len(keyIDs), keyIDs)
	}
	if keyIDs[0] != env.brokerKID {
		t.Errorf("sole upstream signature keyid = %q, want broker keyid %q", keyIDs[0], env.brokerKID)
	}

	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(bodyBytes, &txResp); err != nil {
		t.Fatalf("parse TransactionResponse: %v", err)
	}
	// Always-batch (the items-only collapse): a 1-item flow returns ONE merged item carrying
	// the per-item signed URL, not the top-level retrieval_endpoint.
	if len(txResp.GetItems()) != 1 {
		t.Fatalf("merged items = %d, want 1", len(txResp.GetItems()))
	}
	if txResp.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Error("merged item missing retrieval_endpoint (signed URL)")
	}
	if !strings.Contains(env.logs.String(), "VALIDATED") {
		t.Errorf("relay success emitted no VALIDATED audit log; got: %s", env.logs.String())
	}
}

// Per-offer routing to DISTINCT exchanges is now proven by
// TestExchangeRelay_BatchFansOutByOfferExchange (exchange_relay_batch_integration_test.go),
// which sends ONE items[] body whose items span two registered exchanges, asserts
// each exchange received exactly one broker-signed sub-request (fan-out), and
// checks each item's signed URL came from the exchange it routed to. Under the
// always-batch collapse (the items-only collapse) that batch test subsumes the former
// TestExchangeRelay_RoutesByOfferExchangeToDistinctExchanges (two separate
// single-offer sends), which is RETIRED here to avoid asserting the same routing
// behavior twice. assertSingleBrokerSig (kept below) is the shared re-package
// signature assertion both the batch test and RePackageEmitsValidatedAudit use.

// assertMultisigBinds asserts the captured Exchange request carried the exact
// agent-signed bytes and a sig1(agent)+sig2(broker) chain in label order. Used by
// the DISCOVER relay, which still relays verbatim and chains sig2 — the
// execute relay re-packages and is asserted by assertSingleBrokerSig instead.
func assertMultisigBinds(
	t *testing.T, captured *capturedHeaders, wantBody []byte, agentKID, brokerKID string,
) {
	t.Helper()
	sigInput, sig, capturedBody := captured.get()
	if sigInput == "" || sig == "" {
		t.Fatal("Exchange did not receive Signature-Input/Signature headers")
	}
	if !bytes.Equal(capturedBody, wantBody) {
		t.Errorf("Exchange received body differing from agent-signed bytes:\n got=%s\nwant=%s",
			capturedBody, wantBody)
	}
	keyIDs := keyIDsFromSignatureInput(sigInput)
	if len(keyIDs) != 2 {
		t.Fatalf("expected sig1+sig2, got %d: %v", len(keyIDs), keyIDs)
	}
	if keyIDs[0] != agentKID {
		t.Errorf("sig1 keyid = %q, want agent %q", keyIDs[0], agentKID)
	}
	if keyIDs[1] != brokerKID {
		t.Errorf("sig2 keyid = %q, want broker %q", keyIDs[1], brokerKID)
	}
}

// assertSingleBrokerSig asserts the captured Exchange request carried EXACTLY ONE
// transport signature — the broker's (re-package model: the broker re-signs each
// hop; the agent's sig is not forwarded).
func assertSingleBrokerSig(
	t *testing.T, captured *capturedHeaders, brokerKID string,
) {
	t.Helper()
	sigInput, sig, _ := captured.get()
	if sigInput == "" || sig == "" {
		t.Fatal("Exchange did not receive Signature-Input/Signature headers")
	}
	keyIDs := keyIDsFromSignatureInput(sigInput)
	if len(keyIDs) != 1 {
		t.Fatalf("re-package: upstream transport signatures = %d (%v), want exactly 1 (broker only)",
			len(keyIDs), keyIDs)
	}
	if keyIDs[0] != brokerKID {
		t.Errorf("sole upstream signature keyid = %q, want broker %q", keyIDs[0], brokerKID)
	}
}

// TestExchangeRelay_RejectsUnsignedRequest verifies the broker refuses to relay
// (and stamp sig2 onto) a request carrying no agent signature — the open-proxy
// guard.
func TestExchangeRelay_RejectsUnsignedRequest(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)

	req, err := http.NewRequest(http.MethodPost,
		env.brokerURL+"/broker/v1/exchange/execute", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// No routing header: the body carries offer.exchange, so the broker resolves
	// the target and reaches the sig1 check, which fails for an unsigned request.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unsigned relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an unsigned request, want 0", env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_RejectsTamperedSignature verifies a corrupted sig1 is
// rejected at the broker (open-proxy guard).
func TestExchangeRelay_RejectsTamperedSignature(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)
	req := env.signedRelayRequest(t, body)

	// Corrupt the signature value while leaving Signature-Input intact.
	req.Header.Set("Signature",
		"sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("tampered relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for a tampered request, want 0", env.mockExch.executeCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_AUTHZ") {
		t.Errorf("relay rejection emitted no REJECTED_AUTHZ audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsReplayedSignature verifies the per-signature replay guard: the relay route is
// excluded from the httpsig middleware, so a captured valid relay request
// replayed within the sig1 window must be rejected by the handler's own replay
// guard. The first send succeeds (relayed once); the byte-identical second send
// carries the same sig1 (ed25519 is deterministic) and is rejected as a replay,
// never reaching the Exchange a second time.
func TestExchangeRelay_RejectsReplayedSignature(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)

	first := env.signedRelayRequest(t, body)
	signedHeader := first.Header.Clone()

	resp1, err := http.DefaultClient.Do(first)
	if err != nil {
		t.Fatalf("send first request: %v", err)
	}
	respBody, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first relay failed: %d %s", resp1.StatusCode, respBody)
	}

	replayReq, err := http.NewRequest(http.MethodPost,
		env.brokerURL+"/broker/v1/exchange/execute", bytes.NewReader(body))
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
		t.Fatalf("replayed relay: status = %d, want 401; body=%s", resp2.StatusCode, b)
	}
	if env.mockExch.executeCalls != 1 {
		t.Errorf("Exchange called %d times across the replay, want 1 (replay not forwarded)",
			env.mockExch.executeCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_REPLAY") {
		t.Errorf("replay rejection emitted no REJECTED_REPLAY audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsUnregisteredExchangeDomain verifies the R10 routing
// gate: a request whose signed offer.exchange names a domain NOT in the broker's
// registry is rejected (400, REJECTED_ENDPOINT) and never relayed. Signed !=
// trusted-to-route — a rogue Exchange's signed offer must still be refused.
func TestExchangeRelay_RejectsUnregisteredExchangeDomain(t *testing.T) {
	env := newRelayTestEnv(t)
	// Body routes to an unregistered domain; sig1 signed against env.exchangeURL
	// would only matter if routing resolved — it does not, so we reject before
	// reaching the agent-signature check.
	body := env.txBodyForExchange(t, "rogue.exchange.example")
	req := env.signedRelayRequest(t, body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unregistered offer.exchange: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an unregistered offer.exchange, want 0",
			env.mockExch.executeCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_ENDPOINT") {
		t.Errorf("unregistered domain emitted no REJECTED_ENDPOINT audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsUnregisteredExchangeDomain_CarriesFieldMetadata pins
// the TRUST-gate reject at exchange_relay.go (resolveExchangeEndpoint, GetByDomain
// ErrNotFound on the signed offer.exchange DOMAIN): a request whose offer.exchange
// names a domain NOT in the broker's registry is rejected 400 AND its raw-relay
// ErrorDetail body carries metadata["field"]=="offer.exchange" — the offending
// signed field rides as TYPED metadata (the ADR-019 §1 machine-readable axis),
// never string-matched on the message. This is a DISTINCT fault from the SSRF
// gate (an unknown DOMAIN, not an off-allowlist resolved ENDPOINT). Round-trip:
// agent HTTP POST -> execute relay route -> batch fan-out -> resolveExchangeEndpoint
// trust-gate reject -> writeBrokerError (protojson ErrorDetail) read back through
// the SAME public HTTP surface. FAILS on HEAD: the reject is a bare broker.Newf(...)
// with no .WithField tail, so brokerDetail rides no metadata and
// GetMetadata()["field"] is empty.
func TestExchangeRelay_RejectsUnregisteredExchangeDomain_CarriesFieldMetadata(t *testing.T) {
	env := newRelayTestEnv(t)
	// Body routes to an unregistered domain; the trust gate refuses it before any
	// endpoint resolution, so the reject carries the offending offer.exchange axis.
	body := env.txBodyForExchange(t, "rogue.exchange.example")
	req := env.signedRelayRequest(t, body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
	assertRelayErrorField(t, detail, "field", "offer.exchange")

	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an unregistered offer.exchange, want 0",
			env.mockExch.executeCalls)
	}
}

// The missing-routing-target negative path is now covered by the two
// distinguishing 400 tests in exchange_relay_emptyitems_integration_test.go,
// which the items-only collapse requires:
// TestExchangeRelay_RejectsEmptyItems pins the empty-items[]
// guard ("items[] required (min 1)") and TestExchangeRelay_RejectsItemMissingExchange
// pins the per-item guard ("item N: offer.exchange required"). Each asserts its
// DISTINCT broker-error message, so neither 400 guard can be deleted while the
// suite stays green. The former TestExchangeRelay_RejectsMissingRoutingTarget
// (empty offer.exchange, status-only 400) is RETIRED here — under the always-batch
// path an empty offer.exchange now manifests as the per-item guard, and a
// status-only assertion could not distinguish which of the two 400 guards fired.

// TestExchangeRelay_BoundsOversizedBody verifies the relay caps the body it
// buffers (maxAgentBodyBytes). The route is pre-auth, so an unbounded read would
// let an unauthenticated caller exhaust broker memory. A signed-but-oversized
// items[] request is truncated on read, so the read stops short of the signed
// digest and the request is never relayed — proving the read was bounded (an
// unbounded read would have matched the digest and relayed). The body is the
// always-batch items[] shape (the items-only collapse); the truncation breaks the JSON so
// the failure manifests before any guard, but the proven property is the bounded
// read, not which downstream check rejects the corrupted bytes.
func TestExchangeRelay_BoundsOversizedBody(t *testing.T) {
	env := newRelayTestEnv(t)

	requester := &rampv1.Requester{
		Id:     env.agentKID,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		Name:   stringPtr("https://pub.example/" + strings.Repeat("a", 80*1024)),
	}
	txReq := &rampv1.TransactionRequest{
		Ver:            "0.3",
		IdempotencyKey: "tx-oversized",
		Requester:      requester,
		Items: []*rampv1.TransactionItem{{
			Offer: &rampv1.Offer{OfferId: "offer-1", Exchange: env.exchangeDom},
		}},
	}
	body, err := protojson.Marshal(txReq)
	if err != nil {
		t.Fatalf("marshal oversized TransactionRequest: %v", err)
	}
	if len(body) <= 64*1024 {
		t.Fatalf("test body is not oversized: %d bytes", len(body))
	}

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversized body accepted (status 200) — read was not bounded; body=%s", b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an oversized body, want 0", env.mockExch.executeCalls)
	}
}

// TestExchangeRepo_NormalizesEndpointOnStore pins the endpoint-normalization fix at its source of
// truth: an Exchange configured with a trailing slash is stored canonicalized, so
// discovery emits a single form and the agent never signs a double-slash
// @target-uri that the relay's sig1 verification (and the Exchange route) could
// not match. Without normalization the SSRF allowlist would admit the request but
// sig1 verify would fail-closed, silently breaking such Exchanges over the relay.
func TestExchangeRepo_NormalizesEndpointOnStore(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	exchangeRepo := repo.NewExchangeRepo(pool)

	const want = "https://exchange.example:8443"
	stored, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-trailing",
		Domain:            "mp.trailing.example",
		Endpoint:          want + "/", // operator configured a trailing slash
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if stored.Endpoint != want {
		t.Errorf("UpsertFromBootstrap returned endpoint %q, want normalized %q", stored.Endpoint, want)
	}

	list, err := exchangeRepo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var got string
	for _, ex := range list {
		if ex.ID == "mp-trailing" {
			got = ex.Endpoint
		}
	}
	if got != want {
		t.Errorf("List returned endpoint %q, want normalized %q", got, want)
	}
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
