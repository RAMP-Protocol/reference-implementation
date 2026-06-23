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
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// capturedHeaders records the RFC 9421 headers the Exchange sees, so the relay
// test can assert the broker forwarded sig1 and appended sig2.
type capturedHeaders struct {
	mu       sync.Mutex
	sigInput string
	sig      string
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

func (c *capturedHeaders) set(sigInput, sig string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sigInput, c.sig = sigInput, sig
}

func (c *capturedHeaders) get() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sigInput, c.sig
}

// relayTestEnv wires a broker relay handler in front of a mock Exchange, with a
// real (testcontainers) exchange registry holding the mock Exchange as the only
// allowlisted endpoint. The relay handler self-verifies sig1 and enforces the
// SSRF allowlist — mirroring the production wiring where the relay route is
// exempt from the inbound httpsig middleware.
type relayTestEnv struct {
	brokerURL   string
	exchangeURL string
	agentKID    string
	brokerKID   string
	agentPriv   ed25519.PrivateKey
	mockExch    *mockExchange
	captured    *capturedHeaders
	logs        *lockedBuffer
}

func newRelayTestEnv(t *testing.T) relayTestEnv {
	t.Helper()
	ctx := context.Background()

	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentKID := "agent.test.example"
	_, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate broker key: %v", err)
	}
	brokerKID := httpsig.BrokerKeyIDPrefix + "test-broker.001"

	// Mock Exchange with header capture (sig1 + sig2 land here).
	mockExch := &mockExchange{signedURL: "https://cdn.example/signed?url=1"}
	captured := &capturedHeaders{}
	exMux := http.NewServeMux()
	path, connectHandler := rampv1connect.NewExchangeServiceHandler(mockExch)
	exMux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.set(r.Header.Get("Signature-Input"), r.Header.Get("Signature"))
		connectHandler.ServeHTTP(w, r)
	}))
	exchServer := httptest.NewServer(exMux)
	t.Cleanup(exchServer.Close)

	// Real exchange registry seeded with the mock Exchange as the sole
	// allowlisted endpoint (SSRF allowlist source).
	dsn := setupPostgres(t, ctx)
	pool := sharedb.OpenForTest(t, ctx, dsn)
	exchangeRepo := repo.NewExchangeRepo(pool)
	if _, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-acme",
		Domain:            "mp.acme.example",
		Endpoint:          exchServer.URL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("seed exchange: %v", err)
	}

	// Broker outbound signing transport (appends sig2).
	relayKey := &xclient.RelayKey{KID: brokerKID, Private: brokerPriv}
	signingRT := xclient.NewSigningTransport(nil, relayKey, 30*time.Second, clock.System{})
	xpool := xclient.NewPool(&http.Client{Transport: signingRT})

	// Resolver knows the agent key so the broker can verify sig1.
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{agentKID: agentPub})

	// In-memory replay store mirrors production (SEC-01): the relay endpoint is
	// excluded from the httpsig middleware, so it enforces sig1 (keyid,signature)
	// uniqueness itself.
	replay := httpsig.NewMemoryReplayStore(nil)
	relay := transport.NewExchangeRelayHandler(xpool, resolver, exchangeRepo, clock.System{}, replay)
	brokerMux := http.NewServeMux()
	brokerMux.Handle("/broker/v1/exchange/execute", relay)
	// RequestIDMiddleware attaches a request-scoped logger to the context so the
	// relay's structured audit log lands in a buffer the test can assert.
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	brokerServer := httptest.NewServer(transport.RequestIDMiddleware(logger, brokerMux))
	t.Cleanup(brokerServer.Close)

	return relayTestEnv{
		brokerURL:   brokerServer.URL,
		exchangeURL: exchServer.URL,
		agentKID:    agentKID,
		brokerKID:   brokerKID,
		agentPriv:   agentPriv,
		mockExch:    mockExch,
		captured:    captured,
		logs:        logs,
	}
}

// txBody returns a marshaled agent TransactionRequest.
func (e relayTestEnv) txBody(t *testing.T) []byte {
	t.Helper()
	txReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		Id:             "tx-relay-test",
		OfferId:        stringPtr("offer-1"),
		OfferSignature: stringPtr("sig-x"),
		Requester: &rampv1.Requester{
			Id:     e.agentKID,
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris:   []string{"https://pub.example/article"},
		},
	}
	body, err := protojson.Marshal(txReq)
	if err != nil {
		t.Fatalf("marshal TransactionRequest: %v", err)
	}
	return body
}

// signedRelayRequest builds a POST to the broker relay carrying the agent's
// sig1. CRITICAL: the agent signs @target-uri against the Exchange execute URL
// (the real flow), not the broker relay path — the broker reconstructs that
// target to verify sig1.
func (e relayTestEnv) signedRelayRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	execURL := e.exchangeURL + rampv1connect.ExchangeServiceExecuteTransactionProcedure
	signReq, err := http.NewRequest(http.MethodPost, execURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create sign request: %v", err)
	}
	signReq.Header.Set("Content-Type", "application/json")
	created := clock.System{}.Now().Unix()
	expires := created + 300
	if err := httpsig.SignRequestRAMP(signReq, body, e.agentKID, e.agentPriv, created, expires); err != nil {
		t.Fatalf("agent sign request: %v", err)
	}

	relayReq, err := http.NewRequest(http.MethodPost, e.brokerURL+"/broker/v1/exchange/execute", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create relay request: %v", err)
	}
	relayReq.Header = signReq.Header.Clone()
	relayReq.Header.Set("X-RAMP-Exchange-Endpoint", e.exchangeURL)
	return relayReq
}

// TestExchangeRelay_MultisigBindsToAgent verifies the broker relay preserves the
// agent's sig1, appends the broker's sig2, and the Exchange receives multisig on
// the same body.
func TestExchangeRelay_MultisigBindsToAgent(t *testing.T) {
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

	// The Broker relays the agent's signed TransactionRequest verbatim, so the ver
	// the Exchange receives is the agent's, passed through unchanged. Pin that the
	// relay leg carries the canonical wire version — the relay never restamps, so a
	// stale agent ver would otherwise reach the Exchange unnoticed.
	assertEmittedVer(t, "relayed TransactionRequest", env.mockExch.lastExecuteVer)

	capturedSigInput, capturedSig := env.captured.get()
	if capturedSigInput == "" || capturedSig == "" {
		t.Fatal("Exchange did not receive Signature-Input/Signature headers")
	}

	capturedHdr := http.Header{}
	capturedHdr.Set("Signature-Input", capturedSigInput)
	capturedHdr.Set("Signature", capturedSig)
	labels, err := httpsig.ParseSignatureLabels(capturedHdr)
	if err != nil {
		t.Fatalf("parse captured Signature-Input: %v", err)
	}
	if len(labels) != 2 {
		t.Fatalf("expected 2 signatures (sig1 + sig2), got %d: %v", len(labels), labels)
	}
	if labels[0].KeyID != env.agentKID {
		t.Errorf("sig1 keyid = %q, want agent keyid %q", labels[0].KeyID, env.agentKID)
	}
	if labels[1].KeyID != env.brokerKID {
		t.Errorf("sig2 keyid = %q, want broker keyid %q", labels[1].KeyID, env.brokerKID)
	}

	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(bodyBytes, &txResp); err != nil {
		t.Fatalf("parse TransactionResponse: %v", err)
	}
	if txResp.GetRetrievalEndpoint() == "" {
		t.Error("TransactionResponse missing retrieval_endpoint (signed URL)")
	}
	// MED-04: the success outcome MUST be observable and use the Exchange's
	// "VALIDATED" vocabulary so accept/reject correlate across both audit surfaces.
	if !strings.Contains(env.logs.String(), "VALIDATED") {
		t.Errorf("relay success emitted no VALIDATED audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsUnsignedRequest verifies the broker refuses to relay
// (and stamp sig2 onto) a request carrying no agent signature — CRIT-01: the
// broker must not act as an open signing proxy.
func TestExchangeRelay_RejectsUnsignedRequest(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)

	req, err := http.NewRequest(http.MethodPost, env.brokerURL+"/broker/v1/exchange/execute", bytes.NewReader(body))
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
		t.Fatalf("unsigned relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an unsigned request, want 0", env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_RejectsTamperedSignature verifies a corrupted sig1 is
// rejected at the broker — CRIT-01.
func TestExchangeRelay_RejectsTamperedSignature(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)
	req := env.signedRelayRequest(t, body)

	// Corrupt the signature value while leaving Signature-Input intact.
	req.Header.Set("Signature", "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:")

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
	// MED-05: the rejection MUST be observable — assert the audit outcome.
	if !strings.Contains(env.logs.String(), "REJECTED_AUTHZ") {
		t.Errorf("relay rejection emitted no REJECTED_AUTHZ audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsReplayedSignature verifies SEC-01: the relay endpoint
// is excluded from the httpsig middleware, so a captured valid relay request
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

	// Replay the identical signed request (same sig1 bytes).
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
		t.Errorf("Exchange called %d times across the replay, want 1 (replay not forwarded)", env.mockExch.executeCalls)
	}
	if !strings.Contains(env.logs.String(), "REJECTED_REPLAY") {
		t.Errorf("replay rejection emitted no REJECTED_REPLAY audit log; got: %s", env.logs.String())
	}
}

// TestExchangeRelay_RejectsUnregisteredEndpoint verifies the SSRF allowlist —
// HIGH-02: even a validly-signed request may not steer the broker onto an
// endpoint that is not a registered Exchange.
func TestExchangeRelay_RejectsUnregisteredEndpoint(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)
	req := env.signedRelayRequest(t, body)

	// Point at an endpoint the broker's registry does not know.
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
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an unregistered endpoint, want 0", env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_BoundsOversizedBody verifies the relay caps the body it
// buffers (maxAgentBodyBytes). The endpoint is pre-auth, so an unbounded read
// would let an unauthenticated caller exhaust broker memory. A signed-but-
// oversized request is truncated on read, so sig1 verification fails and it is
// never relayed — proving the read was bounded (an unbounded read would have
// matched the digest and relayed).
func TestExchangeRelay_BoundsOversizedBody(t *testing.T) {
	env := newRelayTestEnv(t)

	txReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		Id:             "tx-oversized",
		OfferId:        stringPtr("offer-1"),
		OfferSignature: stringPtr("sig-x"),
		Requester: &rampv1.Requester{
			Id:     env.agentKID,
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris:   []string{"https://pub.example/" + strings.Repeat("a", 80*1024)},
		},
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

// TestExchangeRepo_NormalizesEndpointOnStore pins the MED-01 fix at its source of
// truth: an Exchange configured with a trailing slash is stored canonicalized, so
// discovery emits a single form and the agent never signs a double-slash
// @target-uri that the relay's sig1 verification (and the Exchange route) could
// not match. Without normalization the SSRF allowlist would admit the request but
// sig1 verify would fail-closed, silently breaking such Exchanges over the relay.
func TestExchangeRepo_NormalizesEndpointOnStore(t *testing.T) {
	ctx := context.Background()
	dsn := setupPostgres(t, ctx)
	pool := sharedb.OpenForTest(t, ctx, dsn)
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

	// The normalization is durable — a fresh read sees the canonical form, so the
	// SSRF allowlist and the discovery offer both emit it without a trailing slash.
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
