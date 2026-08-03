package xclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// agentDirectory is the originating agent's Signature-Agent directory, set once
// by the agent and preserved verbatim by the broker relay transport.
const agentDirectory = "agent.fixture.test"

// TestSigningTransport_PreservesAgentSignature verifies that when an agent
// signs a request with sig1, and the broker's signing transport appends its
// signature, both signatures (sig1 from agent, sig2 from broker) are present
// in the final request and both verify successfully.
func TestSigningTransport_PreservesAgentSignature(t *testing.T) {
	// Setup: generate agent and broker keypairs.
	agentPub, agentPriv := mustGenerateKey(t)
	brokerPub, brokerPriv := mustGenerateKey(t)

	// Create a test server first to get its URL.
	var capturedReq *http.Request
	server := setupCaptureServer(&capturedReq)
	defer server.Close()

	// Create test HTTP request body.
	body := []byte(`{"url":"https://publisher.example/content"}`)

	// Create and sign request with agent's key (sig1). Use real now: the
	// signing library (yaronf/httpsign) stamps created=time.Now() at sign time,
	// so the verifier clock below must track real time, not a frozen past
	// instant, or the signature reads as created-in-the-future.
	now := time.Now()
	req := createAndSignAgentRequest(t, server.URL, body, agentPriv, now)

	// Create broker signing transport and pass request through it.
	brokerKey := &RelayKey{
		KeyID:   rwtestutil.MustThumbprint(t, brokerPub),
		Private: brokerPriv,
	}
	resp := sendThroughSigningTransport(t, req, brokerKey, now)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Verify both signatures are present in captured request.
	assertSignatureHeadersPresent(t, capturedReq)

	// Verify both signatures validate correctly.
	verifyBothSignatures(t, capturedReq, agentPub, brokerPub, now)
}

// mustGenerateKey generates an ed25519 keypair or fails the test.
func mustGenerateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// setupCaptureServer creates a test HTTP server that captures incoming requests.
func setupCaptureServer(captured **http.Request) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clone and preserve request for verification.
		*captured = r.Clone(context.Background())
		bodyBuf := new(bytes.Buffer)
		_, _ = bodyBuf.ReadFrom(r.Body)
		(*captured).Body = io.NopCloser(bytes.NewReader(bodyBuf.Bytes()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
}

// createAndSignAgentRequest creates an HTTP request and signs it with the
// agent's key, producing sig1.
func createAndSignAgentRequest(
	t *testing.T, serverURL string, body []byte,
	agentPriv ed25519.PrivateKey, now time.Time,
) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		serverURL+"/ramp.v1.ExchangeService/CreateOffer",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer agent-token")
	// The originating agent names its own directory in Signature-Agent; the
	// broker relay preserves it so both signatures cover the same value.
	req.Header.Set(helpers.SignatureAgentHeader, agentDirectory)

	agentPub := agentPriv.Public().(ed25519.PublicKey)
	agentSigner, err := helpers.NewEd25519Signer(rwtestutil.MustThumbprint(t, agentPub), agentPriv)
	if err != nil {
		t.Fatalf("new agent signer: %v", err)
	}
	created := now.Unix()
	opts := helpers.SignOptions{Created: created, Expires: created + 30}
	err = helpers.SignRequest(req.Context(), req, body, agentSigner, opts)
	if err != nil {
		t.Fatalf("agent sign: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, "sig1=") {
		t.Fatalf("agent signature missing sig1, got: %q", sigInput)
	}

	return req
}

// sendThroughSigningTransport creates a broker signing transport and sends
// the request through it, returning the HTTP response.
func sendThroughSigningTransport(
	t *testing.T, req *http.Request, brokerKey *RelayKey, now time.Time,
) *http.Response {
	t.Helper()
	clk := clock.NewDeterministic(now)
	transport, err := NewSigningTransport(nil, brokerKey, "broker.fixture.test", 30*time.Second, clk)
	if err != nil {
		t.Fatalf("build signing transport: %v", err)
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("transport roundtrip: %v", err)
	}
	return resp
}

// TestSigningTransport_SetsGetBody guards the retry defect: the relay signing
// transport MUST re-seat req.GetBody after draining the body so net/http can
// replay it on a retried request. A signer that leaves GetBody nil silently
// drops the body on the second attempt (empty content-digest → verify failure).
func TestSigningTransport_SetsGetBody(t *testing.T) {
	_, brokerPriv := mustGenerateKey(t)
	brokerPub := brokerPriv.Public().(ed25519.PublicKey)
	brokerKey := &RelayKey{KeyID: rwtestutil.MustThumbprint(t, brokerPub), Private: brokerPriv}

	// A captured inner transport lets us inspect the request AFTER signing without
	// making a network hop.
	var seen *http.Request
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})

	transport, err := NewSigningTransport(inner, brokerKey, "broker.fixture.test", 30*time.Second,
		clock.NewDeterministic(time.Now()))
	if err != nil {
		t.Fatalf("build signing transport: %v", err)
	}

	body := []byte(`{"url":"https://publisher.example/content"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/CreateOffer", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer agent-token")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	_ = resp.Body.Close()

	if seen == nil {
		t.Fatal("inner transport never saw the request")
	}
	if seen.GetBody == nil {
		t.Fatal("GetBody is nil after signing: a retried request would lose its body")
	}
	// GetBody must reproduce the exact signed bytes so a retry re-sends them.
	rc, err := seen.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	replayed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read replayed body: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Errorf("GetBody replayed %q, want %q", replayed, body)
	}
}

// roundTripFunc adapts a function to http.RoundTripper for the capture test.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// assertSignatureHeadersPresent verifies both sig1 and sig2 are in the
// Signature-Input and Signature headers.
func assertSignatureHeadersPresent(t *testing.T, req *http.Request) {
	t.Helper()
	sigInput := req.Header.Get("Signature-Input")
	sig := req.Header.Get("Signature")

	for _, label := range []string{"sig1", "sig2"} {
		if !strings.Contains(sigInput, label+"=") {
			t.Errorf("Signature-Input missing %s, got: %q", label, sigInput)
		}
		if !strings.Contains(sig, label+"=") {
			t.Errorf("Signature header missing %s, got: %q", label, sig)
		}
	}

	// the broker's sig2 must chain to sig1 — its covered set includes
	// "signature";key="sig1" so it cryptographically commits to the agent's sig.
	if !strings.Contains(sigInput, `"signature";key="sig1"`) {
		t.Errorf(`Signature-Input sig2 missing chain link "signature";key="sig1", got: %q`, sigInput)
	}
}

// verifyBothSignatures uses VerifyMultisigRequestResolved to verify both agent
// and broker signatures, then asserts on their properties.
func verifyBothSignatures(
	t *testing.T, req *http.Request,
	agentPub, brokerPub ed25519.PublicKey, now time.Time,
) {
	t.Helper()
	agentKeyid := rwtestutil.MustThumbprint(t, agentPub)
	brokerKeyid := rwtestutil.MustThumbprint(t, brokerPub)
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		agentKeyid:  agentPub,
		brokerKeyid: brokerPub,
	})
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body for verify: %v", err)
	}

	verified, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, resolver, helpers.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("verify multisig: %v", err)
	}

	if len(verified) != 2 {
		t.Fatalf("want 2 verified signatures, got %d", len(verified))
	}

	// Verify sig1 (agent): keyid is the agent's thumbprint; Signature-Agent
	// names the agent's directory.
	if verified[0].Label != "sig1" || verified[0].KeyID != agentKeyid {
		t.Errorf("sig1: want (sig1, %s), got (%s, %s)",
			agentKeyid, verified[0].Label, verified[0].KeyID)
	}
	if verified[0].SignatureAgent != agentDirectory {
		t.Errorf("sig1 Signature-Agent = %q, want %q", verified[0].SignatureAgent, agentDirectory)
	}

	// Verify sig2 (broker): keyid is the broker's thumbprint; the relay preserved
	// the agent's Signature-Agent, so sig2 covers the same directory value.
	if verified[1].Label != "sig2" || verified[1].KeyID != brokerKeyid {
		t.Errorf("sig2: want (sig2, %s), got (%s, %s)",
			brokerKeyid, verified[1].Label, verified[1].KeyID)
	}
	if verified[1].SignatureAgent != agentDirectory {
		t.Errorf("sig2 Signature-Agent = %q, want %q (relay preserves agent directory)",
			verified[1].SignatureAgent, agentDirectory)
	}
}

// TestLoadRelayKey_ValidFile verifies loading a valid broker relay key file.
func TestLoadRelayKey_ValidFile(t *testing.T) {
	// Generate a test key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Extract seed from private key.
	seed := priv.Seed()

	// Create a temporary file with the relay key. After the WBA split the file
	// carries no kid — the keyid is derived as the public key's thumbprint.
	keyFile := relayKeyFile{
		PrivateKey: base64.RawURLEncoding.EncodeToString(seed),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
	}

	data, err := json.Marshal(keyFile)
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}

	// Write to temp file.
	tmpFile := t.TempDir() + "/broker-relay-key.json"
	if err := writeFile(tmpFile, data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	// Load the key.
	relayKey, err := LoadRelayKey(tmpFile)
	if err != nil {
		t.Fatalf("load relay key: %v", err)
	}

	// KeyID is the RFC 7638 thumbprint of the derived public key.
	if want := rwtestutil.MustThumbprint(t, pub); relayKey.KeyID != want {
		t.Errorf("keyid: want %s, got %s", want, relayKey.KeyID)
	}

	// Verify private key matches.
	if !bytes.Equal(relayKey.Private, priv) {
		t.Error("private key mismatch")
	}
}

// TestLoadRelayKey_BadSeedLength verifies rejection of a private_key whose
// decoded length is not a valid Ed25519 seed.
func TestLoadRelayKey_BadSeedLength(t *testing.T) {
	keyFile := relayKeyFile{
		PrivateKey: base64.RawURLEncoding.EncodeToString([]byte("too-short")),
		PublicKey:  "",
	}

	data, err := json.Marshal(keyFile)
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}

	tmpFile := t.TempDir() + "/bad-key.json"
	if err := writeFile(tmpFile, data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err = LoadRelayKey(tmpFile)
	if err == nil {
		t.Fatal("want error for bad seed length, got nil")
	}
	if !strings.Contains(err.Error(), "private_key length") {
		t.Errorf("error should mention private_key length, got: %v", err)
	}
}

// writeFile is a test helper to write bytes to a file.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
