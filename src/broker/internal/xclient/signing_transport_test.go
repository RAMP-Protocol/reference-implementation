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

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

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

	// Create and sign request with agent's key (sig1).
	now := time.Unix(1700000000, 0)
	req := createAndSignAgentRequest(t, server.URL, body, agentPriv, now)

	// Create broker signing transport and pass request through it.
	brokerKey := &RelayKey{
		KID:     "broker.test-instance.001",
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

	created := now.Unix()
	expires := now.Add(30 * time.Second).Unix()
	err = httpsig.SignRequestRAMP(req, body, "agent.test.v1", agentPriv, created, expires)
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
	transport := NewSigningTransport(nil, brokerKey, 30*time.Second, clk)
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("transport roundtrip: %v", err)
	}
	return resp
}

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

	// RAMP-56: the broker's sig2 must chain to sig1 — its covered set includes
	// "signature";key="sig1" so it cryptographically commits to the agent's sig.
	if !strings.Contains(sigInput, `"signature";key="sig1"`) {
		t.Errorf(`Signature-Input sig2 missing chain link "signature";key="sig1", got: %q`, sigInput)
	}
}

// verifyBothSignatures uses VerifyMultisigRequest to verify both agent and
// broker signatures, then asserts on their properties.
func verifyBothSignatures(
	t *testing.T, req *http.Request,
	agentPub, brokerPub ed25519.PublicKey, now time.Time,
) {
	t.Helper()
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{
		"agent.test.v1":            agentPub,
		"broker.test-instance.001": brokerPub,
	})

	verified, err := httpsig.VerifyMultisigRequest(
		req,
		resolver,
		httpsig.VerifyRequestOptions{Clk: clock.NewDeterministic(now)},
	)
	if err != nil {
		t.Fatalf("verify multisig: %v", err)
	}

	if len(verified) != 2 {
		t.Fatalf("want 2 verified signatures, got %d", len(verified))
	}

	// Verify sig1 (agent).
	if verified[0].Label != "sig1" || verified[0].KeyID != "agent.test.v1" {
		t.Errorf("sig1: want (sig1, agent.test.v1), got (%s, %s)",
			verified[0].Label, verified[0].KeyID)
	}

	// Verify sig2 (broker).
	if verified[1].Label != "sig2" || verified[1].KeyID != "broker.test-instance.001" {
		t.Errorf("sig2: want (sig2, broker.test-instance.001), got (%s, %s)",
			verified[1].Label, verified[1].KeyID)
	}

	if !strings.HasPrefix(verified[1].KeyID, "broker.") {
		t.Errorf("broker keyid missing broker. prefix: %s", verified[1].KeyID)
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

	// Create a temporary file with the relay key.
	keyFile := relayKeyFile{
		KID:        "broker.test.001",
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

	// Verify KID.
	if relayKey.KID != "broker.test.001" {
		t.Errorf("kid: want broker.test.001, got %s", relayKey.KID)
	}

	// Verify private key matches.
	if !bytes.Equal(relayKey.Private, priv) {
		t.Error("private key mismatch")
	}
}

// TestLoadRelayKey_MissingBrokerPrefix verifies rejection of kid without
// broker. prefix.
func TestLoadRelayKey_MissingBrokerPrefix(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	seed := priv.Seed()

	keyFile := relayKeyFile{
		KID:        "agent.test.001", // Wrong prefix.
		PrivateKey: base64.RawURLEncoding.EncodeToString(seed),
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
		t.Fatal("want error for missing broker. prefix, got nil")
	}

	if !strings.Contains(err.Error(), "must have broker.") {
		t.Errorf("error should mention broker. prefix requirement, got: %v", err)
	}
}

// writeFile is a test helper to write bytes to a file.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
