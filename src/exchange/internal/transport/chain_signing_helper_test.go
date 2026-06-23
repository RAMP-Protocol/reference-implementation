//go:build integration

package transport_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// chainSigner pairs an httpsig keyID with its Ed25519 private key for one hop
// of a forwarding signature chain.
type chainSigner struct {
	id   string
	priv ed25519.PrivateKey
}

// chainSigningTransport signs each outbound /ramp.* request with an
// N-signature forwarding chain: the first signer via SignRequestRAMP, each
// subsequent signer via AppendSignatureRAMP (which also writes the RFC 9421
// forwarding-chain link committing to its predecessor). It generalises
// multisigTransport (fixed at 2) so a test can drive an arbitrarily deep chain
// through the Exchange hop-budget gate.
type chainSigningTransport struct {
	base    http.RoundTripper
	signers []chainSigner
}

func (t *chainSigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	now := time.Now()
	created, expires := now.Unix(), now.Add(5*time.Minute).Unix()
	for i, s := range t.signers {
		if i == 0 {
			if err := httpsig.SignRequestRAMP(req, body, s.id, s.priv, created, expires); err != nil {
				return nil, err
			}
			continue
		}
		if err := httpsig.AppendSignatureRAMP(req, body, s.id, s.priv, created, expires); err != nil {
			return nil, err
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return t.base.RoundTrip(req)
}

// newChainClient builds an ExchangeService client that signs every request with
// an N-hop forwarding chain: the default agent-test caller first, then one
// BROKER intermediary per id in intermediaryIDs. Each intermediary key is
// generated, registered in the httpsig resolver, and upserted as a BROKER
// agent, so chains within the hop budget verify cleanly. Over-budget chains are
// rejected by the gate before any signature is verified, so the registration is
// inert there — it exists so the same helper serves the within-budget control.
func (h *testHarness) newChainClient(t *testing.T, intermediaryIDs ...string) rampconnect.ExchangeServiceClient {
	t.Helper()
	signers := []chainSigner{{id: "agent-test", priv: h.callerPriv}}
	for _, id := range intermediaryIDs {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("chain signer %q ed25519: %v", id, err)
		}
		h.resolver.Put(id, pub)
		if _, err := h.queries.UpsertAgent(h.ctx, sqlc.UpsertAgentParams{
			AgentID:       id,
			PublicKey:     pub,
			RequesterType: sqlc.RampRequesterType("BROKER"),
		}); err != nil {
			t.Fatalf("upsert chain signer %q: %v", id, err)
		}
		signers = append(signers, chainSigner{id: id, priv: priv})
	}
	client := &http.Client{Transport: &chainSigningTransport{base: h.baseTransport, signers: signers}}
	return rampconnect.NewExchangeServiceClient(client, h.server.URL, connect.WithGRPC())
}

// signedChainPOST issues a raw HTTP POST to the given /ramp.* path signed with
// an N-hop forwarding chain: agent-test first, then a throwaway key per id in
// intermediaryIDs. It returns the raw response so a test can assert the global
// httpsig gate's HTTP-level contract (status + body) directly — the Connect
// gRPC client remaps a bare HTTP 429 to "unavailable", which masks the gate's
// resource_exhausted semantics. Intermediary keys are deliberately NOT
// registered: the hop-budget gate rejects an over-budget chain before any
// signature is verified, so registration would be inert here.
func (h *testHarness) signedChainPOST(t *testing.T, path string, intermediaryIDs ...string) *http.Response {
	t.Helper()
	signers := []chainSigner{{id: "agent-test", priv: h.callerPriv}}
	for _, id := range intermediaryIDs {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("chain hop %q ed25519: %v", id, err)
		}
		signers = append(signers, chainSigner{id: id, priv: priv})
	}
	client := &http.Client{Transport: &chainSigningTransport{base: h.baseTransport, signers: signers}}
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.server.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("chain POST %s: %v", path, err)
	}
	return resp
}
