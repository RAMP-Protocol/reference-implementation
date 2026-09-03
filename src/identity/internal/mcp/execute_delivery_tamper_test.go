//go:build integration

package mcp_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// The edge double ends its binding check with a real Ed25519 verification, and
// that branch is what makes every other delivery test mean something: without it
// the double would accept any signature and a signer emitting the wrong bytes
// would pass the whole suite while every real fetch 403s.
//
// Nothing drove it. The one test that did — it corrupted a byte of the signature
// after the fetcher had signed, so every earlier check still agreed and only the
// signature was wrong — went with the fetcher this branch deleted. Guarding the
// verification with a constant false and running the suite left all thirty
// packages green, which is how the gap was found rather than by reading.
//
// Restating it needs the proof tampered with AFTER the SDK signs and BEFORE the
// edge verifies, and the SDK offers no seam there. A proxy in front of the edge
// is that seam: the delivery URL names the proxy, so the SDK signs the proxy's
// URL; the proxy forwards while keeping the request addressed to itself, so the
// double reconstructs the same base; only the signature differs.
//
// Both directions are driven. Forwarding untampered must deliver — otherwise the
// refusal below would be the proxy's doing and the test would pin nothing.

// newTamperingProxy stands an origin in front of target. With tamper set it
// flips one bit of the proof signature on the way through.
func newTamperingProxy(t *testing.T, target string, tamper bool) string {
	t.Helper()
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target %q: %v", target, err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, err := http.NewRequestWithContext(
			r.Context(), r.Method, targetURL.Scheme+"://"+targetURL.Host+r.RequestURI, nil)
		if err != nil {
			http.Error(w, "build upstream request", http.StatusBadGateway)
			return
		}
		out.Header = r.Header.Clone()
		if tamper {
			flipped, ok := flipProofSignature(r.Header.Get("Signature"))
			if !ok {
				http.Error(w, "no proof signature to tamper with", http.StatusBadGateway)
				return
			}
			out.Header.Set("Signature", flipped)
		}
		// The far side rebuilds the signature base from the authority it was
		// ASKED for, so the forwarded request has to keep naming this proxy. Let
		// it name the upstream instead and the base changes, the verification
		// fails for that reason, and the test would report a tampered-proof
		// refusal it never actually caused.
		out.Host = r.Host

		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

// flipProofSignature returns the RFC 8941 byte string with one bit of the
// signature inverted, still correctly encoded. Encoding stays valid on purpose:
// a malformed header would be refused by the double's decode step and never
// reach the verification this exists to drive.
func flipProofSignature(value string) (string, bool) {
	raw, ok := strings.CutPrefix(value, "sig1=:")
	if !ok || !strings.HasSuffix(raw, ":") {
		return "", false
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(raw, ":"))
	if err != nil || len(sig) == 0 {
		return "", false
	}
	sig[0] ^= 0x01
	return "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":", true
}

// TestExecute_TamperedProofIsRefused drives the edge double's signature
// verification, and proves the harness around it is honest by driving the same
// path untampered.
func TestExecute_TamperedProofIsRefused(t *testing.T) {
	tests := []struct {
		name       string
		tamper     bool
		wantReason string
	}{
		{name: "forwarded untouched", tamper: false},
		{name: "one bit of the signature flipped", tamper: true, wantReason: "pop_sig_invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			edge := testutil.NewEdgeDouble(t, time.Now().Unix())
			edge.SetBody([]byte("licensed"), "text/plain")
			via := newTamperingProxy(t, edge.Origin(), tc.tamper)

			f := newFixture(t)
			a := f.provision(t, "dev-one")
			// Minted against the proxy, so that is the URL the SDK signs and the
			// authority the double reconstructs.
			endpoint := strings.Replace(edge.URLFor(a.Thumbprint), edge.Origin(), via, 1)
			f.broker.relayResp = &rampv1.TransactionResponse{
				Ver:               helpers.ProtocolVersion,
				AgentIdentityHash: a.Thumbprint,
				Items:             []*rampv1.TransactionResultItem{deliveredItem("offer-1", endpoint)},
			}

			out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
				"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
			})

			if tc.wantReason == "" {
				if len(out.DeliveryFailures) != 0 {
					t.Fatalf("an untampered proof was refused: %+v", out.DeliveryFailures)
				}
				return
			}
			if len(out.DeliveryFailures) != 1 {
				t.Fatalf("got %d delivery failures, want 1: %+v",
					len(out.DeliveryFailures), out.DeliveryFailures)
			}
			if got := out.DeliveryFailures[0].Reason; got != tc.wantReason {
				t.Errorf("reason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}
