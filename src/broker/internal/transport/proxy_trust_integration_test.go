//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// These tests pin the RAMP-171 staging topology on the Broker's execute relay:
// a TLS-terminating proxy (Caddy) fronts the Broker, so the agent signs sig1
// over the https broker route while the service socket sees plain HTTP plus
// X-Forwarded-Proto. The relay's boundary verify (requestTargetURL) must honor
// the forwarded scheme ONLY under the trust-proxy-headers opt-in — before
// RAMP-171 it trusted the header unconditionally, which would let a caller on
// a directly-exposed Broker pick the scheme its signature is verified against.

// signedHTTPSRelayRequest builds a POST to the broker execute route with sig1
// minted over the https route URL — what an agent posts behind a
// TLS-terminating proxy. The URL is left absolute-https; callers deliver it
// either origin-form (after testutil.DowngradeToProxiedWire, the proxied shape)
// or absolute-form (raw, the absform_spoof tests). Shared by both so a change to
// the signing shape cannot silently diverge the proxy and spoof suites.
func signedHTTPSRelayRequest(t *testing.T, env relayTestEnv, body []byte) *http.Request {
	t.Helper()
	httpsRoute := testutil.HTTPSVariant(t, env.brokerURL) + "/broker/v1/exchange/execute"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, httpsRoute, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create relay request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	signer, err := helpers.NewEd25519Signer(env.agentKID, env.agentPriv)
	if err != nil {
		t.Fatalf("new agent signer: %v", err)
	}
	created := clock.System{}.Now().Unix()
	opts := helpers.SignOptions{Created: created, Expires: created + 300}
	if err := helpers.SignRequest(req.Context(), req, body, signer, opts); err != nil {
		t.Fatalf("agent sign over https broker route: %v", err)
	}
	return req
}

// proxiedSig1RelayRequest builds the proxied wire shape: the https-signed
// request downgraded to the plain-HTTP listener carrying X-Forwarded-Proto:
// https — byte-for-byte what Caddy forwards.
func proxiedSig1RelayRequest(t *testing.T, env relayTestEnv, body []byte) *http.Request {
	t.Helper()
	req := signedHTTPSRelayRequest(t, env, body)
	testutil.DowngradeToProxiedWire(req)
	return req
}

// TestExchangeRelay_ProxiedTLSTermination_VerifiesForwardedScheme proves the
// staging shape end-to-end through the relay: with trust-proxy-headers wired,
// the https-signed sig1 verifies over the plain-HTTP leg and the execute is
// relayed to the Exchange. Round-trip: agent → broker route (real HTTP) →
// mock Exchange; assertions read the broker's HTTP response and the
// Exchange-side call count.
func TestExchangeRelay_ProxiedTLSTermination_VerifiesForwardedScheme(t *testing.T) {
	env := newRelayTestEnvShaped(t, true)
	body := env.txBody(t)

	resp, err := http.DefaultClient.Do(proxiedSig1RelayRequest(t, env, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("proxied relay: status = %d, want 200; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 1 {
		t.Errorf("Exchange executeCalls = %d, want 1", env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_DirectExposure_SpoofedForwardedProtoIgnored proves the
// directly-exposed shape: without the opt-in, a caller-supplied
// X-Forwarded-Proto must NOT change the verified scheme — the https-signed
// sig1 fails against the socket's http URL, the request is rejected
// unauthenticated, and nothing reaches the Exchange.
func TestExchangeRelay_DirectExposure_SpoofedForwardedProtoIgnored(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)

	resp, err := http.DefaultClient.Do(proxiedSig1RelayRequest(t, env, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("spoofed relay: status = %d, want 401; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange executeCalls = %d, want 0 (spoofed request must not relay)", env.mockExch.executeCalls)
	}
}
