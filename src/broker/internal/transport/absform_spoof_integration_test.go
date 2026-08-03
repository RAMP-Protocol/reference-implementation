//go:build integration

package transport_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// A directly-exposed service (RAMP_TRUST_PROXY_HEADERS off) must derive the
// signed @target-uri scheme AND host from the socket, never from caller bytes.
// Go's net/http populates r.URL.Scheme, r.URL.Host, and r.Host from an HTTP/1.1
// absolute-form request line (POST https://host/path HTTP/1.1 — RFC 7230 §5.3.2)
// and discards the real Host header, so a caller who never touches a header can
// steer both the scheme and the host the signature is verified against. The
// service refuses absolute-form outright (400) before any verify seam, which is
// the only complete fix — the real host is unrecoverable once Go has dropped the
// Host header. These tests send the raw absolute-form shape and prove rejection.

// TestExchangeRelay_AbsoluteFormRejected proves the flag-off relay refuses an
// absolute-form request line naming the real socket host: rejected with 400
// before verification, never relayed to the Exchange.
func TestExchangeRelay_AbsoluteFormRejected(t *testing.T) {
	env := newRelayTestEnv(t) // flag off — directly-exposed shape
	body := env.txBody(t)
	// signedHTTPSRelayRequest leaves the URL absolute-https, so SendAbsoluteForm
	// emits it as the absolute-form request target (no header spoof needed).
	req := signedHTTPSRelayRequest(t, env, body)
	socketHost := strings.TrimPrefix(env.brokerURL, "http://")

	resp := testutil.SendAbsoluteForm(t, socketHost, req, body)
	defer resp.Body.Close()

	assertAbsoluteFormRejected(t, resp, env)
}

// TestExchangeRelay_AbsoluteFormHostSpoofRejected proves the host half is closed:
// an absolute-form request line naming a DIFFERENT host than the socket (the
// vector that would otherwise rebind the signature's @authority to a host the
// caller chose) is refused with 400, never relayed.
func TestExchangeRelay_AbsoluteFormHostSpoofRejected(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.txBody(t)
	req := signedHTTPSRelayRequest(t, env, body)
	req.URL.Host = "attacker.example" // request line names a host that is not the socket
	socketHost := strings.TrimPrefix(env.brokerURL, "http://")

	resp := testutil.SendAbsoluteForm(t, socketHost, req, body)
	defer resp.Body.Close()

	assertAbsoluteFormRejected(t, resp, env)
}

func assertAbsoluteFormRejected(t *testing.T, resp *http.Response, env relayTestEnv) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("absolute-form request: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange executeCalls = %d, want 0 (absolute-form request must not relay)", env.mockExch.executeCalls)
	}
	// The rejection is the operator's only trace of an attack-only request
	// shape, so it must leave a correlated audit line, like every other
	// rejection on this surface.
	if !strings.Contains(env.logs.String(), "runhttp.absolute_form_reject") {
		t.Errorf("broker log missing the absolute-form rejection line; got:\n%s", env.logs.String())
	}
}
