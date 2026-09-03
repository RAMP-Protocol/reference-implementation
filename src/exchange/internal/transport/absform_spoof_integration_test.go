//go:build integration

package transport_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// A directly-exposed Exchange (RAMP_TRUST_PROXY_HEADERS off) must derive the
// signed @target-uri scheme AND host from the socket, never from caller bytes.
// Go's net/http populates r.URL.Scheme, r.URL.Host, and r.Host from an HTTP/1.1
// absolute-form request line (POST https://host/path HTTP/1.1 — RFC 7230
// §5.3.2) and discards the real Host header, so a caller who never touches a
// header can steer both the scheme and the host verification binds to. The
// service refuses absolute-form outright (400) before the connectserver verify
// seam. These tests drive the raw absolute-form shape and prove rejection.

// captureRoundTripper records the fully-signed request the production signing
// transport produced, instead of sending it, so the test can replay the exact
// same bytes as an absolute-form wire message. Reusing the real signing path
// (newSigningTransport) keeps the signature byte-identical to a genuine call —
// only the request-target FORM differs on the wire.
type captureRoundTripper struct {
	req  *http.Request
	body []byte
}

func (c *captureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		c.body = b
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	// Short-circuit: the test never wants this request delivered here; it
	// replays c.req over a raw socket. A 200 keeps the Connect client quiet.
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     http.Header{},
	}, nil
}

// captureSignedDiscover produces a fully RFC-9421-signed DiscoverResources
// request over the https base URL, without delivering it, and returns the
// request + body for raw replay. The signature covers the https @target-uri.
func captureSignedDiscover(t *testing.T, h *pushHarness, httpsBase string) *captureRoundTripper {
	t.Helper()
	captured := &captureRoundTripper{}
	signing := newSigningTransport(captured, h.discoverKeyID, h.discoverPriv)
	client := rampconnect.NewExchangeServiceClient(&http.Client{Transport: signing}, httpsBase)
	// The call is intercepted by captured before any bytes leave; the error from the
	// dummy 200 (empty body) is irrelevant — we only need the signed request.
	_, _ = client.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester(h.discoverKeyID, "agent.example"), []string{"https://" + h.publisherDom + "/articles/any"})))
	if captured.req == nil {
		t.Fatal("signing transport produced no request")
	}
	return captured
}

// TestExchangeRPC_AbsoluteFormRejected proves the flag-off Exchange
// connectserver seam refuses an absolute-form request line naming the real
// socket host with 400, before verification.
func TestExchangeRPC_AbsoluteFormRejected(t *testing.T) {
	h := newPushHarness(t) // flag off — directly-exposed shape
	socketHost := strings.TrimPrefix(h.server.URL, "http://")

	captured := captureSignedDiscover(t, h, testutil.HTTPSVariant(t, h.server.URL))
	resp := testutil.SendAbsoluteForm(t, socketHost, captured.req, captured.body)
	defer resp.Body.Close()

	assertExchangeAbsoluteFormRejected(t, resp, h)
}

// TestExchangeRPC_AbsoluteFormHostSpoofRejected proves the host half is closed
// at the connectserver seam: an absolute-form line naming a DIFFERENT host than
// the socket is refused with 400.
func TestExchangeRPC_AbsoluteFormHostSpoofRejected(t *testing.T) {
	h := newPushHarness(t)
	socketHost := strings.TrimPrefix(h.server.URL, "http://")

	captured := captureSignedDiscover(t, h, testutil.HTTPSVariant(t, h.server.URL))
	captured.req.URL.Host = "attacker.example" // request line names a host that is not the socket
	resp := testutil.SendAbsoluteForm(t, socketHost, captured.req, captured.body)
	defer resp.Body.Close()

	assertExchangeAbsoluteFormRejected(t, resp, h)
}

func assertExchangeAbsoluteFormRejected(t *testing.T, resp *http.Response, h *pushHarness) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("absolute-form request: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	// The rejection is the operator's only trace of an attack-only request
	// shape, so it must leave a correlated audit line, like every other
	// rejection on this surface.
	if !strings.Contains(h.logs.String(), "runhttp.absolute_form_reject") {
		t.Errorf("server log missing the absolute-form rejection line; got:\n%s", h.logs.String())
	}
}
