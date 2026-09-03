//go:build integration

package transport_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// startMisadvertisingExchange stands up an Exchange that serves its own
// /.well-known/ramp.json but advertises an endpoint on a DIFFERENT origin than
// the one that served the document.
//
// It is the refusal fixture. A manifest may name only the host and port that
// served it, or a subdomain of that host, so the endpoint resolver refuses this
// document with resolvers.ErrEndpointRefused before returning anything. The
// second origin is a live server rather than an invented address on purpose: a
// dead address would fail to DIAL, which is the transient failure this test
// exists to tell apart from a verdict.
func startMisadvertisingExchange(tb testing.TB) (domain, advertised string, dialled *atomic.Int32) {
	tb.Helper()
	// The counter is on the server the endpoint check exists to keep traffic away
	// from. Any other server's count is zero whether the check works or not,
	// because no other server is on this route.
	dialled = &atomic.Int32{}
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dialled.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	tb.Cleanup(elsewhere.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(rwtestutil.ExchangeManifest(r.Host, elsewhere.URL))
	}))
	tb.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), elsewhere.URL, dialled
}

// TestExchangeRelay_RefusedEndpointIsFinalNotRetryable pins how the relay
// classifies an Exchange whose manifest advertises an endpoint on another
// origin.
//
// The distinction is the whole point. The relay's default classification for a
// failed endpoint resolution is upstream-unavailable, which reaches the agent as
// a retryable code. A refused endpoint is a verdict: the manifest was read and
// says something the resolver will not act on, and it will say the same thing on
// every retry. Reporting it as retryable sends an agent round a loop that cannot
// terminate, so the refusal has to arrive as invalid-argument.
//
// Round-trip: agent → the broker relay route over real HTTP → the broker fetches
// the offer.exchange manifest over real HTTP → refusal → the assertion reads the
// broker's own HTTP response. The misadvertised upstream is never dialled, which
// is asserted on that server's own counter: nothing signed may leave the process
// for an address that failed the check, and only the server the check keeps
// traffic away from can answer whether it did.
func TestExchangeRelay_RefusedEndpointIsFinalNotRetryable(t *testing.T) {
	env := newRelayTestEnv(t)
	badDomain, advertised, dialled := startMisadvertisingExchange(t)

	// Registered and trusted, so the trust gate passes and the refusal can only
	// come from the endpoint check. The registry carries the advertised endpoint
	// as well, so the post-resolve allowlist could not have been the objection
	// either.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(context.Background(), repo.Exchange{
		ID:                "mp-" + badDomain,
		Domain:            badDomain,
		Endpoint:          advertised,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("seed misadvertising exchange: %v", err)
	}

	body := env.txBodyForExchange(t, badDomain)
	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// Checked FIRST, and not because it is the headline. It is the assertion that
	// stops holding for a reason the status code cannot show: a relay that fell
	// back to the registry's endpoint column on a refused resolution would post
	// the signed transaction to this server and still answer something. Reading
	// the status first would report that as a wrong code and never say where the
	// request went.
	if got := dialled.Load(); got != 0 {
		t.Fatalf("the misadvertised endpoint was dialled %d times behind a refused check, want 0", got)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("refused endpoint reported as retryable (503) — an agent would retry forever; body=%s", respBody)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refused endpoint: status = %d, want 400; body=%s", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "invalid_argument") {
		t.Errorf("refusal did not carry the invalid_argument kind; body=%s", respBody)
	}
}

// TestExchangeRelay_UnusableExchangeHostIsFinalNotRetryable is the third verdict
// the endpoint contract defines, and the one the relay did not name.
//
// The other two mean the manifest was read and said something unusable. This one
// means it was never read: the domain is not a host, so there is nothing to
// fetch. It is still a verdict — a value that is not a host will not become one
// on a later attempt — and reporting it as a transient failure sends the agent
// round a retry loop that can never end.
//
// Reachable because nothing keeps such a value out of the registry: the domain
// column is plain text with no constraint on its shape, so a seed or an admin
// write puts one there and every offer naming it takes this path.
func TestExchangeRelay_UnusableExchangeHostIsFinalNotRetryable(t *testing.T) {
	env := newRelayTestEnv(t)

	// A registry row whose domain carries a path. Registered and trusted, so the
	// trust gate passes and the refusal can only come from the host check.
	const badDomain = "exchange.example/not-a-host"
	if _, err := env.exchangeRepo.UpsertFromBootstrap(context.Background(), repo.Exchange{
		ID:                "mp-unusable-host",
		Domain:            badDomain,
		Endpoint:          "http://exchange.example",
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("seed exchange with an unusable domain: %v", err)
	}

	body := env.txBodyForExchange(t, badDomain)
	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("an unusable exchange host reported as retryable (503) — an agent would retry forever; body=%s", respBody)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unusable exchange host: status = %d, want 400; body=%s", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "invalid_argument") {
		t.Errorf("refusal did not carry the invalid_argument kind; body=%s", respBody)
	}
}
