//go:build integration

package transport_test

// The DISCOVER relay's answer for an Exchange that is registered and trusted
// but whose last health probe failed.
//
// The execute relay has its own test for the same state. This one exists
// because the two routes reach it through different code and answer with
// different audit records. The discover route is the only caller of
// Core.AdmitEndpoint, so its EndpointDown arm — and REJECTED_ENDPOINT_DOWN, the
// audit action that arm introduced — had no coverage at all: the down
// condition could be returned as unregistered, the audit string could be
// changed back, or the audit call could be deleted, and the whole suite still
// passed.
//
// The discover suite covers every other arm of this gate (unsigned, tampered,
// replayed, missing routing header, unregistered endpoint), each asserting the
// status, that the Exchange was not dialled, and the audit action. This is that
// missing row.

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
)

// TestDiscoverRelay_DownExchangeIsRefusedRetryablyAndAuditedAsUnavailable
// drives the outage through the production lever and asserts all three halves
// of the answer: the code the agent reads, the request never leaving the
// process, and the record the operator greps.
//
// Health is never written by hand. The stub Exchange's /healthz is flipped to
// 503 and one real refresher pass — over the same endpoint resolver production
// wires the refresher to — reads that and marks the row down, the sequence
// production runs on its ticker.
func TestDiscoverRelay_DownExchangeIsRefusedRetryablyAndAuditedAsUnavailable(t *testing.T) {
	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)

	// Baseline: the relay reaches the Exchange while the row still says healthy.
	// Without this leg a later "was not dialled" assertion would also pass on a
	// fixture that could never dial the Exchange for some unrelated reason.
	baseline, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/before"), true),
	)
	if err != nil {
		t.Fatalf("baseline discover relay: %v", err)
	}
	_, _ = io.Copy(io.Discard, baseline.Body)
	_ = baseline.Body.Close()
	dialledWhenHealthy := env.mockExch.discoverCalls
	if dialledWhenHealthy == 0 {
		t.Fatal("the relay never reached the Exchange while it was healthy, " +
			"so nothing after this point would prove the health flag did the work")
	}

	// Take the Exchange down the only way production can: one probe pass over a
	// /healthz that now refuses.
	env.mockExch.setHealthz(http.StatusServiceUnavailable)
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, loopbackProbeClient(), testutil.DiscardLogger(), 0,
	), ctx)

	resp, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/after"), true),
	)
	if err != nil {
		t.Fatalf("discover relay while down: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	// Checked first: nothing signed may leave the process for an Exchange the
	// broker has decided is down. Reading the status first would report a wrong
	// code and never say whether the request was forwarded anyway.
	if env.mockExch.discoverCalls != dialledWhenHealthy {
		t.Errorf("discover calls = %d, want %d — a down Exchange must not be dialled",
			env.mockExch.discoverCalls, dialledWhenHealthy)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (retryable; %d would tell the agent to stop trying "+
			"an Exchange that comes back within one refresher interval)",
			resp.StatusCode, http.StatusServiceUnavailable, http.StatusBadRequest)
	}
	// The message has to name the real cause. "not a registered exchange" is
	// false here: the registry lists this Exchange and the operator still trusts
	// it, which is exactly why the refusal is retryable rather than final.
	if strings.Contains(string(respBody), "not a registered exchange") {
		t.Errorf("body claims the Exchange is unregistered, but the registry lists it: %s",
			respBody)
	}
	assertRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT_DOWN")
	assertNoRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT")
}

// TestDiscoverRelay_UnverifiedCallerLearnsNothingAboutTheRegistry pins that the
// answer above is only ever given to a caller that has proved who it is.
//
// The retryable refusal is useful and it is also informative: it says, in words,
// that this endpoint IS registered and its health check is failing. Given away
// before verification, that turns the relay into a registry oracle — anyone can
// sort address guesses into registered and unregistered, and then poll a
// registered one to watch its outages. The relay deliberately hides the
// blocked-versus-unregistered split from an unverified caller for exactly this
// reason; the health answer reports the same fact on a different axis.
//
// So the unsigned request must be refused as unsigned, and must not reveal which
// state the row is in. Both legs run against the SAME down row, which is what
// makes the pair meaningful: the verified caller gets 503 and the unverified one
// does not.
//
// Mutation check: put the admission check back above the verification and this
// test fails, because the unsigned caller is handed the health answer.
func TestDiscoverRelay_UnverifiedCallerLearnsNothingAboutTheRegistry(t *testing.T) {
	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)

	// Take the Exchange down through the production lever, as above.
	env.mockExch.setHealthz(http.StatusServiceUnavailable)
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, loopbackProbeClient(), testutil.DiscardLogger(), 0,
	), ctx)

	// Leg 1: a verified agent still gets the distinction the branch added it for.
	verified, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/verified"), true),
	)
	if err != nil {
		t.Fatalf("verified discover relay: %v", err)
	}
	_, _ = io.Copy(io.Discard, verified.Body)
	_ = verified.Body.Close()
	if verified.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d — a verified agent has to keep the retryable answer, "+
			"or the leg below proves only that the row is unreachable",
			verified.StatusCode, http.StatusServiceUnavailable)
	}

	// Leg 2: the same row, named by a caller who signed nothing.
	unsigned := env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/unsigned"), true)
	unsigned.Header.Del("Signature")
	unsigned.Header.Del("Signature-Input")

	resp, err := http.DefaultClient.Do(unsigned)
	if err != nil {
		t.Fatalf("unsigned discover relay: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — an unsigned caller must be refused as unsigned, "+
			"not answered about the registry", resp.StatusCode, http.StatusUnauthorized)
	}
	if strings.Contains(string(respBody), "health check") {
		t.Errorf("the refusal tells an unverified caller this endpoint is registered and "+
			"failing its health check: %s", respBody)
	}
}
