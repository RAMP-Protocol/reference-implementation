//go:build integration

package transport_test

// The execute relay's answer for each state a registry row can be in.
//
// The relay tells three states apart: never registered, registered and down,
// registered and withdrawn. It reads all three off the row the signed
// offer.exchange domain matched, so the two tests here drive the two states
// that need a row to exist — an Exchange the operator never registered is
// refused by the trust gate before any of this and has its own coverage.
//
// Neither state had a test before this file. Nothing in the tree put an
// Exchange into the unhealthy state and then drove a relay through it, and the
// withdrawn state was carried by a SQL predicate the execute route no longer
// reads, so both rules lived in comments and a one-word edit could have retired
// either silently.
//
// The two refusals differ in the one way that decides what an agent does next.
// An outage clears within one refresher interval, so it has to arrive
// retryably: answering invalid-argument would tell an agent holding a valid
// signed offer that its offer is bad and that retrying is pointless, and both
// of those are false. A withdrawal is the operator's settled decision, so it
// arrives as the final refusal and is recorded under the same audit action as
// an address nobody registered — which is what it now is.

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// TestExchangeRelay_DownEndpointIsRefusedRetryablyAndNotDialled drives the
// outage through the production lever and asserts all three halves of the
// answer: the code the agent reads, the request never leaving the process, and
// the record the operator greps.
//
// Health is never written by hand. The stub Exchange's /healthz is flipped to
// 503 and one real refresher pass over the real resolver reads that and marks
// the row down — the same sequence production runs on its ticker.
func TestExchangeRelay_DownEndpointIsRefusedRetryablyAndNotDialled(t *testing.T) {
	ctx := t.Context()
	env := newRelayTestEnv(t)

	// Baseline: the relay reaches the Exchange while the row still says healthy.
	// Without this leg a later "was not dialled" assertion would also pass on a
	// fixture that could never dial the Exchange for some unrelated reason.
	// Each leg is signed at its own `created`, so the two carry distinct
	// signatures over identical bytes. That is what a real retry looks like -- the
	// signature covers its own timestamp -- and the relay's replay guard dedups on
	// the signature value, so a byte-identical resend would be refused as a replay
	// before it ever reached the health verdict under test.
	body := env.txBody(t)
	signedAt := clock.System{}.Now().Unix()
	baseline, err := http.DefaultClient.Do(signedSig1OverBrokerRouteAt(
		t, env.brokerURL, env.agentKID, env.agentPriv, body, signedAt))
	if err != nil {
		t.Fatalf("baseline relay: %v", err)
	}
	_, _ = io.Copy(io.Discard, baseline.Body)
	_ = baseline.Body.Close()
	dialledWhenHealthy := env.mockExch.executeCalls
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

	resp, err := http.DefaultClient.Do(signedSig1OverBrokerRouteAt(
		t, env.brokerURL, env.agentKID, env.agentPriv, body, signedAt+1))
	if err != nil {
		t.Fatalf("relay while down: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	// Checked first: nothing signed may leave the process for an Exchange the
	// broker has decided is down. Reading the status first would report a wrong
	// code and never say whether the request was forwarded anyway.
	if env.mockExch.executeCalls != dialledWhenHealthy {
		t.Errorf("execute calls = %d, want %d — a down Exchange must not be dialled",
			env.mockExch.executeCalls, dialledWhenHealthy)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (retryable; %d would tell the agent its "+
			"offer is bad and that retrying is pointless)",
			resp.StatusCode, http.StatusServiceUnavailable, http.StatusBadRequest)
	}
	// The message has to name the real cause. "not a registered exchange" is
	// false here: the registry lists this Exchange and the operator still trusts
	// it, which is exactly why the refusal is retryable rather than final.
	if strings.Contains(string(respBody), "not a registered exchange") {
		t.Errorf("body claims the Exchange is unregistered, but the registry lists it: %s",
			respBody)
	}
	if !strings.Contains(string(respBody), "health check") {
		t.Errorf("body does not name the health state as the cause: %s", respBody)
	}
	// And the outage is filed as an outage. REJECTED_ENDPOINT records an address
	// the operator never authorized, which is the shape an SSRF attempt takes;
	// every execute relay is a batch, so filing routine outages there would make
	// a broker-side network fault read as an attack across the busier route.
	assertRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT_DOWN")
	assertNoRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT")
}

// TestExchangeRelay_WithdrawnExchangeIsRefusedFinallyAndNotDialled pins the
// other state a row can be in.
//
// The execute route reads trust off the row its offer.exchange domain matched.
// It used to get this answer for free from the registry's list query, which
// filters BLOCKED rows out before any caller sees them — but that query answers
// a question keyed on the endpoint, and keying the admission on the endpoint is
// what made a stale registry column refuse a live Exchange. Reading the row the
// domain matched costs the free BLOCKED filter, so the rule is now explicit and
// needs a test that fails without it.
//
// Mutation check: drop the trust arm and the relay forwards a broker-signed
// request to an Exchange the operator has cut off.
func TestExchangeRelay_WithdrawnExchangeIsRefusedFinallyAndNotDialled(t *testing.T) {
	ctx := t.Context()
	env := newRelayTestEnv(t)

	// Withdraw trust. Arranged through the production repository interface
	// because the broker exposes no registry-administration RPC — an operator
	// edits the bootstrap file and restarts. That missing surface is the reason
	// this is a tier-2 arrange rather than a round trip through a public one.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + env.exchangeDom,
		Domain:            env.exchangeDom,
		Endpoint:          env.exchangeURL,
		TrustLevel:        "BLOCKED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("withdraw trust from the exchange: %v", err)
	}

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, env.txBody(t)))
	if err != nil {
		t.Fatalf("relay to a withdrawn exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	// Checked first, for the same reason as above: nothing signed may leave the
	// process for an Exchange the operator has cut off.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("execute calls = %d, want 0 — a withdrawn Exchange must not be dialled",
			env.mockExch.executeCalls)
	}
	// "Not dialled" means not contacted at all, and the execute route contacts an
	// Exchange twice: once for its well-known, once for the transaction. Counting
	// only the second let the broker fetch a withdrawn Exchange's manifest and
	// refuse it afterwards — traffic the registry's own rule says a BLOCKED row
	// never receives. It also let a resolution failure win the race and answer a
	// settled refusal as a retryable one.
	if fetches := env.captured.manifestFetches(); fetches != 0 {
		t.Errorf("manifest fetches = %d, want 0 — a withdrawn Exchange must be refused "+
			"before the broker asks it anything", fetches)
	}
	// Final, not retryable. The operator withdrew trust on purpose and nothing
	// about that clears on its own, so 503 would send an agent round a loop that
	// cannot terminate.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (final; %d would tell the agent to keep retrying "+
			"a decision only the operator can reverse)",
			resp.StatusCode, http.StatusBadRequest, http.StatusServiceUnavailable)
	}
	if !strings.Contains(string(respBody), "not a registered exchange") {
		t.Errorf("body does not give the settled refusal: %s", respBody)
	}
	assertRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT")
	assertNoRelayAudit(t, env.logs.String(), "REJECTED_ENDPOINT_DOWN")
}

// TestExchangeRelay_DiscoveredExchangeIsRefusedForTransactions pins the
// execute-side trust gate.
//
// Trust is graduated, and the steps are not interchangeable. A DISCOVERED
// exchange is one the broker found named in some publisher's ramp.json; nobody
// approved it. It may quote prices, which is comparison shopping and costs
// nothing, and it may not be paid. Anyone who can edit a publisher's ramp.json
// can otherwise write themselves into the payment path, which is the whole
// reason the scale starts below VERIFIED.
//
// The registry's routability verdict cannot carry this. It answers blocked, down
// or live, and DISCOVERED and VERIFIED are equally live — so a healthy
// DISCOVERED row reached transaction fan-out with nothing to stop it.
//
// Mutation check: drop the gate and the broker relays a signed transaction to an
// exchange no operator ever reviewed.
func TestExchangeRelay_DiscoveredExchangeIsRefusedForTransactions(t *testing.T) {
	ctx := t.Context()
	env := newRelayTestEnv(t)

	// Demote to DISCOVERED — healthy, registered, and unreviewed. Arranged
	// through the production repository interface because the broker exposes no
	// registry-administration RPC; an operator edits the bootstrap file and
	// restarts. That missing surface is the reason this is a tier-2 arrange
	// rather than a round trip through a public one.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + env.exchangeDom,
		Domain:            env.exchangeDom,
		Endpoint:          env.exchangeURL,
		TrustLevel:        repo.TrustLevelDiscovered,
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("demote the exchange to DISCOVERED: %v", err)
	}

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, env.txBody(t)))
	if err != nil {
		t.Fatalf("relay to a discovered exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	// Checked first: no money moves, and nothing signed leaves the process.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("execute calls = %d, want 0 — an unreviewed Exchange must not be paid",
			env.mockExch.executeCalls)
	}
	if fetches := env.captured.manifestFetches(); fetches != 0 {
		t.Errorf("manifest fetches = %d, want 0 — the refusal is decided from the registry "+
			"row, so the Exchange should not be contacted at all", fetches)
	}
	// Final, not retryable. It clears when an operator promotes the exchange,
	// which no amount of retrying brings about.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (final; %d would tell the agent to retry until an "+
			"operator happens to promote the Exchange)",
			resp.StatusCode, http.StatusBadRequest, http.StatusServiceUnavailable)
	}
	if !strings.Contains(string(respBody), "not approved for transactions") {
		t.Errorf("body does not say the Exchange is registered but unapproved: %s", respBody)
	}
	assertRelayAudit(t, env.logs.String(), "REJECTED_AUTHZ")
}

// TestExchangeRelay_DiscoveredExchangeStillAnswersDiscovery is the other half of
// the gate: it bounds transactions only. A DISCOVERED exchange exists to be
// price-checked, so refusing it everywhere would make the trust level useless
// rather than cautious.
func TestExchangeRelay_DiscoveredExchangeStillAnswersDiscovery(t *testing.T) {
	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)
	dom := strings.TrimPrefix(env.exchangeURL, "http://")
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + dom,
		Domain:            dom,
		Endpoint:          env.exchangeURL,
		TrustLevel:        repo.TrustLevelDiscovered,
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("demote the exchange to DISCOVERED: %v", err)
	}

	resp, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/discovered"), true),
	)
	if err != nil {
		t.Fatalf("discover relay to a discovered exchange: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — a DISCOVERED Exchange may still be price-checked; "+
			"body=%s", resp.StatusCode, body)
	}
	if env.mockExch.discoverCalls == 0 {
		t.Error("the Exchange was never dialled — the transaction gate leaked onto discovery")
	}
}

// TestExchangeRelay_UnverifiedCallerLearnsNothingAboutTheRegistry pins that the
// execute route answers nothing about the registry until the caller has proved
// who it is.
//
// offer.exchange arrives in an UNSIGNED body, and the admission gate answers it
// four distinguishable ways: never registered, registered and failing its probe,
// registered but not approved to be paid, and admitted. Read before verification,
// those four codes let anyone map the Broker's registry by naming domains, and
// then poll a registered one to watch its outages.
//
// The three registry states are driven against the SAME unsigned caller so the
// assertion is that they are INDISTINGUISHABLE, not merely that each is refused.
//
// Mutation check: put the admission gate back above the verification and each leg
// answers with its own registry-specific code instead of 401.
func TestExchangeRelay_UnverifiedCallerLearnsNothingAboutTheRegistry(t *testing.T) {
	ctx := t.Context()
	env := newRelayTestEnv(t)

	// Leg 1: a domain the registry has never heard of.
	unregistered := env.txBodyForExchange(t, "nobody.example")
	assertUnsignedIsRefusedAsUnsigned(t, env, unregistered, "an unregistered exchange")

	// Leg 2: a registered exchange the operator has not approved for payment.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + env.exchangeDom,
		Domain:            env.exchangeDom,
		Endpoint:          env.exchangeURL,
		TrustLevel:        repo.TrustLevelDiscovered,
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("demote the exchange to DISCOVERED: %v", err)
	}
	assertUnsignedIsRefusedAsUnsigned(t, env, env.txBody(t), "an unapproved exchange")

	// Leg 3: registered, approved, and failing its health probe.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + env.exchangeDom,
		Domain:            env.exchangeDom,
		Endpoint:          env.exchangeURL,
		TrustLevel:        repo.TrustLevelVerified,
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("restore the exchange to VERIFIED: %v", err)
	}
	env.mockExch.setHealthz(http.StatusServiceUnavailable)
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, loopbackProbeClient(), testutil.DiscardLogger(), 0,
	), ctx)
	assertUnsignedIsRefusedAsUnsigned(t, env, env.txBody(t), "a down exchange")

	// Nothing was dialled for any of the three.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("execute calls = %d, want 0 — an unsigned caller reached an Exchange",
			env.mockExch.executeCalls)
	}
}

// assertUnsignedIsRefusedAsUnsigned sends body with the agent signature stripped
// and requires the answer to be about the missing signature and nothing else. The
// three registry states share this helper on purpose: their answers have to be
// byte-comparable for the disclosure claim to hold, and three hand-written copies
// would let one drift into asserting something weaker.
func assertUnsignedIsRefusedAsUnsigned(t *testing.T, env relayTestEnv, body []byte, what string) {
	t.Helper()
	req := env.signedRelayRequest(t, body)
	req.Header.Del("Signature")
	req.Header.Del("Signature-Input")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unsigned relay naming %s: %v", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("%s: status = %d, want %d — an unsigned caller must be refused as "+
			"unsigned, not told what the registry knows; body=%s",
			what, resp.StatusCode, http.StatusUnauthorized, respBody)
	}
	for _, leak := range []string{"not a registered exchange", "health check", "not approved"} {
		if strings.Contains(string(respBody), leak) {
			t.Errorf("%s: the refusal tells an unverified caller %q; body=%s",
				what, leak, respBody)
		}
	}
}
