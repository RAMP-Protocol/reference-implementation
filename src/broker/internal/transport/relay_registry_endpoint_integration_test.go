//go:build integration

package transport_test

// What the registry's endpoint column is for, asserted through both relay
// routes.
//
// Three parts of the broker held three opinions about where an Exchange is. The
// resolve path dials whatever the Exchange's own /.well-known/ramp.json
// advertises and overwrites the column value it read. The health refresher
// probes that same resolved address. The relay compared against the column, and
// nothing kept the column current — so an Exchange whose operator-supplied
// bootstrap value had gone stale was served by discovery and refused by both
// relay routes as "not a registered exchange", a final verdict for an Exchange
// the registry lists and the operator still trusts.
//
// The two routes now answer it from different places, because their target
// arrives differently. On the execute route the target is derived from a signed
// offer.exchange domain, so the admission is read off the row that domain
// already matched and the column is never consulted. On the discover route the
// target arrives in a request header, so the column IS the allowlist and the
// comparison must stay exact: admitting any host anchored to a registered
// domain would let a caller steer the broker's signed POST at a subdomain the
// Exchange never advertised. What keeps that exact comparison from stranding an
// Exchange is the refresher writing each pass's resolved address back.
//
// Both tests make the two sources disagree on purpose. In any fixture where the
// column and the well-known agree, every version of this code passes.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// staleEndpoint is an address that refuses a connection immediately, standing
// in for a bootstrap value an Exchange has outgrown. A live second server would
// test something else: the point is that this address is never dialled at all.
const staleEndpoint = "http://127.0.0.1:1"

// staleTheColumn points a registered Exchange's endpoint column at a dead
// address while its well-known keeps advertising the live one.
//
// Arranged through the production repository interface because the broker
// exposes no registry-administration RPC — an operator edits the bootstrap file
// and restarts. That missing surface is the reason this is a tier-2 arrange
// rather than a round trip through a public one.
func staleTheColumn(t *testing.T, ctx context.Context, r *repo.PgxExchangeRepo, domain string) {
	t.Helper()
	if _, err := r.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-" + domain,
		Domain:            domain,
		Endpoint:          staleEndpoint,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("stale the registry endpoint: %v", err)
	}
}

// TestExchangeRelay_StaleRegistryColumnDoesNotRefuseTheRelay pins that the
// execute route never consults the column.
//
// No refresh pass runs here, and that is the assertion. The Exchange is
// trusted, healthy and advertising a live endpoint; the only thing wrong is a
// column the operator typed. If the admission still matched on that column, the
// relay would refuse a working Exchange as one nobody registered — while the
// resolve path, reading the same registry, kept serving it.
func TestExchangeRelay_StaleRegistryColumnDoesNotRefuseTheRelay(t *testing.T) {
	ctx := t.Context()
	env := newRelayTestEnv(t)
	staleTheColumn(t, ctx, env.exchangeRepo, env.exchangeDom)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, env.txBody(t)))
	if err != nil {
		t.Fatalf("execute relay against the stale column: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — the Exchange is live and trusted, and only its "+
			"registry column is stale; body=%s", resp.StatusCode, body)
	}
	if env.mockExch.executeCalls == 0 {
		t.Error("the Exchange was never dialled — the relay refused it over a column value " +
			"that names an address nothing routes to")
	}
}

// TestDiscoverRelay_StaleRegistryColumnIsCorrectedByAProbePass pins the other
// half: the discover route does compare against the column, and one probe pass
// is what makes that comparison true.
//
// The refusal leg is what makes the second leg mean anything. Without it, an
// admitted request would prove only that the fixture works.
func TestDiscoverRelay_StaleRegistryColumnIsCorrectedByAProbePass(t *testing.T) {
	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)
	staleTheColumn(t, ctx, env.exchangeRepo, strings.TrimPrefix(env.exchangeURL, "http://"))

	// Leg 1: the live Exchange, named by the address it actually advertises, is
	// refused as one the operator never registered.
	stale, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/stale"), true),
	)
	if err != nil {
		t.Fatalf("discover relay against the stale column: %v", err)
	}
	staleBody, _ := io.ReadAll(stale.Body)
	_ = stale.Body.Close()
	if stale.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d — the column is stale, so this leg has to be the "+
			"refusal the probe pass removes; body=%s",
			stale.StatusCode, http.StatusBadRequest, staleBody)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Fatalf("discover calls = %d, want 0 — the refused request must not be relayed",
			env.mockExch.discoverCalls)
	}

	// One pass resolves the Exchange's well-known, probes the address it names,
	// and records that address as the one the registry holds.
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, loopbackProbeClient(), testutil.DiscardLogger(), 0,
	), ctx)

	// Leg 2: the identical routing target is now admitted and relayed. Nothing
	// else changed, so the pass is what moved the column.
	fixed, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/fixed"), true),
	)
	if err != nil {
		t.Fatalf("discover relay after the probe pass: %v", err)
	}
	fixedBody, _ := io.ReadAll(fixed.Body)
	_ = fixed.Body.Close()
	if fixed.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — the probe pass did not correct the column; body=%s",
			fixed.StatusCode, fixedBody)
	}
	if env.mockExch.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1 — the Exchange was never reached",
			env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_ProbeRefusedByTheGuardLeavesTheExchangeDownAndUnadmitted is
// the negative leg for the guarded probe client.
//
// The refresher dials whatever an exchange's own well-known advertises, and the
// address it measures is the one written into the column the discover relay
// compares a caller-supplied endpoint against. So the probe client is the last
// thing standing between a manifest-supplied address and the allowlist: an
// exchange that serves its well-known from a reachable host can advertise an
// address inside the deployment's own network, and an unguarded probe would get
// an answer from it, turn the row live, and admit relays to it every interval.
//
// This drives the production client, in the production posture. The mock
// Exchange listens on loopback, which that client refuses -- exactly what it
// would do to a metadata or private address a real manifest advertised. The two
// legs are what make it mean something: the exchange is reachable and admitted
// first, and refused only after a pass whose probe the guard turned away.
func TestDiscoverRelay_ProbeRefusedByTheGuardLeavesTheExchangeDownAndUnadmitted(t *testing.T) {
	// Production posture: neither opt-out set, so the client refuses both a
	// private address and a plaintext scheme.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")

	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)

	// Leg 1: the exchange is registered, live and relayed to. Without this the
	// second leg would prove only that the fixture refuses everything.
	admitted, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/guarded"), true),
	)
	if err != nil {
		t.Fatalf("discover relay before the guarded pass: %v", err)
	}
	admittedBody, _ := io.ReadAll(admitted.Body)
	_ = admitted.Body.Close()
	if admitted.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the Exchange has to be admitted first for the "+
			"refusal below to mean anything; body=%s", admitted.StatusCode, admittedBody)
	}
	dialledBefore := env.mockExch.discoverCalls
	if dialledBefore == 0 {
		t.Fatal("the Exchange was never dialled on the admitted leg")
	}

	// One pass with the production probe client. Resolution still succeeds, so
	// the pass learns WHERE the exchange is; the guard refuses the dial to it,
	// so the pass learns the exchange is not answering.
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, resolvers.NewGuardedClientFromEnv(),
		testutil.DiscardLogger(), 0,
	), ctx)

	// Leg 2: the identical request is now refused, and refused RETRYABLY — the
	// registry still knows this exchange, so answering "not a registered
	// exchange" would be false about a row the operator wrote.
	// A different URL, so the second request's sig1 differs from the first's.
	// Signing the same body twice inside one wall-clock second collides in the
	// replay store, and the refusal under test would be masked by a 401.
	refused, err := http.DefaultClient.Do(
		env.signedDiscoverRequest(t, env.queryBodyFor(t, "https://acme.example/guarded-again"), true),
	)
	if err != nil {
		t.Fatalf("discover relay after the guarded pass: %v", err)
	}
	refusedBody, _ := io.ReadAll(refused.Body)
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d — a probe the guard refused must leave the row down, "+
			"not live and not unregistered; body=%s",
			refused.StatusCode, http.StatusServiceUnavailable, refusedBody)
	}
	if strings.Contains(string(refusedBody), "not a registered exchange") {
		t.Errorf("the refusal claims the Exchange is unregistered, but the operator "+
			"registered it and only its probe failed; body=%s", refusedBody)
	}
	if env.mockExch.discoverCalls != dialledBefore {
		t.Errorf("discover calls = %d, want %d — a refused endpoint must not be relayed to",
			env.mockExch.discoverCalls, dialledBefore)
	}
}

// TestDiscoverRelay_TwoRowsSharingAnEndpointGiveOneStableAnswer pins that the
// allowlist answer does not depend on which matching row the registry returns
// first.
//
// Nothing makes the endpoint column unique — only the domain is — so two
// registered domains whose well-knowns advertise the same origin both carry it.
// The refresher actively brings that about: each pass writes the address a row's
// well-known advertises into that row's column. When one of the two is down and
// the other is up, reading the first match made the same request succeed on one
// call and fail on the next, with nothing in the registry having changed.
//
// The correct answer is the permissive one. The question the allowlist asks is
// whether ANY registered exchange advertises this address, and one row being
// down says nothing about another that is up.
//
// Mutation check: read the first matching row instead of the best one and this
// fails — the seeded pair is ordered so the down row comes first.
func TestDiscoverRelay_TwoRowsSharingAnEndpointGiveOneStableAnswer(t *testing.T) {
	ctx := t.Context()
	env := newDiscoverRelayTestEnv(t)
	live := strings.TrimPrefix(env.exchangeURL, "http://")

	// A second registered domain advertising the SAME origin, which one pass will
	// mark down because its own well-known resolves nowhere. The higher priority
	// puts it first in the list, so a first-match read finds this row and not the
	// live one -- without that the test would pass either way. Arranged through
	// the production repository interface because the broker exposes no
	// registry-administration RPC; an operator edits the bootstrap file and
	// restarts.
	if _, err := env.exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-shadow-" + live,
		Domain:            "shadow." + live,
		Endpoint:          env.exchangeURL,
		TrustLevel:        repo.TrustLevelVerified,
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          20,
	}); err != nil {
		t.Fatalf("seed the second row: %v", err)
	}
	// Take only the second row down. Its well-known resolves nowhere, so one
	// pass marks it unhealthy while the live row keeps answering /healthz.
	refreshOnce(t, registry.NewRefresher(
		env.exchangeRepo, env.endpoints, loopbackProbeClient(), testutil.DiscardLogger(), 0,
	), ctx)

	// Repeated because the defect is order-dependence, and a single call cannot
	// tell a stable answer from a lucky one.
	for i := range 4 {
		resp, err := http.DefaultClient.Do(env.signedDiscoverRequest(
			t, env.queryBodyFor(t, fmt.Sprintf("https://acme.example/shared-%d", i)), true,
		))
		if err != nil {
			t.Fatalf("discover relay call %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200 — a live exchange advertises this "+
				"address, and another row being down says nothing about it; body=%s",
				i, resp.StatusCode, body)
		}
	}
}
