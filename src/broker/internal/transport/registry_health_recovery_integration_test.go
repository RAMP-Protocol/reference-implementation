//go:build integration

package transport_test

// Registry health recovery, driven through ramp.v1.BrokerService/Resolve.
//
// The health refresher writes broker.exchanges.healthy, and the resolve fan-out
// reads it: an exchange marked unhealthy is not routed to, so every URL whose
// publisher names it answers with a typed-absence group. The two halves must
// therefore agree about which exchanges are still worth probing. They did not:
// the refresher listed only the healthy rows, so the first failed probe removed
// the exchange from the list the next pass reads and the flag could never go
// back to true. One failed probe during a restart stranded the exchange for
// good, and nothing at any layer said why discovery had stopped answering.
//
// These tests drive the whole loop over the wire -- a real HTTP /healthz on the
// stub Exchange, the real refresher, and the real signed Resolve RPC. Health
// state is never written by hand: the tests take the Exchange down by making
// its /healthz answer 503 and bring it back by making it answer 200, which is
// the only lever production has.

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// catalogedURI is a URL the stub Exchange answers with an offer, on the
// publisher domain the fixture's manifest covers.
const catalogedURI = "https://acme.example/article-42"

// newRefresher builds the health refresher over the fixture's database exactly
// as the broker's composition root does: the same constructor, the same
// repository, and the SAME endpoint resolver the resolve handler routes
// through. Only the polling loop is left out — the tests call RefreshOnce so a
// pass happens at a chosen moment instead of after a 30-second interval.
//
// The probe client is the one deliberate difference, and loopbackProbeClient
// says why.
//
// Sharing one resolver is what makes the test honest about the fix: the probe
// has to measure the endpoint routing will actually use, and handing the two
// halves separate resolvers would hide a disagreement between them.
func newRefresher(fx *fixture) *registry.Refresher {
	return registry.NewRefresher(
		repo.NewExchangeRepo(fx.pool), fx.endpoints, loopbackProbeClient(), fx.logger, 0,
	)
}

// loopbackProbeClient is the probe client for tests whose mock Exchange listens
// on loopback. Production wires the SSRF-guarded client, which refuses a
// loopback address by design — that is the whole point of the guard — so a test
// serving 127.0.0.1 has to opt out of it explicitly. Naming the opt-out here
// keeps it visible: a test that reached for a bare &http.Client would look like
// production wiring, and this one cannot be mistaken for it.
func loopbackProbeClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second}
}

// refreshOnce drives a single probe pass and fails the test if the pass could
// not run at all. Asserting the error is the point of RefreshOnce returning
// one: a pass that never listed anything would otherwise look identical to a
// pass that listed everything and found nothing to change.
func refreshOnce(t *testing.T, r *registry.Refresher, ctx context.Context) {
	t.Helper()
	if err := r.RefreshOnce(ctx); err != nil {
		t.Fatalf("refresh pass did not run: %v", err)
	}
}

// resolveCataloged issues one signed Resolve for the cataloged URL.
func resolveCataloged(t *testing.T, fx *fixture) *rampv1.DiscoveryResponse {
	t.Helper()
	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{uri: catalogedURI, budgetMinor: 10000})
	return out
}

// assertServed fails unless the response carries the offer the stub Exchange
// publishes for the cataloged URL.
func assertServed(t *testing.T, out *rampv1.DiscoveryResponse, leg string) {
	t.Helper()
	groups := out.GetOfferGroups()
	if len(groups) != 1 {
		t.Fatalf("%s: offer_groups = %d, want 1 (one per requested URI), absence_reason=%v",
			leg, len(groups), out.GetAbsenceReason())
	}
	if len(groups[0].GetOffers()) == 0 {
		t.Fatalf("%s: the group carries no offers, absence_reason=%v",
			leg, groups[0].GetAbsenceReason())
	}
}

// assertUnroutable fails unless the response is the group-less request-level
// refusal a URL gets when no exchange its publisher names can serve it, with
// the reason want.
//
// The unroutable URL does start out as a typed-absence group, but that group
// carries no offer, so the batch has no winner and Resolve replaces the whole
// set with the request-level refusal. That shape says nothing at all about
// which exchange dropped out, which is why the log record is asserted too.
//
// The reason is a parameter because the two ways a URL becomes unroutable owe
// an agent different answers. An exchange that is down clears itself within one
// refresher interval, so the batch answers TEMPORARILY_UNAVAILABLE, the same
// answer noHealthyExchangeResponse gives the free-text query path for the same
// condition. An exchange the operator BLOCKED is a settled decision, and a URL
// that routes nowhere else really is not in this broker's catalog.
func assertUnroutable(
	t *testing.T, out *rampv1.DiscoveryResponse, want rampv1.OfferAbsenceReason, leg string,
) {
	t.Helper()
	if n := len(out.GetOfferGroups()); n != 0 {
		t.Errorf("%s: offer_groups = %d, want 0 (the request-level refusal carries none)", leg, n)
	}
	if got := out.GetAbsenceReason(); got != want {
		t.Errorf("%s: absence_reason = %v, want %v", leg, got, want)
	}
}

// TestResolve_UnhealthyExchangeRecoversWhenHealthzReturnsOK is the regression
// test for the one-way health flag. It walks the full outage: the Exchange
// serves, goes down, is skipped, comes back, and serves again -- each leg
// asserted through the Resolve RPC, with the health flag moved only by the
// refresher probing a real /healthz.
//
// Two legs fail on the old code, and they prove different halves. Leg 3 fails
// because broker.routing.skipped did not exist, so nothing said which exchange
// had dropped out. Leg 5 is the regression proper: with the refresher listing
// only healthy rows, the exchange is absent from the pass that follows its own
// downgrade, so /healthz answering 200 again changes nothing and the final
// resolve still refuses.
func TestResolve_UnhealthyExchangeRecoversWhenHealthzReturnsOK(t *testing.T) {
	ctx := t.Context()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example", captureLogs: true})
	refresher := newRefresher(fx)

	// Leg 1: the Exchange is up and serves the URL. Establishes that everything
	// after this point is about health alone, not about a broken fixture.
	assertServed(t, resolveCataloged(t, fx), "baseline, before the outage")
	servedBefore := fx.exchange.discoverCalls
	if skips := fx.logs.Find("broker.routing.skipped"); len(skips) != 0 {
		t.Fatalf("a healthy exchange was logged as skipped: %v — the record would be "+
			"routine noise rather than a signal", skips)
	}

	// Leg 2: the Exchange goes down. One refresh pass sees the failed probe and
	// writes healthy=false, the same way production learns about an outage.
	fx.exchange.setHealthz(http.StatusServiceUnavailable)
	refreshOnce(t, refresher, ctx)

	// Leg 3: while it is down the URL answers with a typed-absence group, the
	// Exchange is not dialled, and the broker says which exchange it declined.
	assertUnroutable(t, resolveCataloged(t, fx),
		rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE,
		"while the exchange is down")
	if fx.exchange.discoverCalls != servedBefore {
		t.Errorf("discover calls = %d, want %d — an unhealthy exchange must not be dialled",
			fx.exchange.discoverCalls, servedBefore)
	}
	assertSkipLogged(t, fx, mockExchangeDomain, "unhealthy")

	// Leg 4: the Exchange comes back. The next refresh pass must still reach it.
	fx.exchange.setHealthz(http.StatusOK)
	refreshOnce(t, refresher, ctx)

	// Leg 5: routing resumes on its own, with no operator intervention.
	assertServed(t, resolveCataloged(t, fx), "after /healthz returned 200 again")
	if fx.exchange.discoverCalls <= servedBefore {
		t.Errorf("discover calls = %d, want more than %d — the recovered exchange was never dialled",
			fx.exchange.discoverCalls, servedBefore)
	}
}

// TestRefresher_DoesNotProbeBlockedExchange pins the other half of the list the
// refresher reads. Widening it to unhealthy rows must not widen it to BLOCKED
// ones: the operator withdrew trust from those, so the broker sends them no
// traffic, a health probe included.
func TestRefresher_DoesNotProbeBlockedExchange(t *testing.T) {
	ctx := t.Context()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	blocked := &mockExchange{domain: "mp.blocked.example", offerUnitCost: 0.10}
	blockedURL := startMockExchange(t, blocked)
	if _, err := repo.NewExchangeRepo(fx.pool).UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-blocked",
		Domain:            "mp.blocked.example",
		Endpoint:          blockedURL,
		TrustLevel:        "BLOCKED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("upsert blocked exchange: %v", err)
	}

	refreshOnce(t, newRefresher(fx), ctx)

	if got := blocked.healthzProbeCount(); got != 0 {
		t.Errorf("/healthz probes on the BLOCKED exchange = %d, want 0", got)
	}
	// Without this the assertion above would also pass if the pass had probed
	// nothing at all -- a refresher that read an empty list, or never ran.
	if fx.exchange.healthzProbeCount() == 0 {
		t.Fatal("the refresh pass probed no exchange at all, so the BLOCKED assertion proves nothing")
	}
}

// TestResolve_BlockedExchangeIsRefusedAsNotInCatalog pins the other arm of the
// health-and-trust check, and the absence reason that goes with it.
//
// A BLOCKED exchange and a down one are both unroutable, and both leave a
// broker.routing.skipped record — but they must not read the same. The operator
// withdrew trust from a BLOCKED exchange on purpose, so nothing about it clears
// on its own: the reason says "blocked", not "unhealthy", and the batch answers
// NOT_IN_CATALOG rather than the TEMPORARILY_UNAVAILABLE a down exchange gets.
// Without this test, the routing skip could record either reason for either
// state and the suite would not notice.
func TestResolve_BlockedExchangeIsRefusedAsNotInCatalog(t *testing.T) {
	ctx := t.Context()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example", captureLogs: true})

	// Withdraw trust from the exchange the publisher's manifest names. Arranged
	// through the production repository interface because the broker exposes no
	// registry-administration RPC — an operator edits the bootstrap file and
	// restarts. That missing surface is the reason this is a tier-2 arrange
	// rather than a round trip through a public one.
	if _, err := repo.NewExchangeRepo(fx.pool).UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-acme",
		Domain:            mockExchangeDomain,
		Endpoint:          fx.endpoints.byDomain[mockExchangeDomain],
		TrustLevel:        "BLOCKED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("block the exchange: %v", err)
	}

	dialledBefore := fx.exchange.discoverCalls
	assertUnroutable(t, resolveCataloged(t, fx),
		rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
		"while the operator has the exchange blocked")
	if fx.exchange.discoverCalls != dialledBefore {
		t.Errorf("discover calls = %d, want %d — a BLOCKED exchange must not be dialled",
			fx.exchange.discoverCalls, dialledBefore)
	}
	assertSkipLogged(t, fx, mockExchangeDomain, "blocked")
}

// TestRefresher_ProbesTheWellKnownEndpointNotTheRegistryColumn pins WHICH
// address the health probe measures.
//
// The registry's endpoint column is operator-supplied bootstrap. The address
// routing actually uses comes from the exchange's OWN well-known, resolved
// through the endpoint resolver, and routing overwrites the column value with
// it on every resolve. An exchange that moves and republishes its well-known is
// therefore still reachable by discovery while its column points somewhere
// stale.
//
// If the probe read the column instead, that exchange would be marked down and
// stay down: its real /healthz could answer 200 for good and the broker would
// never ask it. That is a second way to strand an exchange, past the one-way
// flag this suite already covers, and it is invisible in any fixture where the
// two addresses agree — which is why this test makes them disagree.
func TestRefresher_ProbesTheWellKnownEndpointNotTheRegistryColumn(t *testing.T) {
	ctx := t.Context()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	// A dead address that refuses immediately, standing in for a column left
	// behind by an exchange that moved. The resolver still returns the live one,
	// so the two sources now disagree exactly as they would in production.
	// Arranged through the production repository interface: the broker exposes
	// no registry-administration RPC, so the bootstrap upsert is the only write
	// path there is.
	if _, err := repo.NewExchangeRepo(fx.pool).UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-acme",
		Domain:            mockExchangeDomain,
		Endpoint:          "http://127.0.0.1:1",
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("stale the registry endpoint: %v", err)
	}

	refreshOnce(t, newRefresher(fx), ctx)

	// The headline. A probe that read the column would have dialled the dead
	// address and this counter would still be zero.
	if fx.exchange.healthzProbeCount() == 0 {
		t.Fatal("the live exchange received no /healthz probe — the pass measured " +
			"the registry column, which is not the address routing uses")
	}
	// And the flag the probe wrote is the one routing reads, so the exchange
	// stays usable rather than being stranded by its own stale column.
	assertServed(t, resolveCataloged(t, fx), "after a pass over a stale registry endpoint")
}

// assertSkipLogged fails unless the captured records carry a routing-skip line
// naming the domain and the reason, at INFO. The record is what makes an
// unroutable publisher diagnosable from the broker's logs, so it is asserted as
// behavior, not treated as incidental output.
//
// The level is part of the assertion because it is what separates the two kinds
// of decline. A skip on one of the OPERATOR'S OWN rows is the signal they need
// and stays at INFO; a decline on a domain some remote publisher named is
// routine, unbounded in cardinality, and goes to DEBUG. Demoting one of these
// to DEBUG would take it out of an operator's default view, and without this
// clause the capture (a JSON handler at its default INFO floor) would simply
// stop seeing the record and the loop below would report it as missing rather
// than as demoted. Promoting one to WARN would turn a routine outage into an
// alarm on every resolve, and nothing else here would notice at all.
func assertSkipLogged(t *testing.T, fx *fixture, domain, reason string) {
	t.Helper()
	records := fx.logs.Find("broker.routing.skipped")
	if slices.ContainsFunc(records, func(rec string) bool {
		return strings.Contains(rec, `"domain":"`+domain+`"`) &&
			strings.Contains(rec, `"reason":"`+reason+`"`) &&
			strings.Contains(rec, `"level":"INFO"`)
	}) {
		return
	}
	t.Errorf("no INFO broker.routing.skipped record for domain %q with reason %q; captured: %v",
		domain, reason, records)
}
