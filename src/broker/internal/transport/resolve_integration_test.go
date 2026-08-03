//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/offerkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

type fixture struct {
	resolveHandler *resolve.Service
	exchange       *mockExchange
	// exchange2 is the SECOND exchange, wired only when fixtureOpts.secondary is
	// set (the multi-publisher / cross-group selection-audit scenario). nil for
	// the single-exchange suites.
	exchange2 *mockExchange
	logger    *slog.Logger
	// pool is the live pgx pool bound to the shared migrated Postgres the
	// resolve handler writes through. The selection-audit test reuses it to
	// build a SelectionLogRepo for its tier-2 read leg (same DB, same
	// connection the WRITE leg persisted through) — observing the audit row
	// through the production repository interface, never a second/raw handle.
	pool *pgxpool.Pool
}

type fixtureOpts struct {
	providerDomain string
	unlicensed     bool
	budgetMinor    int64
	// secondary, when non-nil, wires a SECOND publisher domain + SECOND exchange
	// into the resolve fixture so a route-per-URL resolve fans a multi-URI batch
	// across two distinct provider domains (one OfferGroup per domain). Each
	// exchange surfaces a DISTINCT offer (offerID + canonicalURL) at its own
	// unit cost, so selection.Rank can deterministically place the GLOBAL winner
	// in EITHER group. Used by the cross-group selection-audit regression test.
	secondary *secondaryProvider
	// verifier, when non-nil, OVERRIDES the default fixtureOfferVerifier wired
	// into Deps.Verifier. It lets a test inject a broker-side offer-verification
	// DECISION (the legitimate Deps.OfferVerifier seam) — e.g. a verifier that
	// rejects a specific offer — WITHOUT mocking the Exchange (Testing Doctrine
	// pt 6): the offers still come from the real Exchange/mock, only the
	// verify/reject verdict is controlled. nil keeps the default (Off-mode
	// pass-through for the legacy 'sig-x' fixtures).
	verifier resolve.OfferVerifier
}

// secondaryProvider parameterises the second publisher domain + its exchange's
// discovered offer for the multi-publisher resolve fixture. providerDomain is
// the publisher whose /.well-known/ramp.json the broker probes; exchangeDomain
// is the (distinct) exchange that publisher names and the broker queries;
// offerID / offerCost / offerCanonicalURL parameterise the single offer that
// exchange returns for its routed URI.
type secondaryProvider struct {
	providerDomain    string
	exchangeDomain    string
	offerID           string
	offerCost         float64
	offerCanonicalURL string
}

func newFixture(tb testing.TB, ctx context.Context, opts fixtureOpts) *fixture {
	tb.Helper()
	logger := testutil.DiscardLogger()
	pool := acquireTestDB(tb, ctx)
	redisClient := acquireTestRedis(tb, ctx)

	// Seed exchange row (domain must match the manifest payload).
	exchangeRepo := repo.NewExchangeRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)

	// Start the mock Exchange Connect-Go server. The mock surfaces an offer
	// with EstimatedQuantity=42 so the relay-path test can assert the Broker
	// actually forwards Usage.ConsumedQuantity. A non-zero
	// value is required because zero quantities also pass the validator's
	// zero-estimate REJECT rule by reporting consumed=0; using 42 makes both
	// the propagation AND the equality assertion non-vacuous.
	exSrv := &mockExchange{
		offerUnitCost:          0.10,
		signedURL:              "https://edge.example/signed?tok=abc",
		offerEstimatedQuantity: 42,
	}
	exchangeURL := startMockExchange(tb, exSrv)

	// Upsert exchange row pointing at the mock Exchange.
	if _, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-acme",
		Domain:            "mp.acme.example",
		Endpoint:          exchangeURL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		tb.Fatalf("upsert exchange: %v", err)
	}

	// Provider fixture hosts /.well-known/ramp.json.
	var providerBase string
	if opts.unlicensed {
		providerBase = startUnlicensedProvider(tb).URL
	} else {
		providerBase = startProviderFixture(tb, exchangeURL).URL
	}
	providerURL, err := url.Parse(providerBase)
	if err != nil {
		tb.Fatalf("parse provider url: %v", err)
	}

	// Wire probe to hit the provider via loopback.
	probeTargets := map[string]string{
		opts.providerDomain: providerBase,
		// also handle :port case from http.Request (host may include port).
		opts.providerDomain + ":" + providerURL.Port(): providerBase,
	}

	// Discovery: static client with our provider domain.
	exaCandidates := []exa.Candidate{
		{URL: "https://" + opts.providerDomain + "/x", Domain: opts.providerDomain, Score: 0.9},
	}

	endpointsByDomain := map[string]string{
		"mp.acme.example": exchangeURL,
	}

	// Multi-publisher wiring (cross-group selection-audit scenario): a SECOND
	// provider domain hosting its OWN well-known (naming a SECOND exchange) plus
	// the second exchange registered + endpoint-resolvable, and the probe client
	// taught to reach the second provider over loopback. The second exchange
	// surfaces a DISTINCT offer at its own cost so selection can place the global
	// winner in either group.
	var exchange2 *mockExchange
	if sec := opts.secondary; sec != nil {
		exchange2 = &mockExchange{
			offerUnitCost:     sec.offerCost,
			signedURL:         "https://edge2.example/signed?tok=def",
			offerID:           sec.offerID,
			offerCanonicalURL: sec.offerCanonicalURL,
		}
		exchange2URL := startMockExchange(tb, exchange2)
		if _, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
			ID:                "mp-" + sec.exchangeDomain,
			Domain:            sec.exchangeDomain,
			Endpoint:          exchange2URL,
			TrustLevel:        "VERIFIED",
			SupportedProfiles: []string{"ramp-news-v1"},
			Priority:          10,
		}); err != nil {
			tb.Fatalf("upsert exchange2: %v", err)
		}
		provider2 := startProviderFixtureFor(tb, sec.providerDomain, sec.exchangeDomain, exchange2URL)
		provider2URL, err := url.Parse(provider2.URL)
		if err != nil {
			tb.Fatalf("parse provider2 url: %v", err)
		}
		probeTargets[sec.providerDomain] = provider2.URL
		probeTargets[sec.providerDomain+":"+provider2URL.Port()] = provider2.URL
		endpointsByDomain[sec.exchangeDomain] = exchange2URL
		exaCandidates = append(exaCandidates, exa.Candidate{
			URL: "https://" + sec.providerDomain + "/x", Domain: sec.providerDomain, Score: 0.8,
		})
	}

	probeClient := &rewritingHTTPClient{targets: probeTargets}
	prober := probe.New(probeClient, logger, probe.Options{Scheme: "http"})
	discovery := &exa.StaticClient{Candidates: exaCandidates}

	// Production offer-signing-key resolver: the SAME constructor the broker
	// wires (offerkeys.New). It backs the default fixtureOfferVerifier, which runs
	// in mode Off for the legacy 'sig-x' fixtures (offerSigningPub unset), so the
	// resolver is never called by these suites — verification-drop behaviour is
	// exercised instead by injecting a fixtureOpts.verifier (the Deps.OfferVerifier
	// seam), not by mock-Exchange WBA key resolution.
	offerKeyResolver := offerkeys.New(offerkeys.Config{Client: probeClient, Scheme: "http"})

	// Default offer-verification seam: pass-through (mode Off) for the legacy
	// fixtures. A test may OVERRIDE it via fixtureOpts.verifier to inject a
	// specific verify/reject decision without mocking the Exchange (pt 6).
	var verifier resolve.OfferVerifier = fixtureOfferVerifier{ex: exSrv, resolver: offerKeyResolver}
	if opts.verifier != nil {
		verifier = opts.verifier
	}

	// Build the co-signer directly rather than through LoadFromEnv: the fixture
	// wants a working signer, not a test of the environment contract. Going
	// through the env would also make every test here depend on the
	// ephemeral-key opt-out, which production is required NOT to set.
	_, signerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("signer key: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.local", "broker-test", signerKey, nil)
	if err != nil {
		tb.Fatalf("signer: %v", err)
	}
	xpool := xclient.NewPool(&http.Client{})
	// Anchor the budget period bucket at a fixed instant so the per-agent
	// accumulation tests land every resolve in one deterministic period
	// ("2026-04") regardless of wall clock — no month-rollover flake. Redis is
	// FLUSHDB-reset per fixture, so each test starts from an empty counter.
	budgetSvc := budget.NewRedis(redisClient, 0,
		clock.NewDeterministic(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)))

	resolver := resolve.NewService(resolve.Deps{
		Exchanges: exchangeRepo,
		Log:       logRepo,
		Discovery: discovery,
		Prober:    prober,
		Exchange:  xpool,
		Budget:    budgetSvc,
		Signer:    signer,
		// Discovery now resolves the exchange endpoint via the exchange's OWN
		// well-known (registry = trust allowlist only). The fake maps the registered
		// exchange domain to the mock Exchange URL, as the real resolver would from
		// the exchange's /.well-known/ramp.json.
		Endpoints: &fakeEndpointResolver{byDomain: endpointsByDomain},
		Verifier:  verifier,
	})
	return &fixture{resolveHandler: resolver, exchange: exSrv, exchange2: exchange2, logger: logger, pool: pool}
}

// reqOpts carries the optional DiscoveryRequest fields the resolve tests vary.
type reqOpts struct {
	query string
	uri   string
	// uris is the full requested batch (batch fan-out). When set it populates
	// DiscoveryRequest.uris verbatim, so a multi-publisher resolve can drive the
	// route-per-URL path that produces one OfferGroup per requested URI. uri
	// (the single-URI convenience) and uris are mutually exclusive at call
	// sites; uris takes precedence when both are set.
	uris        []string
	budgetMinor int64
	maxHops     *int32
}

// buildDiscoveryRequest assembles a canonical DiscoveryRequest for the resolve tests.
// budgetMinor is expressed in minor units and mapped onto constraints.period_budget
// (major units) the same way the production handler inverts it.
func buildDiscoveryRequest(agentID string, o reqOpts) *rampv1.DiscoveryRequest {
	req := &rampv1.DiscoveryRequest{
		Requester: &rampv1.Requester{Id: agentID, Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}
	if o.query != "" {
		q := o.query
		req.Query = &q
	}
	switch {
	case len(o.uris) > 0:
		req.Uris = o.uris
	case o.uri != "":
		req.Uris = []string{o.uri}
	}
	if o.budgetMinor > 0 || o.maxHops != nil {
		c := &rampv1.RequestConstraints{MaxHops: o.maxHops}
		if o.budgetMinor > 0 {
			// budgetMinor is the test's notion of the cap in cents; the wire
			// PeriodBudget.amount is the canonical decimal STRING in major units
			// (money-as-string). The production handler scales it to 1e8
			// fixed-point internally; here we only render the major-unit string.
			c.PeriodBudget = &rampv1.Cost{Amount: mustMoney(float64(o.budgetMinor) / 100), Currency: "USD"}
		}
		req.Constraints = c
	}
	return req
}

// resolveOverConnect spins up the real Connect+RFC9421 harness for a SIGNED
// caller acting on its own behalf (keyID == requester.id), issues the Resolve
// through the generated client, and returns the server fixture + decoded
// response. Every leg is a genuine protocol round-trip: signing client → RFC
// 9421 signature → httpsig middleware → registered Connect handler → shared
// resolve core → toDiscoveryResponse → typed *rampv1.DiscoveryResponse. The 200-OK
// happy/refusal tests share this setup to avoid duplicated harness wiring.
func resolveOverConnect(t *testing.T, fx *fixture, callerID string, o reqOpts) (*brokerConnectFixture, *rampv1.DiscoveryResponse) {
	t.Helper()
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)
	client := signingBrokerClient(srv.base, srv.server.URL, callerID, priv)
	resp, err := client.Resolve(context.Background(), connect.NewRequest(buildDiscoveryRequest(callerID, o)))
	if err != nil {
		t.Fatalf("Resolve returned transport error: %v", err)
	}
	return srv, resp.Msg
}

// TestResolve_DiscoversRankedOffers pins the R7
// DISCOVERY-ONLY contract: a licensed resolve DISCOVERS and RANKS the
// already-signed Offers and RETURNS them in DiscoveryResponse.offer_groups (winner
// first), and does so WITHOUT executing a transaction, minting a signed URL, or
// recording broker-side spend. The Exchange is the sole executor and biller (at
// ExecuteTransaction time); resolve must not double-bill. Every leg is a
// genuine protocol round-trip (signed Connect client → httpsig → handler →
// resolve core → toDiscoveryResponse → typed DiscoveryResponse).
func TestResolve_DiscoversRankedOffers(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		query:       "RAMP intro",
		budgetMinor: 10000,
	})

	// Licensed-discovery signal: NON-EMPTY offer_groups carrying the ranked signed
	// Offers (best first). The discovery path mints NO signed URL and NO tx id.
	groups := out.GetOfferGroups()
	if len(groups) == 0 {
		t.Fatal("expected non-empty offer_groups (licensed-discovery signal)")
	}
	offers := groups[0].GetOffers()
	if len(offers) == 0 {
		t.Fatal("expected ranked offers in the first offer_group")
	}
	if offers[0].GetOfferId() != "offer-1" {
		t.Errorf("ranked winner offer_id = %q, want %q", offers[0].GetOfferId(), "offer-1")
	}
	if offers[0].GetSignature() == "" {
		t.Error("ranked offer is missing its signature — discovery must return the already-signed Offer")
	}
	// ADR-019: the agent-facing response is PURE canonical typed
	// DiscoveryResponse — zero ramp.broker.* ext smuggle keys.
	assertNoBrokerExt(t, out)
	if srv.exchange.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1", srv.exchange.discoverCalls)
	}
	// R7: resolve retires the broker-authored execute. The Exchange's
	// ExecuteTransaction MUST NOT be called at resolve (it executes/bills at the
	// agent's own ExecuteTransaction) — this is the no-double-billing pin.
	if srv.exchange.executeCalls != 0 {
		t.Errorf("execute calls = %d, want 0 (resolve is discovery-only)", srv.exchange.executeCalls)
	}
	// Usage reporting is an execute-time concern, not a resolve concern.
	if srv.exchange.reportCalls != 0 {
		t.Errorf("report calls = %d, want 0 (resolve does not report usage)", srv.exchange.reportCalls)
	}
}

// TestResolve_NoRampJSON_RefusesNotInCatalog locks in the v1 contract:
// a publisher that does not host /.well-known/ramp.json is refused with
// NOT_IN_CATALOG. The bare-URL fallback that legacy bot-grade fetchers
// relied on has been removed — there is no more "silently accept and
// hand back the bare URL" tolerance.
func TestResolve_NoRampJSON_RefusesNotInCatalog(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "bare.example", unlicensed: true})

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{uri: "https://bare.example/item"})

	wantReason := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
	if got := out.GetAbsenceReason(); got != wantReason {
		t.Errorf("typed absence_reason = %v, want %v", got, wantReason)
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("no transaction should happen: executeCalls = %d", srv.exchange.executeCalls)
	}
}

// TestResolve_RefusalKeepsZeroValuedFieldsOnJSONWire pins the wire-codec half of
// production parity: the harness must emit the SAME JSON shape production does.
// Production wires connectserver.WithEmitUnpopulated so zero-valued response
// fields stay on the JSON wire; a refusal DiscoveryResponse has an EMPTY
// offer_groups, which protojson OMITS by default and RENDERS as "offer_groups":[]
// only under EmitUnpopulated. Driven over the Connect-JSON protocol (the wire the
// codec governs — the gRPC client the other tests use would never surface this),
// so if the harness dropped WithEmitUnpopulated the field would vanish and this
// test would fail. That absent assertion is exactly what let the harness silently
// exercise a different response shape than production.
func TestResolve_RefusalKeepsZeroValuedFieldsOnJSONWire(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "bare.example", unlicensed: true})

	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, "agent-1", pub)
	client, capture := signingBrokerJSONClient(srv.base, srv.server.URL, "agent-1", priv)

	// Refusal path: 200-OK DiscoveryResponse carrying only ver + absence_reason,
	// with empty offer_groups.
	resp, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest("agent-1", reqOpts{uri: "https://bare.example/item"})))
	if err != nil {
		t.Fatalf("Resolve returned transport error: %v", err)
	}
	if got := resp.Msg.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG {
		t.Fatalf("absence_reason = %v, want NOT_IN_CATALOG (refusal path)", got)
	}
	// The load-bearing assertion: the empty offer_groups survives on the JSON wire
	// as an explicit [], proving the EmitUnpopulated codec is active exactly as in
	// production. Without WithEmitUnpopulated the key would be omitted entirely.
	// (The codec emits proto field names, so the wire key is snake_case.)
	if !bytes.Contains(capture.body, []byte(`"offer_groups"`)) {
		t.Fatalf("offer_groups omitted from JSON wire — harness is NOT wiring EmitUnpopulated like production; body=%s", capture.body)
	}
}

func TestResolve_BudgetExhausted(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 1, // deliberately tiny: $0.01 cap vs offer cost $0.10 (1e6 vs 1e7 at 1e8 fixed-point)
	})

	// ADR-019: budget exhaustion is a REFUSAL, surfaced ONLY via the
	// typed DiscoveryResponse.absence_reason below — never via a ramp.broker.error ext
	// key. Assert the contractual ext keys are gone (was: extStringMsg "budget").
	assertNoBrokerExt(t, out)
	// budget-exhausted maps to the TYPED DiscoveryResponse.absence_reason
	// NOT_AUTHORIZED (budgetExhaustedResponse -> pickResolveAbsenceReason ->
	// NOT_AUTHORIZED), asserted instead of the ramp.broker.absence_reason ext.
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Errorf("typed absence_reason = %v, want %v",
			got, rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED)
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("budget-exhausted must not call ExecuteTransaction: got %d", srv.exchange.executeCalls)
	}
}

// TestResolve_BudgetExhausted_Refused is the budget-guard negative path: an
// over-budget resolve is refused before any offer is licensed. The guard keys on
// the authenticated agent identity (always present, never forgeable), so a
// declared budget below the cheapest offer's cost yields a typed refusal. Every
// leg is a genuine protocol round-trip (signed Connect client → httpsig →
// handler → resolve core → toDiscoveryResponse → typed DiscoveryResponse); the
// refusal is observed at that same public surface (typed NOT_AUTHORIZED, empty
// offer_groups, no execute).
func TestResolve_BudgetExhausted_Refused(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 1, // $0.01 cap vs the fixture's $0.10 offer cost — over budget
	})

	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("over-budget resolve must be refused by the identity-keyed guard: "+
			"absence_reason = %v, want NOT_AUTHORIZED", got)
	}
	if groups := out.GetOfferGroups(); len(groups) != 0 {
		t.Errorf("budget-denied resolve must return empty offer_groups, got %d groups", len(groups))
	}
	// Discovery WAS reached (the guard runs after selection); the refusal is a
	// budget denial, not a discovery miss — and no execute fires.
	if srv.exchange.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1 (the budget guard runs post-discovery)", srv.exchange.discoverCalls)
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("budget-denied resolve must not execute: got %d", srv.exchange.executeCalls)
	}
}

// TestResolve_BudgetAccumulatesPerAgent pins the per-agent accumulation D2
// introduces. The guard now calls Budget.Record for the admitted
// winner, so an agent's period counter carries spend ACROSS requests. Three
// resolves share one fixture (one Redis keyspace, one deterministic period):
//
//  1. agent-accum, cap empty  → ALLOWED, records the $0.05 winner.
//  2. agent-accum, same period → REFUSED, because the first consumed the cap
//     (proves Record accumulated across requests, not a per-request check).
//  3. agent-other, same period → ALLOWED, because its counter is keyed on its
//     OWN identity (proves the key is per-agent, not global).
//
// Every leg is a genuine protocol round-trip (signed Connect client → httpsig →
// handler → resolve core → typed DiscoveryResponse); allow/deny is observed at
// that public surface (non-empty offer_groups vs the typed NOT_AUTHORIZED).
func TestResolve_BudgetAccumulatesPerAgent(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	// Single-unit offer at $0.05 so exactly one resolve consumes a $0.05 cap.
	fx.exchange.offerUnitCost = 0.05
	fx.exchange.offerEstimatedQuantity = 1

	// (1) First resolve for agent-accum — cap empty → ALLOWED.
	_, out1 := resolveOverConnect(t, fx, "agent-accum", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 5, // $0.05 cap == one offer
	})
	if len(out1.GetOfferGroups()) == 0 {
		t.Fatalf("first resolve must be ALLOWED against an empty cap: absence_reason = %v",
			out1.GetAbsenceReason())
	}

	// (2) Second resolve, SAME agent + SAME period — the first consumed the cap,
	// so the accumulated counter now refuses this one.
	srv2, out2 := resolveOverConnect(t, fx, "agent-accum", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 5,
	})
	if got := out2.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("second resolve for the SAME agent must be refused — the first consumed the cap and "+
			"Budget.Record carried the spend across requests (per-agent accumulation): absence_reason = %v, "+
			"want NOT_AUTHORIZED", got)
	}
	if len(out2.GetOfferGroups()) != 0 {
		t.Errorf("refused resolve must return empty offer_groups, got %d", len(out2.GetOfferGroups()))
	}
	if srv2.exchange.executeCalls != 0 {
		t.Errorf("budget-denied resolve must not execute: got %d", srv2.exchange.executeCalls)
	}

	// (3) A DIFFERENT agent in the SAME period is unaffected — its counter is
	// keyed on its own identity, so it still sees the licensed offer.
	_, out3 := resolveOverConnect(t, fx, "agent-other", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 5,
	})
	if len(out3.GetOfferGroups()) == 0 {
		t.Fatalf("a DIFFERENT agent must be unaffected by another agent's spend (per-agent key): "+
			"absence_reason = %v", out3.GetAbsenceReason())
	}
}

// TestResolve_ScopeInsufficientRefusal locks the propagation contract
// for the OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT path: when an upstream
// Exchange returns zero offers plus an OfferGroup tagged
// SCOPE_INSUFFICIENT, the Broker surfaces "proof missing" as the error
// vocabulary and MUST NOT call ExecuteTransaction or mint a signed URL.
func TestResolve_ScopeInsufficientRefusal(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	fx.exchange.scopeRestricted = true

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{uri: "https://acme.example/article-42"})

	// ADR-019: the refusal cause rides ONLY on the typed
	// DiscoveryResponse.absence_reason — the free-text ramp.broker.error ext key
	// ("proof missing") is gone (was: extStringMsg "proof missing").
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT {
		t.Errorf("typed absence_reason = %v, want SCOPE_INSUFFICIENT", got)
	}
	assertNoBrokerExt(t, out)
	if srv.exchange.executeCalls != 0 {
		t.Errorf("SCOPE_INSUFFICIENT must not call ExecuteTransaction: got %d", srv.exchange.executeCalls)
	}
}

// TestResolve_NoVerifiedCaller_Unauthenticated pins the self-action invariant:
// an UNSIGNED Resolve (no httpsig context) is rejected with Unauthenticated and
// no upstream side effects fire. brokerConnectSigPredicate lets the unsigned
// /ramp. request through (no Signature-Input), the handler finds no verified
// context, and returns Unauthenticated.
func TestResolve_NoVerifiedCaller_Unauthenticated(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent-1"
	pub, _ := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)

	// PLAIN unsigned client — NOT the signing transport.
	client := rampconnect.NewBrokerServiceClient(srv.server.Client(), srv.server.URL, connect.WithGRPC())

	_, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest(callerID, reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodeUnauthenticated)
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("upstream calls leaked: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_CallerImpersonation_PermissionDenied pins the self-action
// invariant through the REAL httpsig stack: the ATTACKER key is registered in
// the resolver AND the request is SIGNED with it, while the DiscoveryRequest names
// the VICTIM as requester.id. The verified keyID (attacker) != req.AgentID
// (victim) → PermissionDenied, and no upstream side effects fire.
func TestResolve_CallerImpersonation_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const attackerID = "agent-attacker"
	const victimID = "agent-victim"
	attackerPub, attackerPriv := newBrokerKeyPair(t)
	// Seed the resolver with the ATTACKER key (this is who actually signs).
	srv := startBrokerConnectServer(t, fx, attackerID, attackerPub)
	// Sign with the attacker key, but claim to be the victim.
	client := signingBrokerClient(srv.base, srv.server.URL, attackerID, attackerPriv)

	_, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest(victimID, reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodePermissionDenied)
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("impersonation must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_MaxHopsBelowBrokerHopBudget_Rejected pins the RequestConstraints
// max_hops self-cap: a request whose max_hops cannot accommodate the Broker's
// own relay hop is rejected with InvalidArgument before any upstream
// discovery/execute fires. Reverting the enforceHopBudget call in
// validateAndCanonicalizeRequest (or dropping the json:"max_hops" tag) makes this case
// proceed to discovery and the assertion fails — the wiring is exercised end to
// end through a real signed Connect call, not just the isolated enforceHopBudget
// unit.
func TestResolve_MaxHopsBelowBrokerHopBudget_Rejected(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent.example"
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)
	client := signingBrokerClient(srv.base, srv.server.URL, callerID, priv)

	maxHops := int32(0) // 0 < 1 broker relay hop ⇒ the chain is impossible.
	_, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest(callerID, reqOpts{
		query:   "RAMP intro",
		maxHops: &maxHops,
	})))
	assertConnectCodeLocal(t, err, connect.CodeInvalidArgument)
	// ADR-019 §1 obligation: the offending field rides as TYPED
	// ErrorDetail.metadata["field"]=="max_hops", never baked into the message.
	// FAILS on HEAD: enforceHopBudget bakes "max_hops=%d" into the message and
	// attaches no metadata (broker.Error has no Metadata field yet).
	assertBrokerErrorField(t, err, "field", "max_hops")
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("max_hops rejection must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// brokerExtPrefix is the namespace under which the Broker used to smuggle
// non-canonical signals on DiscoveryResponse.ext. ADR-019: the Broker's
// agent-facing response is PURELY the canonical typed DiscoveryResponse — the
// licensed signal is retrieval_endpoint presence, the refusal cause is the typed
// absence_reason, faults are Connect errors carrying a typed ErrorDetail, and
// everything else (offer_id, budget, evaluated candidates) is broker
// selection/billing/audit detail that has no canonical field and is NOT echoed
// to the agent (it lives in the broker's SelectionLog / budget service). So NO
// ramp.broker.* key may appear under ext.
const brokerExtPrefix = "ramp.broker."

// assertNoBrokerExt fails if out carries ANY ramp.broker.* ext key. This is the
// class-level guard: the Broker emits zero ext smuggle keys, current or future.
func assertNoBrokerExt(t *testing.T, out *rampv1.DiscoveryResponse) {
	t.Helper()
	for k := range out.GetExt().GetFields() {
		if strings.HasPrefix(k, brokerExtPrefix) {
			t.Errorf("broker ext key %q must NOT be emitted — the agent-facing response is pure canonical DiscoveryResponse (use the typed surface / SelectionLog): ext=%v",
				k, out.GetExt().GetFields())
		}
	}
}

// TestResolve_NoContractualExtKeys_LicensedFlow pins the ADR-019
// cure on the LICENSED-DISCOVERY path: a successful DiscoveryResponse carries NONE of
// ramp.broker.{licensed,error,absence_reason} — the licensed signal is derived
// from NON-EMPTY offer_groups presence, not from an ext flag or a
// retrieval_endpoint. Every leg is a genuine protocol round-trip (signed Connect
// client → httpsig → handler → resolve core → toDiscoveryResponse → typed
// DiscoveryResponse).
func TestResolve_NoContractualExtKeys_LicensedFlow(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		query:       "RAMP intro",
		budgetMinor: 10000,
	})
	if len(out.GetOfferGroups()) == 0 {
		t.Fatal("expected non-empty offer_groups (licensed-discovery flow) — wrong fixture state")
	}
	assertNoBrokerExt(t, out)
}

// TestResolve_NoContractualExtKeys_RefusalFlow pins the same cure on a REFUSAL
// path: a no-ramp.json refusal carries the typed absence_reason ONLY — none of
// the contractual ext keys (ramp.broker.absence_reason in particular must be
// gone, replaced by the typed DiscoveryResponse.absence_reason field). FAILS on HEAD
// (brokerExt sets ramp.broker.absence_reason), PASSES after the keys are
// dropped.
func TestResolve_NoContractualExtKeys_RefusalFlow(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "bare.example", unlicensed: true})

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{uri: "https://bare.example/item"})
	// The typed refusal-cause surface stays — it is the sole refusal channel now.
	if out.GetAbsenceReason() != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG {
		t.Errorf("typed absence_reason = %v, want NOT_IN_CATALOG", out.GetAbsenceReason())
	}
	assertNoBrokerExt(t, out)
}

// TestResolve_FaultCarriesErrorDetail pins the ADR-019 fault
// contract: a true fault (here an UNSIGNED Resolve → Unauthenticated, the same
// fault path TestResolve_NoVerifiedCaller drives) returns a Connect transport
// error that BOTH has the expected code AND carries a typed *rampv1.ErrorDetail
// with Domain "ramp.v1.BrokerService". On HEAD the broker fault path is a bare
// broker.ToConnect(err) with NO detail attached (broker_connect_handler.go:41-49),
// so the wire error has zero details → assertBrokerErrorDetail fails. PASSES
// after the fault path attaches connect.NewErrorDetail(&rampv1.ErrorDetail{
// Message, Domain:"ramp.v1.BrokerService"}). The detail-decoding helper mirrors
// the exchange suite's assertDenialReason.
func TestResolve_FaultCarriesErrorDetail(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent-1"
	pub, _ := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)

	// PLAIN unsigned client — no httpsig context → Unauthenticated fault.
	client := rampconnect.NewBrokerServiceClient(srv.server.Client(), srv.server.URL, connect.WithGRPC())

	_, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest(callerID, reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodeUnauthenticated)
	assertBrokerErrorDetail(t, err, "ramp.v1.BrokerService")
}
