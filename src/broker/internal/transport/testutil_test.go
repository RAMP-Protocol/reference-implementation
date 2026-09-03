//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"google.golang.org/protobuf/types/known/timestamppb"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/offerkeys"
	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
)

// mustMoney renders a test-authored float amount to the canonical wire decimal
// STRING the proto money fields now carry (money-as-string), matching
// production's FormatMoney semantics (0.10 -> "0.1", 5.0 -> "5", 0 -> "0").
func mustMoney(amount float64) string {
	s, err := helpers.FormatMoney(decimal.NewFromFloat(amount))
	if err != nil {
		panic(err)
	}
	return s
}

// acquireTestDB resets the shared package Postgres to its migrated baseline (see
// TestMain) and returns a fresh pool bound to it. Each test calls it exactly once;
// it delegates to db.AcquireTestDB (once-per-test and serial-execution contract
// documented there).
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

// acquireTestRedis resets the shared package Redis to an empty keyspace (FLUSHDB,
// see TestMain) and returns the shared client. The client is owned by the suite —
// it is NOT closed per test. Each Redis-backed test calls this exactly once.
func acquireTestRedis(tb testing.TB, ctx context.Context) *redis.Client {
	tb.Helper()
	if err := sharedRedis.Reset(ctx); err != nil {
		tb.Fatalf("reset shared redis: %v", err)
	}
	return sharedRedis.Client
}

// -----------------------------------------------------------------------------
// Mock EXA server.

type mockExa struct {
	server *httptest.Server
	domain string
}

func newMockExa(tb testing.TB, resultDomain string) *mockExa {
	m := &mockExa{domain: resultDomain}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"url":"https://`+resultDomain+`/article-42","title":"Example","score":0.9}]}`)
	}))
	tb.Cleanup(m.server.Close)
	return m
}

func (m *mockExa) URL() string { return m.server.URL }

// -----------------------------------------------------------------------------
// Mock Exchange (Connect-Go handler).
//
// Doctrine justification (Testing Doctrine pt 6, documented-fallback): this
// suite tests BROKER-side mechanics — ranking, refusal mapping, budget
// arithmetic, httpsig admission, hop-budget caps, fan-out routing, batch
// merge/back-fill/aggregation, replay pass-through, audit, and error-envelope
// shape. The Exchange here is a controllable upstream STUB whose responses are
// fixtures, not the system under test: its knobs (failExecute, omitOfferIDs,
// denyOfferIDs, offerRate distinct from unit cost, scopeRestricted, ...) force
// broker branches a real Exchange cannot be coerced into deterministically.
// Anything that is genuinely an Exchange CONTRACT (discovery→ranking against
// real offers, execute happy path, idempotency replay) is covered against the
// REAL Exchange by the Docker e2e harness under tests/e2e/harness/; the one
// broker test whose purpose was offer VERIFICATION (meaningless against a
// stub) already lives there.

type mockExchange struct {
	// The embedded Unimplemented base absorbs RPCs the broker relay never
	// exercises (they answer CodeUnimplemented), exactly as the production
	// ExchangeHandler embeds it — a new proto RPC must not break this stub.
	rampv1connect.UnimplementedExchangeServiceHandler

	mu            sync.Mutex
	discoverCalls int
	executeCalls  int
	reportCalls   int
	// healthzStatus is what this Exchange's /healthz answers. Zero means 200:
	// an Exchange is up unless a test says otherwise. A test flips it to take
	// the Exchange down and back up while the broker keeps running, which is
	// what the registry health refresher reads through the wire.
	healthzStatus int
	// healthzProbes counts the /healthz requests that arrived. It is how a test
	// asserts an Exchange was NOT probed at all -- a BLOCKED Exchange must
	// receive no traffic from the broker, health checks included.
	healthzProbes int
	// lastDiscoverRequesterID is the requester.id the broker actually FORWARDED on
	// the most recent discover. The broker canonicalizes req.AgentID and writes it
	// back onto the request, so this is where a test observes that the value which
	// travelled upstream is the identity rather than the caller's spelling.
	lastDiscoverRequesterID string
	// domain is this Exchange's own published identity: the value it signs into
	// the offers it issues, the recipient it answers to, and the domain its
	// registry row carries. Empty means mockExchangeDomain, which is what the
	// single-exchange fixtures use; a fixture wiring a SECOND exchange gives that
	// one its own, so a fan-out leg addressed to the wrong sibling is refused
	// rather than served.
	domain string
	// lastDiscoverExchange is the recipient the most recent discover leg named.
	// The Broker authors each leg, so this is where a test observes that the leg
	// which arrived here says it was meant for here.
	lastDiscoverExchange string
	offerUnitCost        float64
	// offerRate, when > 0, sets the discovered offer's Pricing.rate to a value
	// DISTINCT from its unit_cost (which always comes from offerUnitCost). The
	// real Exchange normalises a provider's per-model rate into a per-unit
	// unit_cost, so the two diverge whenever the provider's pricing model is not
	// already per-unit in the base currency (catalog_pricing.go falls back
	// unit_cost<-rate ONLY when the term omits unit_cost — i.e. they coincide
	// only in the masked-today case). The money source-of-truth split needs rate != unit_cost to expose
	// that the broker budget gate reads the wrong field; this knob is the minimal
	// public-surface extension that produces such an offer. When 0 the offer's
	// rate falls back to unit_cost, so every existing single-cost suite (which
	// leaves this field unset) keeps rate == unit_cost and reads unchanged.
	offerRate float64
	signedURL string
	// scopeRestricted makes DiscoverResources return an empty Offers slice
	// plus an OfferGroup with OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT, the
	// shape an Exchange uses to advertise a resource the caller's scopes
	// don't cover.
	scopeRestricted bool
	// discoveryMethod is the method the mock reports on every OfferGroup it
	// returns. It defaults to EXCHANGE in mockOfferGroup, matching the real
	// Exchange; a test sets it to another value to prove the Broker IGNORES what
	// the exchange reported and states its own, which is the contract on the
	// Resolve path.
	discoveryMethod rampv1.DiscoveryMethod
	// rejectURILessQuery makes DiscoverResources refuse a ResourceQuery carrying
	// no uris, which is what the REAL Exchange does ("at least one uri
	// required"). It is opt-in and defaults false because this mock has always
	// answered a uri-less query, and the free-text-query suites are built on
	// that: turning it on globally would rewrite what sixteen pre-existing tests
	// exercise. A test sets it when the behaviour under test is what the Broker
	// does against a COMPLIANT Exchange — today, on the query path, that is
	// producing no groups at all.
	rejectURILessQuery bool
	// offerEstimatedQuantity, when > 0, is set as the offer's
	// Pricing.EstimatedQuantity. The Broker relay echoes this value as
	// Usage.ConsumedQuantity on the synthesised UsageReport so tests can
	// pin that the relay actually populated the payload.
	offerEstimatedQuantity int32
	// lastReport captures the most-recent UsageReport seen by ReportUsage so
	// tests can assert the full payload (e.g. Usage.ConsumedQuantity is what
	// the broker relay populated). Without this, a finger-counter on
	// reportCalls cannot pin the contract.
	lastReport *rampv1.UsageReport
	// lastExecute captures the most-recent TransactionRequest seen by
	// ExecuteTransaction so tests can assert the broker relayed the FULL signed
	// Offer (reflected), not just an id+signature.
	lastExecute *rampv1.TransactionRequest
	// denyOfferIDs, when an item's offer_id is present here, makes the batch
	// ExecuteTransaction return that item as a per-item denial (denial_reason
	// SIGNATURE_INVALID) instead of a success — so a broker batch test can
	// exercise a mixed (partial-failure) per-exchange response.
	denyOfferIDs map[string]bool
	// failExecute, when true, makes ExecuteTransaction fail the whole call with a
	// CodeUnavailable error (no items[] response) — the broker's xclient surfaces
	// this as a transport-level err, exercising fanOutBatch's whole-group
	// CONTENT_UNAVAILABLE synthesis (collectGroupDenials).
	failExecute bool
	// omitOfferIDs, when an item's offer_id is present here, makes batchResponse
	// DROP that item from the returned items[] — the exchange answers 200 but with
	// fewer items than it was sent, exercising mergeBatchResults' back-fill of the
	// missing offer_id with a CONTENT_UNAVAILABLE denial.
	omitOfferIDs map[string]bool
	// itemCostAmount / itemCostCurrency, when itemCostCurrency != "", make
	// batchResponse stamp a per-item TransactionResultItem.Cost (exact decimal
	// amount, ISO-4217 currency) on every NON-denied item, AND emit a per-group
	// TransactionResponse.TotalCost = (amount * non-denied item count) in that
	// currency. This is the per-group subtotal the broker's fanOutBatch must
	// aggregate across exchanges — without it the broker aggregate is not
	// observable through the relay HTTP surface (Testing Doctrine 9: no
	// internal-state peeking). itemCostAmount is the per-item charge.
	itemCostAmount   float64
	itemCostCurrency string
	// offerID / offerCanonicalURL, when set, override the DiscoverResources
	// offer identity so a MULTI-URI / MULTI-EXCHANGE resolve can surface a
	// DISTINCT offer per exchange (distinct offer_id + distinct canonical_url,
	// the latter keeping each offer in its own selection.Dedup identity bucket).
	// Empty fields fall back to the legacy single-exchange defaults
	// ("offer-1" / "https://acme.example/article-42") so the existing
	// single-exchange suites read unchanged.
	offerID           string
	offerCanonicalURL string

	// offerSigningKey, when non-nil, makes DiscoverResources emit TWO genuinely
	// Exchange-signed offers (both signed with offerSigningKey via
	// helpers.SignOffer): id=validOfferID and id=rejectedOfferID. Both carry a
	// real signature and a fresh expiry — the drop that a verification test
	// exercises is decided by the injected broker Deps.OfferVerifier (which id it
	// rejects), NOT by a doctored signature, so no test mocks the Exchange's
	// verification (Testing Doctrine pt 6). When offerSigningKey is nil,
	// DiscoverResources returns the legacy single-offer "sig-x" shape so every
	// existing test keeps passing unchanged.
	offerSigningKey ed25519.PrivateKey
	offerSigningPub ed25519.PublicKey
}

// mockOfferGroup builds an OfferGroup the way the REAL Exchange does
// (service/discover.go newOfferGroup): the uri plus the discovery method, which
// the Exchange states on every group it emits. method is the mock's configured
// value; UNSPECIFIED means "behave like the real Exchange" and yields EXCHANGE.
// Every group this mock returns goes through here, so the METHOD cannot drift
// from the producer it stands in for. Other parts of the shape do differ — the
// real Exchange returns one group per requested URI and this mock returns one
// for uris[0] — so this is not a general fidelity guarantee.
//
// groupURIFor resolves that single URI: the first requested one, or fallback for
// the suites that drive this mock with no URIs at all. It lives beside the
// builder because all three return paths need the same resolution and had a copy
// of it each.
func groupURIFor(req *connect.Request[rampv1.ResourceQuery], fallback string) string {
	if uris := req.Msg.GetUris(); len(uris) > 0 {
		return uris[0]
	}
	return fallback
}

func mockOfferGroup(uri string, method rampv1.DiscoveryMethod) *rampv1.OfferGroup {
	if method == rampv1.DiscoveryMethod_DISCOVERY_METHOD_UNSPECIFIED {
		method = rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE
	}
	return &rampv1.OfferGroup{Uri: uri, DiscoveryMethod: method.Enum()}
}

func (m *mockExchange) DiscoverResources(_ context.Context, req *connect.Request[rampv1.ResourceQuery]) (*connect.Response[rampv1.ResourceResponse], error) {
	m.mu.Lock()
	m.discoverCalls++
	m.lastDiscoverRequesterID = req.Msg.GetRequester().GetId()
	m.lastDiscoverExchange = req.Msg.GetExchange()
	cost := m.offerUnitCost
	rate := m.offerRate
	scopeRestricted := m.scopeRestricted
	signingKey := m.offerSigningKey
	method := m.discoveryMethod
	rejectURILess := m.rejectURILessQuery
	m.mu.Unlock()
	// Mirrors the real Exchange's first validation: a ResourceQuery must name at
	// least one uri (src/exchange/internal/service/exchange.go). Opt-in — see the
	// field's comment for why this mock answers a uri-less query by default.
	if rejectURILess && len(req.Msg.GetUris()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at least one uri required"))
	}
	if scopeRestricted {
		group := mockOfferGroup(groupURIFor(req, "https://acme.example/article-42"), method)
		group.AbsenceReason = rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT.Enum()
		return connect.NewResponse(&rampv1.ResourceResponse{
			Ver:         helpers.ProtocolVersion,
			OfferGroups: []*rampv1.OfferGroup{group},
		}), nil
	}
	costStr := mustMoney(cost)
	// rate defaults to unit_cost (the masked-today coincidence) unless the test
	// set offerRate to force the divergence the money source-of-truth split turns on.
	rateStr := costStr
	if rate > 0 {
		rateStr = mustMoney(rate)
	}
	unit := "accesses"
	pricing := &rampv1.Pricing{
		Rate:     rateStr,
		Currency: "USD",
		UnitCost: &costStr,
		// R7: the discovered Offer now rides on the agent-facing DiscoveryResponse
		// (offer_groups), so it must satisfy the proto's Offer validation rules
		// (pricing.model and identity.resource_mutability must be set, not the
		// zero/UNSPECIFIED enum). Before R7 the offer was consumed into a tx and
		// never serialized, so these fields were never validated. PER_UNIT
		// requires Pricing.unit (mirrors the Exchange's seedPricedTermEst fixture).
		Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
		Unit:  &unit,
	}
	if est := m.offerEstimatedQuantity; est > 0 {
		pricing.EstimatedQuantity = &est
	}
	url := "https://acme.example/article-42"
	if m.offerCanonicalURL != "" {
		url = m.offerCanonicalURL
	}
	offerID := "offer-1"
	if m.offerID != "" {
		offerID = m.offerID
	}
	offer := &rampv1.Offer{
		OfferId:            offerID,
		Pricing:            pricing,
		DeliveryMethod:     rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		Signature:          "sig-x",
		SignatureAlgorithm: "EdDSA",
		// Exchange (field 8) is the Exchange's canonical domain, signed into the
		// offer (the execute-routing target). The Exchange producer
		// sets this in buildOffer before SignOffer; the mock stands in for that
		// producer with the same domain its own registry row carries.
		Exchange: m.identity(),
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl:       &url,
			ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
		},
		Reporting: &rampv1.ReportingObligation{Required: true},
		// Terms is the full licensing payload — the broker must forward it verbatim
		// in DiscoveryResponse.offer_groups (no lossy re-type). A non-empty Terms
		// makes the verbatim-forward assertion non-vacuous.
		Terms: []*rampv1.LicenseTerm{{
			// Semantics is publisher/catalog-provided data: the REAL Exchange's
			// seedPricedTerm fixture sets TERM_SEMANTICS_ENUMERATED, and the proto's
			// LicenseTerm.semantics {not_in:[0]} rule is now enforced when the broker
			// serializes offer_groups in its DiscoveryResponse. The mock stands in for
			// the Exchange producer, so it mirrors that fixture (matching the
			// ResourceMutability:STATIC mirror above) — an unset semantics here is a
			// stale mock, not a broker-production gap (the broker forwards terms
			// verbatim and never derives semantics).
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Scopes:    []string{"ai-training"},
			Pricing:   pricing,
		}},
	}

	// Offer-verification test mode: when offerSigningKey is set, return TWO
	// genuinely Exchange-signed offers (validOfferID and rejectedOfferID), both
	// carrying a real signature and a fresh expiry. The broker's drop-wiring is
	// then exercised by injecting a Deps.OfferVerifier that rejects one id — the
	// verify/reject DECISION is mocked (a legitimate broker seam), the Exchange is
	// not (Testing Doctrine pt 6). When signingKey is nil, fall through to the
	// legacy single-offer path so every existing test stays green.
	if signingKey != nil {
		// Build the valid offer.
		validOffer := &rampv1.Offer{
			OfferId:            validOfferID,
			Pricing:            pricing,
			DeliveryMethod:     rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
			SignatureAlgorithm: helpers.OfferSignatureAlgorithm,
			Exchange:           m.identity(),
			// The SDK Verifier is fail-closed on freshness (a missing or past
			// expires_at is EXPIRED), so mint a real future bound covered by the
			// signature — otherwise even the genuine offer is rejected.
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			Identity: &rampv1.ResourceIdentity{
				CanonicalUrl:       &url,
				ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
			},
			Reporting: &rampv1.ReportingObligation{Required: true},
			Terms: []*rampv1.LicenseTerm{{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Scopes:    []string{"ai-training"},
				Pricing:   pricing,
			}},
		}
		validSig, err := helpers.SignOffer(signingKey, validOffer)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				errors.New("mockExchange: sign valid offer: "+err.Error()))
		}
		validOffer.Signature = validSig

		// Build the SECOND offer: same shape, a distinct id + canonical_url so the
		// broker keeps it in its own identity bucket, and a GENUINE Exchange
		// signature (both offers are validly signed). Whether it reaches
		// offer_groups is decided by the injected Deps.OfferVerifier, not by any
		// signature defect.
		secondCanonicalURL := "https://acme.example/article-rejected"
		secondOffer := &rampv1.Offer{
			OfferId:            rejectedOfferID,
			Pricing:            pricing,
			DeliveryMethod:     rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
			SignatureAlgorithm: helpers.OfferSignatureAlgorithm,
			Exchange:           m.identity(),
			ExpiresAt:          timestamppb.New(time.Now().Add(time.Hour)),
			Identity: &rampv1.ResourceIdentity{
				CanonicalUrl:       &secondCanonicalURL,
				ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
			},
			Reporting: &rampv1.ReportingObligation{Required: true},
			Terms: []*rampv1.LicenseTerm{{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Scopes:    []string{"ai-training"},
				Pricing:   pricing,
			}},
		}
		secondSig, err := helpers.SignOffer(signingKey, secondOffer)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				errors.New("mockExchange: sign second offer: "+err.Error()))
		}
		secondOffer.Signature = secondSig

		group := mockOfferGroup(groupURIFor(req, url), method)
		group.Offers = []*rampv1.Offer{validOffer, secondOffer}
		return connect.NewResponse(&rampv1.ResourceResponse{
			Ver:         helpers.ProtocolVersion,
			Offers:      []*rampv1.Offer{validOffer, secondOffer},
			OfferGroups: []*rampv1.OfferGroup{group},
		}), nil
	}

	// Mirror the REAL Exchange (service/discover.go): a hit returns ONE OfferGroup
	// per requested uri, keyed on OfferGroup.Uri, AND the flat Offers aggregate.
	// The broker now MERGES per-URI OfferGroups (resolve.go discoverOffers), so the
	// group MUST be keyed on the requested uri for the merge to surface it. A
	// query carrying no uris (the EXA-query suites) keys the group on the offer's
	// own canonical_url so a single-group response is still produced.
	//
	// The Exchange-facing leg (ResourceResponse) is otherwise UNAFFECTED by the
	// agent<->broker DiscoveryRequest/DiscoveryResponse rename: the broker reads
	// resp.GetOffers() (and, post per-URL fan-out, resp.GetOfferGroups()) from the
	// Exchange exactly as before.
	group := mockOfferGroup(groupURIFor(req, url), method)
	group.Offers = []*rampv1.Offer{offer}
	return connect.NewResponse(&rampv1.ResourceResponse{
		Ver:         helpers.ProtocolVersion,
		Offers:      []*rampv1.Offer{offer},
		OfferGroups: []*rampv1.OfferGroup{group},
	}), nil
}

// mockExchangeDomain is the canonical Exchange domain the mock Exchange signs
// into Offer.exchange (field 8) and that the registry row in newFixture carries.
// The discovery test asserts the broker forwards this verbatim, and the relay
// test routes execute to it via the signed-domain mechanism (no endpoint header).
const mockExchangeDomain = "mp.acme.example"

// identity is the Exchange this mock stands for. Every place that needs the
// value reads it here, so a fixture that gives a second exchange its own domain
// moves the offers it signs and the recipient it accepts together.
func (m *mockExchange) identity() string {
	if m.domain == "" {
		return mockExchangeDomain
	}
	return m.domain
}

// setHealthz takes this Exchange up or down for the health refresher by setting
// the status its /healthz answers. Safe to call while the broker is running:
// the refresher reads it over HTTP on its next pass.
func (m *mockExchange) setHealthz(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthzStatus = status
}

// healthzProbeCount reports how many /healthz requests reached this Exchange.
func (m *mockExchange) healthzProbeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthzProbes
}

// serveHealthz answers the liveness probe the registry health refresher sends,
// recording that it arrived. Unset healthzStatus answers 200.
func (m *mockExchange) serveHealthz(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	m.healthzProbes++
	status := m.healthzStatus
	m.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func (m *mockExchange) ExecuteTransaction(_ context.Context, req *connect.Request[rampv1.TransactionRequest]) (*connect.Response[rampv1.TransactionResponse], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeCalls++
	m.lastExecute = req.Msg
	// Whole-call failure: surface a transport-class error so the broker relay
	// treats this exchange's entire group as unreachable (collectGroupDenials).
	if m.failExecute {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("mockExchange: simulated upstream unavailable"))
	}
	// Batch mode: respond with one TransactionResultItem per inbound item,
	// mirroring the real Exchange's first-class items[] path. Each item gets its
	// own signed retrieval endpoint unless its offer_id is in denyOfferIDs, in
	// which case it comes back as an in-body per-item denial (non-atomic).
	if items := req.Msg.GetItems(); len(items) > 0 {
		return connect.NewResponse(m.batchResponse(req.Msg.GetIdempotencyKey(), items)), nil
	}
	// Items-only: the broker always relays items[]; a no-items request is
	// a contract violation the broker's empty-items guard rejects upstream, so the
	// downstream Exchange never sees one. (Single-offer mode + its top-level
	// TransactionResponse result fields were removed in C5.)
	return nil, connect.NewError(connect.CodeInvalidArgument,
		errors.New("mockExchange: ExecuteTransaction requires items[] (single-offer mode removed)"))
}

// batchResponse builds a TransactionResponse.items[] mirroring the real
// Exchange's first-class batch path: one TransactionResultItem per inbound
// item, each with its own signed retrieval endpoint, except offer_ids listed in
// denyOfferIDs which come back as in-body per-item denials. The signed URL
// carries the offer_id so a multi-exchange test can attribute each item to the
// exchange that minted it. Caller holds m.mu.
func (m *mockExchange) batchResponse(idem string, items []*rampv1.TransactionItem) *rampv1.TransactionResponse {
	results := make([]*rampv1.TransactionResultItem, 0, len(items))
	groupTotal := decimal.Zero
	for _, it := range items {
		offerID := it.GetOffer().GetOfferId()
		if m.omitOfferIDs[offerID] {
			// Exchange returns fewer items than sent: drop this one entirely.
			continue
		}
		if m.denyOfferIDs[offerID] {
			reason := rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID
			results = append(results, &rampv1.TransactionResultItem{
				OfferId:      offerID,
				DenialReason: &reason,
			})
			continue
		}
		txID := "tx-" + idem + ":" + offerID
		billID := "bill-" + idem + ":" + offerID
		endpoint := m.signedURL + "&offer=" + offerID
		result := &rampv1.TransactionResultItem{
			OfferId:           offerID,
			TransactionId:     txID,
			BillingId:         billID,
			RetrievalEndpoint: &endpoint,
		}
		// Per-item Cost: an exact decimal charge in this exchange's currency,
		// authoritative per the Core Invariant (items[].cost is the source of
		// truth). The per-group TotalCost is the exact decimal sum of these.
		if m.itemCostCurrency != "" {
			result.Cost = &rampv1.Cost{
				Amount:   mustMoney(m.itemCostAmount),
				Currency: m.itemCostCurrency,
			}
			groupTotal = groupTotal.Add(decimal.NewFromFloat(m.itemCostAmount))
		}
		results = append(results, result)
	}
	resp := &rampv1.TransactionResponse{Ver: helpers.ProtocolVersion, Items: results}
	if m.itemCostCurrency != "" {
		resp.TotalCost = &rampv1.Cost{
			Amount:   mustMoney(groupTotal.InexactFloat64()),
			Currency: m.itemCostCurrency,
		}
	}
	return resp
}

func (m *mockExchange) ReportUsage(_ context.Context, req *connect.Request[rampv1.UsageReport]) (*connect.Response[rampv1.UsageReportResponse], error) {
	m.mu.Lock()
	m.reportCalls++
	m.lastReport = req.Msg
	m.mu.Unlock()
	return connect.NewResponse(&rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-" + req.Msg.GetIdempotencyKey()}), nil
}

// fakeEndpointResolver stands in for resolvers.WellKnownEndpointResolver in the
// broker integration tests: it maps a registered exchange DOMAIN to the mock
// Exchange's loopback URL exactly as the exchange's own /.well-known/ramp.json
// would. The production broker now resolves discovery endpoints via well-known
// (Deps.Endpoints), with the registry a trust allowlist only — so the fixture
// supplies the endpoint here, NOT via the registry's Endpoint column. An
// unmapped domain returns resolvers.ErrNoEndpoint, the same not-advertised signal
// the real resolver raises (so a URL routed to it falls to typed-absence).
type fakeEndpointResolver struct {
	byDomain map[string]string
}

func (f *fakeEndpointResolver) ResolveEndpoint(_ context.Context, domain string) (string, error) {
	if u, ok := f.byDomain[domain]; ok {
		return u, nil
	}
	return "", resolvers.ErrNoEndpoint
}

// startMockExchange serves the mock Exchange stub over loopback HTTP. See the
// doctrine justification on mockExchange: broker-side mechanics are under
// test here; real-Exchange contract coverage lives in tests/e2e/harness/.
func startMockExchange(tb testing.TB, m *mockExchange) string {
	tb.Helper()
	mux := http.NewServeMux()
	// Behind the recipient check, keyed to this Exchange's own identity — a real
	// Exchange mounts the same interceptor. Without it the Broker could stamp
	// its own domain on every leg, or the first exchange's domain on all of
	// them, and the whole suite would still pass.
	// A real Exchange serves through the canonical codec, so this stand-in does
	// too — otherwise the Broker's decode is only ever exercised against the
	// camelCase alias no Exchange puts on the wire.
	path, h := rampv1connect.NewExchangeServiceHandler(m,
		connect.WithInterceptors(audiencetest.MustInterceptor(tb, m.identity())),
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	mux.Handle(path, h)
	// The liveness probe the broker's registry health refresher polls. A real
	// Exchange mounts this route in its own composition root (the handler is
	// healthzHandler in src/exchange/cmd/server/probes.go; internal/runhttp
	// supplies only ProbeHealthz, the client half the healthcheck subcommand
	// runs). The stub must serve it too — without it every mock Exchange
	// answers 404 and the refresher reads the whole suite as permanently down.
	mux.HandleFunc("GET /healthz", m.serveHealthz)
	srv := httptest.NewServer(mux)
	tb.Cleanup(srv.Close)
	return srv.URL
}

// startProviderFixture serves a /.well-known/ramp.json pointing at the given
// Exchange endpoint. Returns the provider's domain.
func startProviderFixture(tb testing.TB, exchangeEndpoint string) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"ver":"1.0","role":"ROLE_PUBLISHER","domain":"acme.example","exchanges":[{"domain":"mp.acme.example","endpoint":"`+exchangeEndpoint+`","relationship":"PROVIDER_RELATIONSHIP_DIRECT"}],"supported_profiles":["ramp-news-v1"]}`)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// startProviderFixtureFor serves a /.well-known/ramp.json for an ARBITRARY
// publisher domain that names an ARBITRARY exchange domain at the given
// endpoint. It generalises startProviderFixture (which hardcodes
// acme.example / mp.acme.example) for the multi-publisher resolve fixture: the
// second provider must advertise its OWN domain + its OWN exchange so the
// broker's buildRoutePlan routes the second URI to the second exchange,
// producing a SECOND OfferGroup distinct from the first.
func startProviderFixtureFor(tb testing.TB, providerDomain, exchangeDomain, exchangeEndpoint string) *httptest.Server {
	tb.Helper()
	body := `{"ver":"1.0","role":"ROLE_PUBLISHER","domain":"` + providerDomain +
		`","exchanges":[{"domain":"` + exchangeDomain + `","endpoint":"` + exchangeEndpoint +
		`","relationship":"PROVIDER_RELATIONSHIP_DIRECT"}],"supported_profiles":["ramp-news-v1"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// noRampProvider serves 404 for /.well-known/ramp.json — used for bare-URL test.
func startUnlicensedProvider(tb testing.TB) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// rewritingHTTPClient maps probes for arbitrary domains onto a loopback address
// so tests can exercise the real fetch path.
type rewritingHTTPClient struct {
	targets map[string]string // domain -> base URL
}

func (c *rewritingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if base, ok := c.targets[strings.ToLower(req.URL.Host)]; ok {
		u := base + req.URL.Path
		if req.URL.RawQuery != "" {
			u += "?" + req.URL.RawQuery
		}
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, u, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// fixtureOfferVerifier is the per-fixture offer-verification seam. When the mock
// exchange is ARMED with an offer-signing key (the offer-verification tests), it
// verifies STRICTLY via the SDK Verifier, resolving the exchange's key through
// the PRODUCTION offerkeys.Resolver — which FETCHES the exchange's WBA directory
// (FetchWBA + ActiveKeyWithExpiry) exactly as production newOfferVerifier does,
// never an injected key. When unarmed it surfaces offers under mode Off so the
// legacy 'sig-x' fixtures stay green. The armed-key check reads the mock's pub at
// Sort time only to SELECT the mode (Strict vs Off); the key itself is resolved
// from the served directory, so a broken WBA-fetch path drops the valid offer.
type fixtureOfferVerifier struct {
	ex       *mockExchange
	resolver *offerkeys.Resolver
}

func (v fixtureOfferVerifier) Sort(ctx context.Context, offers []*rampv1.Offer) core.Result {
	v.ex.mu.Lock()
	pub := v.ex.offerSigningPub
	v.ex.mu.Unlock()
	if pub == nil {
		return core.NewVerifier(core.Off, nil, time.Now).Sort(ctx, offers)
	}
	return core.NewVerifier(core.Strict, v.resolver, time.Now).Sort(ctx, offers)
}

// assertRelayAudit fails unless the captured relay audit carries want as an
// outcome. The record is the operator's only view of a relay refusal — the
// agent gets a status code and a message, and neither says which endpoint the
// broker declined — so the action is asserted as behavior, not treated as
// incidental output.
func assertRelayAudit(t *testing.T, logs, want string) {
	t.Helper()
	if !strings.Contains(logs, `"outcome":"`+want+`"`) {
		t.Errorf("no relay audit record with outcome %q; got: %s", want, logs)
	}
}

// assertNoRelayAudit fails if the captured relay audit carries the outcome.
// It is how a test pins that two different refusals are recorded apart: an
// outage must not land under REJECTED_ENDPOINT, which records an address the
// operator never authorized and is the shape an SSRF attempt takes. Without
// this clause a route that answered correctly on the wire but filed the wrong
// action would still pass.
func assertNoRelayAudit(t *testing.T, logs, unwanted string) {
	t.Helper()
	if strings.Contains(logs, `"outcome":"`+unwanted+`"`) {
		t.Errorf("relay audit recorded outcome %q, which names the wrong kind of "+
			"refusal for this rejection; got: %s", unwanted, logs)
	}
}
