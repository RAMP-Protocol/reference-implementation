//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// Core invariant (the principle this test protects):
//   The realistic canonical publisher feed fixture — three EUR resources whose terms span
//   FREE/PER_UNIT/FLAT pricing, an attribution obligation, daily quotas, geography
//   and user-type restrictions, and a subscription-gated REFERENCE_ONLY term —
//   round-trips intact through the INGESTION surface. Each entry pushed via
//   CatalogService.PushResources is observable, term-for-term proto-equal, through
//   the public CatalogService→ExchangeService read surface DiscoverResources →
//   Offer.terms, with NO agent-agency and NO billing dependency (billing fires
//   only at ExecuteTransaction/consume, so EUR pricing is fine at ingest+discover).
//
// Every assertion below drives behaviour through the OUTERMOST public surface
// (PushResources to write, DiscoverResources to read) and asserts back through
// that SAME surface. No DB / sqlc Querier / raw SQL / Redis is read or written to
// arrange or observe (Testing Doctrine pt 9). The terms[] expectation is produced
// by the PRODUCTION ingest pipeline (ingest.ParseJSONL + MapRecords),
// the same mapper+Normalize the real feed flows through, so a regression in either
// the mapper or the Discover projection breaks the proto.Equal comparison.

// canonicalFeedFixture parses the committed canonical publisher feed fixture through the
// PRODUCTION ingest pipeline (ParseJSONL → MapRecords). It returns the parsed
// records (for their paths) and the proto-exact, Normalize-canonicalized entries
// the catalog must accept. The mapper runs the SAME Normalize the PushResources
// handler runs, so the returned terms are exactly what a faithful round-trip must
// project back.
func canonicalFeedFixture(t *testing.T) ([]ingest.Record, []*rampv1.ResourceEntry) {
	t.Helper()
	feed, err := os.Open(feedFixturePath(t))
	if err != nil {
		t.Fatalf("open canonical feed: %v", err)
	}
	defer func() { _ = feed.Close() }()
	records, err := ingest.ParseJSONL(feed)
	if err != nil {
		t.Fatalf("parse canonical feed: %v", err)
	}
	entries, err := ingest.MapRecords(records)
	if err != nil {
		t.Fatalf("map canonical feed: %v", err)
	}
	if len(records) != len(entries) {
		t.Fatalf("records/entries length mismatch: %d vs %d", len(records), len(entries))
	}
	return records, entries
}

// pushCanonicalContributor registers a freshly-generated catalog contributor for
// the canonical feed's publisher domain (both auth gates) and seeds that tenant,
// returning the signing catalog client, the contributor kid, and the owning tenant
// id. It deliberately generates its own keypair rather than reading any committed
// key file, so the test stands alone regardless of fixture-key churn.
func pushCanonicalContributor(t *testing.T, h *pushHarness) (client rampconnect.CatalogServiceClient, kid, tenantID string) {
	t.Helper()
	kid = "publisher-contributor.example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen contributor key: %v", err)
	}
	h.publishAgent(t, kid, pub)                     // Gate 1: kid -> pubkey via ramp.json self-signup
	h.publishPublisher(t, canonicalFeedDomain, kid) // Gate 2: kid listed as contributor in publisher manifest
	tenantID = seedTenantForDomain(t, h, canonicalFeedDomain)
	return h.signedCat(kid, priv), kid, tenantID
}

// pushCanonicalEntry pushes a single mapped canonical entry under the publisher
// tenant via the public PushResources RPC and asserts it was accepted (1/0). It is
// the per-entry write leg shared by every sub-test below; the entries already
// carry their own (domain, path) from the feed.
func pushCanonicalEntry(t *testing.T, h *pushHarness, client rampconnect.CatalogServiceClient, kid, tenantID string, entry *rampv1.ResourceEntry) {
	t.Helper()
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: tenantID,
		CallerId: kid,
		Entries:  []*rampv1.ResourceEntry{entry},
	}))
	if err != nil {
		t.Fatalf("push %s%s: %v", entry.GetDomain(), entry.GetPath(), err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("push %s%s: accepted=%d rejected=%d, want 1/0",
			entry.GetDomain(), entry.GetPath(), resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
}

// findTerm returns the single discovered term proto-equal to want, failing the
// test if no discovered term matches. It compares against the production-mapped
// expectation (mapper + Normalize), so the match proves the full canonical shape
// — pricing, restrictions, quotas, obligations, scopes — survived the round-trip.
func findTerm(t *testing.T, got []*rampv1.LicenseTerm, want *rampv1.LicenseTerm) *rampv1.LicenseTerm {
	t.Helper()
	for _, g := range got {
		if proto.Equal(g, want) {
			return g
		}
	}
	t.Fatalf("no discovered term equals the expected canonical term:\nwant = %v\ngot  = %v", want, got)
	return nil
}

const canonicalFeedDomain = "publisher.example"

// TestCanonicalFeed_PerUnitQuotaRoundTrip drives the FIRST canonical entry
// (photosynthesis) through PushResources → DiscoverResources and asserts its
// commercial PER_UNIT term — EUR, unit=accesses, rate 0.02, with a daily 1000
// accesses quota and FUNCTION/USER_TYPE/GEOGRAPHY restrictions — round-trips
// proto-exact. A commercial DE requester declaring ai-input is the projection key.
func TestCanonicalFeed_PerUnitQuotaRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	records, entries := canonicalFeedFixture(t)
	client, kid, tenantID := pushCanonicalContributor(t, h)
	pushCanonicalEntry(t, h, client, kid, tenantID, entries[0])

	// entries[0].Terms[1] is the commercial PER_UNIT EUR term with the quota.
	wantTerm := entries[0].GetTerms()[1]
	uri := "https://" + canonicalFeedDomain + records[0].Path
	req := requesterWithExt("agent-commercial-de", "commercial_entity", "DE", "ai-input")
	got := discoverTermsAs(t, h, uri, req)

	term := findTerm(t, got, wantTerm)

	// Pin the canonical PER_UNIT-with-quota shape explicitly (beyond proto.Equal)
	// so a reader sees what "per-unit EUR pricing with quotas" means concretely.
	p := term.GetPricing()
	if p.GetModel() != rampv1.PricingModel_PRICING_MODEL_PER_UNIT {
		t.Errorf("pricing model = %v, want PER_UNIT", p.GetModel())
	}
	if p.GetCurrency() != "EUR" {
		t.Errorf("currency = %q, want EUR", p.GetCurrency())
	}
	if p.GetRate() != "0.02" {
		t.Errorf("rate = %q, want %q", p.GetRate(), "0.02")
	}
	if p.GetUnit() != pricingunits.Accesses {
		t.Errorf("unit = %q, want %q", p.GetUnit(), pricingunits.Accesses)
	}
	if len(term.GetQuotas()) != 1 {
		t.Fatalf("quotas = %d, want 1", len(term.GetQuotas()))
	}
	q := term.GetQuotas()[0]
	if q.GetLimit() != 1000 || q.GetWindow() != rampv1.QuotaWindow_QUOTA_WINDOW_DAILY {
		t.Errorf("quota = (limit %d, window %v), want (1000, DAILY)", q.GetLimit(), q.GetWindow())
	}
}

// TestCanonicalFeed_FlatPricingAndAttributionObligationRoundTrip drives the SECOND
// canonical entry (recipes) through the ingestion surface and asserts its FLAT EUR
// term (4.99 EUR, no metering unit) AND its attribution obligation (on_use, with
// the backlink detail) round-trip proto-exact. An EU requester declaring ai-input
// is the projection key (the term is geo-gated to EU).
func TestCanonicalFeed_FlatPricingAndAttributionObligationRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	records, entries := canonicalFeedFixture(t)
	client, kid, tenantID := pushCanonicalContributor(t, h)
	pushCanonicalEntry(t, h, client, kid, tenantID, entries[1])

	wantTerm := entries[1].GetTerms()[0]
	uri := "https://" + canonicalFeedDomain + records[1].Path
	req := requesterWithExt("agent-eu", "", "EU", "ai-input")
	got := discoverTermsAs(t, h, uri, req)

	term := findTerm(t, got, wantTerm)

	// FLAT: 4.99 EUR, no metering unit (the FLAT no-unit invariant).
	p := term.GetPricing()
	if p.GetModel() != rampv1.PricingModel_PRICING_MODEL_FLAT {
		t.Errorf("pricing model = %v, want FLAT", p.GetModel())
	}
	if p.GetCurrency() != "EUR" {
		t.Errorf("currency = %q, want EUR", p.GetCurrency())
	}
	if p.GetRate() != "4.99" {
		t.Errorf("rate = %q, want %q", p.GetRate(), "4.99")
	}
	if p.GetUnit() != "" {
		t.Errorf("unit = %q, want empty (FLAT no-unit invariant)", p.GetUnit())
	}

	// Attribution obligation: on_use, carrying the backlink detail.
	if len(term.GetObligations()) != 1 {
		t.Fatalf("obligations = %d, want 1", len(term.GetObligations()))
	}
	ob := term.GetObligations()[0]
	if ob.GetKind() != rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION {
		t.Errorf("obligation kind = %v, want ATTRIBUTION", ob.GetKind())
	}
	if ob.GetTrigger() != rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE {
		t.Errorf("obligation trigger = %v, want ON_USE", ob.GetTrigger())
	}
	if ob.GetDetail() != "Credit publisher.example with a backlink" {
		t.Errorf("obligation detail = %q, want the backlink credit", ob.GetDetail())
	}
}

// TestCanonicalFeed_SubscriptionReferenceOnlyRoundTrip drives the THIRD canonical
// entry (tax return) through the ingestion surface and asserts its
// REFERENCE_ONLY term — governed by the Premium License document and scoped to
// subscription:premium — round-trips proto-exact. The term is scope-gated, so the
// requester must declare the subscription:premium scope to discover it; a
// requester WITHOUT that scope must not see it (negative leg through the same
// surface).
func TestCanonicalFeed_SubscriptionReferenceOnlyRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	records, entries := canonicalFeedFixture(t)
	client, kid, tenantID := pushCanonicalContributor(t, h)
	pushCanonicalEntry(t, h, client, kid, tenantID, entries[2])

	wantTerm := entries[2].GetTerms()[0]
	uri := "https://" + canonicalFeedDomain + records[2].Path

	// Negative leg: a subscriber-less requester does not cover the term's
	// subscription:premium scope, so the entry yields no projected offer.
	noScope := requesterWithExt("agent-no-sub", "", "", "ai-input")
	if offers := discoverOffersAs(t, h, uri, noScope); len(offers) != 0 {
		t.Fatalf("offers without subscription scope = %d, want 0 (scope-gated)", len(offers))
	}

	// Positive leg: a requester declaring the subscription:premium scope covers
	// the term and discovers it.
	subscriber := requesterWithExt("agent-premium", "", "", "ai-input")
	subscriber.requester.Scopes = []string{"subscription:premium"}
	offers := discoverOffersAs(t, h, uri, subscriber)
	if len(offers) != 1 {
		t.Fatalf("offers with subscription scope = %d, want 1", len(offers))
	}

	term := findTerm(t, offers[0].GetTerms(), wantTerm)

	if term.GetSemantics() != rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY {
		t.Errorf("semantics = %v, want REFERENCE_ONLY", term.GetSemantics())
	}
	if got := term.GetScopes(); len(got) != 1 || got[0] != "subscription:premium" {
		t.Errorf("scopes = %v, want [subscription:premium]", got)
	}
	if term.GetLicense().GetUri() != "https://publisher.example/licensing/premium" {
		t.Errorf("license uri = %q, want the premium license uri", term.GetLicense().GetUri())
	}
}

// TestCanonicalFeed_MultiResourceAllDiscoverable proves the multi-entry ingest:
// all three canonical resources pushed together are each discoverable by URI
// through DiscoverResources, and each projects exactly one offer to a requester
// that satisfies its gating axes. This grounds ingestion correctness on the FULL
// realistic feed rather than a single hand-built synthetic entry.
func TestCanonicalFeed_MultiResourceAllDiscoverable(t *testing.T) {
	h := newPushHarness(t)
	records, entries := canonicalFeedFixture(t)
	if len(entries) != 3 {
		t.Fatalf("canonical feed entries = %d, want 3", len(entries))
	}
	client, kid, tenantID := pushCanonicalContributor(t, h)
	for i := range entries {
		pushCanonicalEntry(t, h, client, kid, tenantID, entries[i])
	}

	// Each resource has its own gating axes; build a requester per entry that
	// satisfies them, then assert exactly one offer projects for each URI.
	type probe struct {
		path string
		req  requesterSpec
	}
	probes := []probe{
		// entry 0: academic FREE term (functions ai-input/search, geos DE/EU,
		// user academic) — an academic DE requester declaring ai-input matches.
		{records[0].Path, requesterWithExt("agent-academic-de", "academic", "DE", "ai-input")},
		// entry 1: FLAT EU term — an EU requester declaring ai-input matches.
		{records[1].Path, requesterWithExt("agent-eu-flat", "", "EU", "ai-input")},
		// entry 2: subscription:premium REFERENCE_ONLY term — a premium subscriber.
		{records[2].Path, premiumSubscriber("agent-premium-multi")},
	}
	for _, pr := range probes {
		uri := "https://" + canonicalFeedDomain + pr.path
		offers := discoverOffersAs(t, h, uri, pr.req)
		if len(offers) != 1 {
			t.Errorf("discover %s: offers = %d, want 1 (multi-resource ingest)", uri, len(offers))
		}
	}
}

// premiumSubscriber returns a requester carrying the subscription:premium scope so
// it can discover the canonical feed's scope-gated REFERENCE_ONLY term.
func premiumSubscriber(id string) requesterSpec {
	spec := requesterWithExt(id, "", "", "ai-input")
	spec.requester.Scopes = []string{"subscription:premium"}
	return spec
}
