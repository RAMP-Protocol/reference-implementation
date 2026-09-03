//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// feedFixturePath resolves the committed reference sample JSON-L fixture
// relative to this test file (deploy/fixtures/publisher/sample.jsonl at the repo
// root).
func feedFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "publisher", "sample.jsonl")
}

// generateContributorKeyFile generates a fresh Ed25519 catalog-contributor
// keypair and writes it to a temp file in the {kid,private_key,public_key} shape
// LoadContributorKey decodes. No private-key material is tracked in git:
// every run mints its own demo key at setup. Returns the file path so the test
// can drive the production LoadContributorKey path, exactly as the CLI does.
func generateContributorKeyFile(t *testing.T, kid string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate contributor key: %v", err)
	}
	seed := priv.Seed()
	doc := map[string]string{
		"kid":         kid,
		"private_key": base64.RawURLEncoding.EncodeToString(seed),
		"public_key":  base64.RawURLEncoding.EncodeToString(pub),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal contributor key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "catalog-contributor-key.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write contributor key: %v", err)
	}
	return path
}

// registerContributor wires both auth gates for a freshly-generated
// contributor key against the given entry domain: it generates a demo keypair at
// setup, loads it through the production LoadContributorKey path, registers the
// pubkey via the agent self-signup origin (Gate 1) and lists the kid as a
// contributor in the domain's publisher manifest (Gate 2). It returns the kid the
// caller pushes as.
func registerContributor(t *testing.T, h *pushHarness, domain string) (kid string, priv ed25519.PrivateKey) {
	t.Helper()
	const contributorKID = "catalog-contributor-e2e"
	keyPath := generateContributorKeyFile(t, contributorKID)
	loadedKid, loadedPriv, err := ingest.LoadContributorKey(keyPath)
	if err != nil {
		t.Fatalf("load contributor key: %v", err)
	}
	pub := loadedPriv.Public().(ed25519.PublicKey)
	h.publishAgent(t, loadedKid, pub)        // Gate 1: kid -> pubkey via ramp.json
	h.publishPublisher(t, domain, loadedKid) // Gate 2: kid listed as contributor
	return loadedKid, loadedPriv
}

// pushTarget names the harness Exchange as recipient, the tenant that owns
// the entries' domain and the contributor pushing — the way every ingest test
// addresses a push. Where the push is dialled is the client's
// (mustCatalogClient).
func pushTarget(tenantID, kid string) ingest.PushTarget {
	return ingest.PushTarget{Exchange: harnessExchangeDomain, TenantID: tenantID, CallerID: kid}
}

// forwardWithoutTrailers is an intermediary that forwards status, headers and
// body to upstream and never HTTP trailers — the shape of a TLS-terminating
// proxy whose upstream hop is HTTP/1.1, which is what fronts the Exchange in a
// deployment. It keeps the authority the client signed (@target-uri covers
// it), the way a TLS proxy preserves the public hostname on its upstream hop.
func forwardWithoutTrailers(upstream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		req.Host = r.Host
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		// resp.Trailer is deliberately not forwarded: this proxy never passes
		// trailers on, like the deployment hop this test models.
	}
}

// TestIngest_FixtureAcceptedAndDiscoverable drives the PRODUCTION
// ingest path — ParseJSONL + MapRecords + PushEntries through the SDK catalog
// client (RFC 9421-signed Connect RPC, no SQL) — over the committed publisher
// sample fixture against a real Exchange + testcontainers Postgres. It asserts
// every fixture record is accepted and that a mapped term is readable back
// through DiscoverResources.
func TestIngest_FixtureAcceptedAndDiscoverable(t *testing.T) {
	h := newPushHarness(t)

	// The fixture's entries all carry domain "publisher.example"; both gates are
	// keyed off that domain's publisher manifest. Catalog rows are owned by the
	// tenant whose domain matches the entry's publisher domain (server-side
	// derivation), so publisher.example must be a registered tenant and the
	// ingest must push under that tenant's id — not the harness's primary tenant.
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	feed, err := os.Open(feedFixturePath(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = feed.Close() }()
	records, err := ingest.ParseJSONL(feed)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	entries, err := ingest.MapRecords(records)
	if err != nil {
		t.Fatalf("map fixture: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("fixture mapped to zero entries")
	}

	report, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, h.server.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	if err != nil {
		t.Fatalf("push fixture: %v", err)
	}
	if int(report.Accepted) != len(entries) {
		t.Fatalf("push report = accepted %d, want %d (warnings: %v)", report.Accepted, len(entries), report.Warnings)
	}

	// The first fixture record (photosynthesis) carries a FREE academic term and a
	// commercial PER_UNIT term. An academic requester must discover its term back
	// through the public RPC — proving the mapped terms[] were validated, stored,
	// and are Select-projectable (a SQL backdoor could not produce this).
	uri := "https://" + publisherDomain + records[0].Path
	terms := discoverTermsAs(t, h, uri, requesterWithExt("agent-discover", "academic", "DE", "ai-input"))
	if len(terms) == 0 {
		t.Fatalf("discover %s: no terms projected for academic requester", uri)
	}
	if terms[0].GetPricing().GetModel() != rampv1.PricingModel_PRICING_MODEL_FREE {
		t.Fatalf("academic term pricing model = %v, want FREE", terms[0].GetPricing().GetModel())
	}
}

// TestIngest_BadTermRejectedNotPersisted proves a term the Exchange's ingest
// tier refuses sinks the WHOLE submission (all-or-nothing): pushed alongside a
// valid entry, the bad sibling causes the entire submission to be refused —
// CodeInvalidArgument from the RPC — and NEITHER URI enters the catalog. No
// partial acceptance: the publisher fixes and resubmits the whole set.
//
// The bad term carries a bare pricing unit that is not a registered metering
// token. It passes the wire pattern on Pricing.unit, so the client's own wire
// validation lets the request through and the refusal is the Exchange's, after
// the request crossed the wire — which the absence of a Violations detail on
// the error proves (the wire tier attaches one; the ingest tier does not).
// TestIngest_WireViolationRefusedBeforeSending covers the other tier.
func TestIngest_BadTermRejectedNotPersisted(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	goodPath := "/article/valid-term"
	badPath := "/article/bad-term"
	entries := []*rampv1.ResourceEntry{
		{Domain: publisherDomain, Path: goodPath, Terms: []*rampv1.LicenseTerm{seedPricedTerm()}},
		{Domain: publisherDomain, Path: badPath, Terms: []*rampv1.LicenseTerm{unregisteredUnitTerm()}},
	}

	_, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, h.server.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if violations := testutil.ValidationViolations(t, err); len(violations) != 0 {
		t.Fatalf("refusal carries %d wire violation(s); want none: the ingest tier refused, not the wire tier",
			len(violations))
	}

	// All-or-nothing: NEITHER the bad nor the valid sibling persisted.
	for _, p := range []string{goodPath, badPath} {
		uri := "https://" + publisherDomain + p
		if offers := discoverOffersAs(t, h, uri, requesterWithExt("agent-discover", "", "", "ai-input")); len(offers) != 0 {
			t.Fatalf("entry %s yielded %d offer(s); want 0 (all-or-nothing: nothing persists)", p, len(offers))
		}
	}
}

// TestIngest_WireViolationRefusedBeforeSending proves the client's strict wire
// validation, the property NewCatalogClient claims: an entry that fails a
// protovalidate rule — a SHARE_ALIKE obligation with no scope_license, the
// message-level CEL rule obligation.share_alike.requires_scope_license in the
// pinned protocol module — is refused by the client before anything is signed
// or sent. The refusal is CodeInvalidArgument carrying the Violations detail
// that names the rule, the counting proxy in front of the Exchange sees no
// request at all, and neither entry of the submission enters the catalog. The
// Exchange applies the same rule at its own wire tier; this proves the CLI
// never gets that far.
func TestIngest_WireViolationRefusedBeforeSending(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	var requests atomic.Int32
	forward := forwardWithoutTrailers(h.server.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		forward(w, r)
	}))
	defer proxy.Close()

	goodPath := "/article/valid-sibling"
	badPath := "/article/share-alike-without-scope"
	entries := []*rampv1.ResourceEntry{
		{Domain: publisherDomain, Path: goodPath, Terms: []*rampv1.LicenseTerm{seedPricedTerm()}},
		{
			Domain: publisherDomain, Path: badPath,
			Terms: []*rampv1.LicenseTerm{{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   seedPricedTerm().GetPricing(),
				Obligations: []*rampv1.Obligation{{
					Kind:    rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE,
					Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_DISTRIBUTION,
				}},
			}},
		},
	}

	_, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, proxy.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertWireViolation(t, err, "entries[1].terms[0].obligations[0]", "obligation.share_alike.requires_scope_license")
	if n := requests.Load(); n != 0 {
		t.Fatalf("the proxy saw %d request(s); a wire-invalid submission must be refused before it is sent", n)
	}
	for _, p := range []string{goodPath, badPath} {
		uri := "https://" + publisherDomain + p
		if got := discoverOfferCount(t, h, uri); got != 0 {
			t.Fatalf("entry %s yielded %d offer(s); want 0 (nothing was sent)", p, got)
		}
	}
}

// TestIngest_UnknownVocabAcceptedWithWarning proves an unknown bare
// vocabulary token on a non-critical restriction is forward-compatible: the term
// is accepted but the unknown token is surfaced in warnings[].
func TestIngest_UnknownVocabAcceptedWithWarning(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	entries := []*rampv1.ResourceEntry{{
		Domain: publisherDomain, Path: "/article/warn-term",
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   seedPricedTerm().GetPricing(),
			Restrictions: []*rampv1.Restriction{{
				Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
				Permitted: []string{"ai-input", "totally-made-up-function"},
				// non-critical → unknown token warns, does not reject
			}},
		}},
	}}

	report, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, h.server.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if report.Accepted != 1 {
		t.Fatalf("push report = accepted %d, want 1", report.Accepted)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected non-empty warnings[] for unknown vocab token, got none")
	}
}

// TestIngest_PushCrossesTrailerlessProxy proves the catalog push works through
// an intermediary that forwards status, headers, and body but never HTTP
// trailers — the shape of a TLS-terminating proxy whose upstream hop is
// HTTP/1.1, which is what fronts the Exchange in a deployment. The gRPC
// protocol puts the RPC verdict in trailers, so a client pinned to it fails
// behind such a proxy with a transport error before any verdict arrives; the
// Connect protocol the SDK catalog client speaks by default has no trailer
// dependency. A regression back onto a trailer-dependent protocol fails this
// test.
func TestIngest_PushCrossesTrailerlessProxy(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	proxy := httptest.NewServer(forwardWithoutTrailers(h.server.URL))
	defer proxy.Close()

	entries := []*rampv1.ResourceEntry{{
		Domain: publisherDomain, Path: "/article/behind-proxy",
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   seedPricedTerm().GetPricing(),
		}},
	}}

	report, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, proxy.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	if err != nil {
		t.Fatalf("push through trailer-dropping proxy: %v", err)
	}
	if report.Accepted != 1 {
		t.Fatalf("push report = accepted %d, want 1 (warnings: %v)", report.Accepted, report.Warnings)
	}
}
