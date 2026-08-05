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
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

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

// TestIngest_FixtureAcceptedAndDiscoverable drives the PRODUCTION
// ingest path — ParseJSONL + MapRecords + PushEntries (RFC 9421-signed Connect
// RPC, no SQL) — over the committed publisher sample fixture against a real
// Exchange + testcontainers Postgres. It asserts every fixture record is
// accepted and that a mapped term is readable back through DiscoverResources.
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

	report, err := ingest.PushEntries(h.ctx, h.server.URL, publisherTenant, kid, mustSigningClient(t, kid, priv), entries)
	if err != nil {
		t.Fatalf("push fixture: %v", err)
	}
	if int(report.Accepted) != len(entries) || report.Rejected != 0 {
		t.Fatalf("push report = accepted %d / rejected %d, want %d / 0 (warnings: %v)",
			report.Accepted, report.Rejected, len(entries), report.Warnings)
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

// TestIngest_BadTermRejectedNotPersisted proves a deliberately-invalid
// term sinks the WHOLE push (all-or-nothing): pushed alongside a valid
// entry, the bad sibling causes the entire submission to be rejected and NEITHER
// URI enters the catalog. No partial acceptance — the publisher fixes and
// resubmits the whole set.
func TestIngest_BadTermRejectedNotPersisted(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	goodPath := "/article/valid-term"
	badPath := "/article/bad-term"
	entries := []*rampv1.ResourceEntry{
		{
			Domain: publisherDomain, Path: goodPath,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		},
		{
			Domain: publisherDomain, Path: badPath,
			// SHARE_ALIKE obligation with no scope_license is a licenseterm.Validate
			// hard reject (the copyleft-target license is mandatory).
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

	_, err := ingest.PushEntries(h.ctx, h.server.URL, publisherTenant, kid, mustSigningClient(t, kid, priv), entries)
	if err == nil {
		t.Fatal("want whole-push rejection (all-or-nothing); the bad sibling must sink the batch")
	}

	// All-or-nothing: NEITHER the bad nor the valid sibling persisted.
	for _, p := range []string{goodPath, badPath} {
		uri := "https://" + publisherDomain + p
		if offers := discoverOffersAs(t, h, uri, requesterWithExt("agent-discover", "", "", "ai-input")); len(offers) != 0 {
			t.Fatalf("entry %s yielded %d offer(s); want 0 (all-or-nothing: nothing persists)", p, len(offers))
		}
	}
}

// TestIngest_UnknownVocabAcceptedWithWarning proves an unknown bare
// vocabulary token on a non-critical restriction is forward-compatible: the term
// is accepted (rejected==0) but the unknown token is surfaced in warnings[].
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

	report, err := ingest.PushEntries(h.ctx, h.server.URL, publisherTenant, kid, mustSigningClient(t, kid, priv), entries)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if report.Accepted != 1 || report.Rejected != 0 {
		t.Fatalf("push report = accepted %d / rejected %d, want 1 / 0", report.Accepted, report.Rejected)
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
// Connect protocol the ingest client speaks has no trailer dependency. A
// regression back onto a trailer-dependent protocol fails this test.
func TestIngest_PushCrossesTrailerlessProxy(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	upstream := h.server.URL
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		// Keep the authority the client signed (@target-uri covers it), the
		// way a TLS proxy preserves the public hostname on its upstream hop.
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
	}))
	defer proxy.Close()

	entries := []*rampv1.ResourceEntry{{
		Domain: publisherDomain, Path: "/article/behind-proxy",
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   seedPricedTerm().GetPricing(),
		}},
	}}

	report, err := ingest.PushEntries(h.ctx, proxy.URL, publisherTenant, kid, mustSigningClient(t, kid, priv), entries)
	if err != nil {
		t.Fatalf("push through trailer-dropping proxy: %v", err)
	}
	if report.Accepted != 1 || report.Rejected != 0 {
		t.Fatalf("push report = accepted %d / rejected %d, want 1 / 0 (warnings: %v)",
			report.Accepted, report.Rejected, report.Warnings)
	}
}
