//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// publisherOrigin serves /.well-known/ramp.json for a single publisher domain.
// Contributors and 404 behavior are mutated mid-test to drive the scenarios.
type publisherOrigin struct {
	server       *httptest.Server
	mu           sync.Mutex
	contributors []string
	notFound     bool
	provider     string
}

func newPublisherOrigin(t *testing.T, provider string) *publisherOrigin {
	t.Helper()
	o := &publisherOrigin{provider: provider}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *publisherOrigin) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.notFound {
		http.NotFound(w, r)
		return
	}
	doc := &rampv1.WellKnownManifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: o.provider,
		// The schema requires exchanges[] for ROLE_PUBLISHER; one direct
		// entry satisfies it. Gate 2 keys only off catalog_contributors,
		// so the exchange entry is incidental to these tests.
		Exchanges: []*rampv1.AuthorizedExchange{{
			Domain:       "exchange.ramp.test",
			Endpoint:     "https://exchange.ramp.test/ramp",
			Relationship: rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT,
		}},
	}
	for _, c := range o.contributors {
		doc.CatalogContributors = append(doc.CatalogContributors, &rampv1.CatalogContributor{
			Domain: c, Relationship: "publisher",
		})
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(doc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (o *publisherOrigin) setContributors(cs ...string) {
	o.mu.Lock()
	o.contributors = cs
	o.notFound = false
	o.mu.Unlock()
}

// pushAgentOrigin serves /.well-known/ramp.json for lazy-signup tests. The
// mutually-exclusive failure toggles drive the registry's fetch down each
// mapLazyRegisterError branch: missing → 404 (Unauthenticated), unavailable →
// 503 (Unavailable/retryable), malformed → schema-invalid body
// (Unauthenticated), expired → a manifest whose only key is outside its
// validity window (no-valid-key → Unauthenticated).
type pushAgentOrigin struct {
	server      *httptest.Server
	agentID     string
	pub         ed25519.PublicKey
	mu          sync.Mutex
	missing     bool
	unavailable bool
	malformed   bool
	expired     bool
}

func newPushAgentOrigin(t *testing.T, agentID string, pub ed25519.PublicKey) *pushAgentOrigin {
	t.Helper()
	o := &pushAgentOrigin{agentID: agentID, pub: pub}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *pushAgentOrigin) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	o.mu.Lock()
	missing, unavailable, malformed, expired := o.missing, o.unavailable, o.malformed, o.expired
	o.mu.Unlock()
	switch {
	case missing:
		http.NotFound(w, r)
		return
	case unavailable:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case malformed:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid ramp json"))
		return
	}
	from, until := agentKeyValidFrom(), agentKeyValidUntil()
	if expired {
		from, until = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	}
	doc, err := agentManifestFields(o.agentID, o.pub, from, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// agentManifestFields renders the unified ROLE_AGENT well-known manifest
// (ramp.v1.WellKnownManifest, protojson/snake_case) as a generic JSON object so
// callers can either serve it verbatim or splice publisher-only fields onto the
// same document (the combined-origin self-signup fixture). domain anchors the
// agent's identity (formerly agent_id); public_keys carries one inline Ed25519
// JWK valid over [validFrom, validUntil) built by the shared rampwellknown
// producer helper so the served shape always matches what the consumer accepts.
func agentManifestFields(agentID string, pub ed25519.PublicKey, validFrom, validUntil time.Time) (map[string]any, error) {
	key := rampwellknown.NewKey("k1", pub, validFrom, validUntil)
	raw := testutil.MarshalManifest(testutil.Manifest(rampwellknown.RoleAgent, agentID, key))
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode agent manifest: %w", err)
	}
	return fields, nil
}

// agentKeyValidFrom / agentKeyValidUntil bound a fixture key around "now" so it
// is active at serve time without a fixed clock.
func agentKeyValidFrom() time.Time  { return time.Now().Add(-time.Hour) }
func agentKeyValidUntil() time.Time { return time.Now().Add(24 * time.Hour) }

// rewritingTransport rewrites outbound fetches whose Host appears in rewrite
// onto a local httptest server. Used by the rampwellknown cache + agentreg so
// production wiring never sees test-only URLs.
type rewritingTransport struct {
	base    http.RoundTripper
	mu      *sync.Mutex
	rewrite map[string]string // host → target base URL
}

func (t *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	target, ok := t.rewrite[req.URL.Host]
	t.mu.Unlock()
	if !ok {
		return t.base.RoundTrip(req)
	}
	u, err := url.Parse(target + req.URL.Path)
	if err != nil {
		return nil, err
	}
	if req.URL.RawQuery != "" {
		u.RawQuery = req.URL.RawQuery
	}
	r2 := req.Clone(req.Context())
	r2.URL = u
	r2.Host = u.Host
	return t.base.RoundTrip(r2)
}

// pushHarness wires the full Exchange plane with real agentreg.Registry +
// real rampwellknown.Cache, both routed at httptest origins via a rewriting
// transport. This is the E2E substrate for Gate 1 + Gate 2 coverage.
type pushHarness struct {
	ctx          context.Context
	tenantID     string
	publisher    *publisherOrigin
	publisherDom string
	server       *httptest.Server
	// baseTransport is the underlying Transport that signedCat layers RFC
	// 9421 signing on top of. Sibling harnesses (e.g. agent self-signup)
	// reuse it to avoid duplicating the full bring-up.
	baseTransport http.RoundTripper
	queries       *sqlc.Queries
	rewriteMu     *sync.Mutex
	rewrite       map[string]string
	unsignedCat   rampconnect.CatalogServiceClient
	signedCat     func(id string, priv ed25519.PrivateKey) rampconnect.CatalogServiceClient
	exchange      rampconnect.ExchangeServiceClient
	// discoverKeyID + discoverPriv are the keypair the harness's `exchange`
	// client signs every outbound /ramp.v1.ExchangeService/* call with.
	// Sibling harnesses (agent self-signup) that rewrap the transport must
	// re-apply newSigningTransport(..., discoverKeyID, discoverPriv) so the
	// signature still clears the global httpsig gate. The pubkey is
	// registered in the test mux's static resolver at startExchangeServer
	// time via the httpsigKeys field on exchangeServerDeps.
	discoverKeyID string
	discoverPriv  ed25519.PrivateKey
	// resolver is the global-httpsig static resolver. Self-acting agent
	// tests register a fresh transport-signing pubkey here (resolver.Put) so
	// the agent's own signature clears the gate while its agents-repo row is
	// still absent — the precondition for exercising resolveCaller's ADR-009
	// D2 lazy-registration path. Multisig tests likewise register agent
	// pubkeys here dynamically.
	resolver *httpsig.StaticResolver
	// rsaPub is the CloudFront RSA verify key the fixture minted. Onboarding
	// tests read it here (RAMP v1 no longer publishes it at a well-known route).
	rsaPub *rsa.PublicKey
}

// selfActingExchangeClient returns an ExchangeService client that signs every
// /ramp.* call with keyID/priv — the self-acting shape where the agent signs
// for itself (keyID == requester.id == agent_id). Pairs with resolver.Put so
// the signature clears the global gate.
func (h *pushHarness) selfActingExchangeClient(
	keyID string, priv ed25519.PrivateKey,
) rampconnect.ExchangeServiceClient {
	c := &http.Client{Transport: newSigningTransport(h.baseTransport, keyID, priv)}
	return rampconnect.NewExchangeServiceClient(c, h.server.URL, connect.WithGRPC())
}

func newPushHarness(t *testing.T) *pushHarness {
	t.Helper()
	fx := setupExchangeTestDB(t, "unused-agent")
	ctx, logger, pool, queries, keystore := fx.ctx, fx.logger, fx.pool, fx.queries, fx.keystore

	publisherDomain := "pub-" + uuid.NewString() + ".example"
	tenantID := "t_" + uuid.NewString()
	if _, err := queries.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          publisherDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   "secret://ed25519/" + tenantID,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert publisher tenant: %v", err)
	}
	pubOfferPub, pubOfferPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("publisher ed25519: %v", err)
	}
	keystore.PutEd25519("secret://ed25519/"+tenantID, pubOfferPub, pubOfferPriv)

	publisher := newPublisherOrigin(t, publisherDomain)

	rewriteMu := &sync.Mutex{}
	rewrite := map[string]string{publisherDomain: publisher.server.URL}

	rewriteClient := &http.Client{Transport: &rewritingTransport{
		base: http.DefaultTransport, mu: rewriteMu, rewrite: rewrite,
	}}

	manifests := rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     rewriteClient,
		ExpectRole: rampwellknown.RolePublisher,
	})
	registry := agentreg.New(agentreg.Config{
		Repo: repo.NewAgentRepo(queries),
		HTTP: rewriteClient,
	})

	offerSigner, err := signing.NewEd25519Signer(pubOfferPub, pubOfferPriv)
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}

	// Discover-side signer: the global httpsig gate now applies to every
	// /ramp.v1.ExchangeService/* call (post-1rnxh). Each pushHarness owns
	// one pre-registered keypair that the harness's `exchange` client signs
	// outbound DiscoverResources/ExecuteTransaction/ReportUsage with. The
	// keyID matches the requester.id used in tests (agent-discover) so the
	// signature's kid lines up with the agent the assertions reference.
	const discoverKeyID = "agent-discover"
	discoverPub, discoverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("discover ed25519: %v", err)
	}

	srv := startExchangeServer(t, exchangeServerDeps{
		pool: pool, queries: queries, registry: registry, manifests: manifests,
		bill: billing.FreeAdapter{}, signer: offerSigner, keystore: keystore, logger: logger,
		// Per-contributor signers registered for individual Catalog tests
		// install themselves dynamically (each test generates its own
		// caller keypair and pushes via publishAgent → ramp.json self-signup).
		// Those don't go through the global gate (predicate excludes
		// /ramp.v1.CatalogService/), so they do NOT need to live in
		// httpsigKeys. Only the discover-side signer below does.
		httpsigKeys: map[string]ed25519.PublicKey{discoverKeyID: discoverPub},
	})
	if err := srv.catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}
	// Register the discover-side signer as a BROKER agent. The self-signup
	// and onboarding e2e flows sign Execute/Report calls with this key
	// while naming a freshly-registered AGENT in requester.id — the
	// broker-on-behalf shape the new caller-identity authorization
	// supports. The publisher tenant gets allow_broker_relay=true so the
	// broker is accepted.
	if _, err := queries.UpsertAgent(ctx, sqlc.UpsertAgentParams{
		AgentID:       discoverKeyID,
		PublicKey:     discoverPub,
		RequesterType: sqlc.RampRequesterTypeBROKER,
	}); err != nil {
		t.Fatalf("upsert discover agent: %v", err)
	}
	if err := queries.SetTenantAllowBrokerRelay(ctx, sqlc.SetTenantAllowBrokerRelayParams{
		TenantID:         tenantID,
		AllowBrokerRelay: true,
	}); err != nil {
		t.Fatalf("enable publisher broker relay: %v", err)
	}

	signedFactory := func(id string, priv ed25519.PrivateKey) rampconnect.CatalogServiceClient {
		c := &http.Client{Transport: newSigningTransport(srv.baseTransport, id, priv)}
		return rampconnect.NewCatalogServiceClient(c, srv.server.URL, connect.WithGRPC())
	}

	exchangeClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, discoverKeyID, discoverPriv)}

	return &pushHarness{
		ctx:           ctx,
		tenantID:      tenantID,
		publisher:     publisher,
		publisherDom:  publisherDomain,
		server:        srv.server,
		baseTransport: srv.baseTransport,
		queries:       queries,
		rewriteMu:     rewriteMu,
		rewrite:       rewrite,
		resolver:      srv.resolver,
		unsignedCat:   rampconnect.NewCatalogServiceClient(srv.server.Client(), srv.server.URL, connect.WithGRPC()),
		signedCat:     signedFactory,
		exchange:      rampconnect.NewExchangeServiceClient(exchangeClient, srv.server.URL, connect.WithGRPC()),
		discoverKeyID: discoverKeyID,
		discoverPriv:  discoverPriv,
		rsaPub:        srv.rsaPub,
	}
}

func (h *pushHarness) registerHost(host, target string) {
	h.rewriteMu.Lock()
	h.rewrite[host] = target
	h.rewriteMu.Unlock()
}

func (h *pushHarness) publishAgent(t *testing.T, agentID string, pub ed25519.PublicKey) *pushAgentOrigin {
	origin := newPushAgentOrigin(t, agentID, pub)
	h.registerHost(agentID, origin.server.URL)
	return origin
}

func (h *pushHarness) publishPublisher(t *testing.T, domain string, contributors ...string) *publisherOrigin {
	origin := newPublisherOrigin(t, domain)
	origin.setContributors(contributors...)
	h.registerHost(domain, origin.server.URL)
	return origin
}

// TestPushResources_UnsignedRequestRejected proves Gate 1 rejects a push that
// lacks the RFC 9421 signature headers.
func TestPushResources_UnsignedRequestRejected(t *testing.T) {
	h := newPushHarness(t)
	h.publisher.setContributors("caller.example")

	_, err := h.unsignedCat.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "caller.example",
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/one"}},
	}))
	assertCode(t, err, connect.CodeUnauthenticated)
}

// TestPushResources_UnknownCallerManifestMissing proves Gate 1 rejects when
// the caller's manifest origin returns 404 (no lazy-signup possible).
func TestPushResources_UnknownCallerManifestMissing(t *testing.T) {
	h := newPushHarness(t)
	h.publisher.setContributors("caller.example")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	origin := h.publishAgent(t, "caller.example", nil)
	origin.mu.Lock()
	origin.missing = true
	origin.mu.Unlock()

	client := h.signedCat("caller.example", priv)
	_, err = client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "caller.example",
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/one"}},
	}))
	assertCode(t, err, connect.CodeUnauthenticated)
}

// TestPushResources_UnknownCallerManifestUnavailable proves the catalog
// self-signup handler classifies a TRANSIENT manifest-fetch failure (origin
// 503) as Unavailable/retryable, not as a permanent Unauthenticated — matching
// the service lazy-registration path (agentreg.IsCallerFault).
func TestPushResources_UnknownCallerManifestUnavailable(t *testing.T) {
	h := newPushHarness(t)
	h.publisher.setContributors("caller.example")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	origin := h.publishAgent(t, "caller.example", nil)
	origin.mu.Lock()
	origin.unavailable = true
	origin.mu.Unlock()

	client := h.signedCat("caller.example", priv)
	_, err = client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "caller.example",
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/one"}},
	}))
	assertCode(t, err, connect.CodeUnavailable)
}

// TestPushResources_UnknownCallerAutoRegisteredAndAdmitted proves the lazy
// self-signup path: unknown caller → registry fetches manifest → key stored →
// request re-verified and, because the caller is a listed contributor, the
// entry is accepted.
func TestPushResources_UnknownCallerAutoRegisteredAndAdmitted(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/one"}},
	}))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want 1/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
}

// TestPushResources_ContributorAdmittedSnapshotRebuilt proves Gate 2 admits a
// listed contributor, rebuilds the snapshot automatically, and makes the
// entry visible via DiscoverResources.
func TestPushResources_ContributorAdmittedSnapshotRebuilt(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	client := h.signedCat(callerID, priv)
	if _, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: "/articles/one"}},
	})); err != nil {
		t.Fatalf("push: %v", err)
	}

	discovered, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q-contrib",
		Requester: &rampv1.Requester{
			Id: "agent-discover", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: []string{"https://" + h.publisherDom + "/articles/one"},
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(discovered.Msg.GetOffers()) != 1 {
		t.Fatalf("offers len = %d, want 1", len(discovered.Msg.GetOffers()))
	}
}

// TestPushResources_CallerNotInContributorsRejectedPerEntry proves Gate 2
// rejects per-entry (not per-request) when the caller is authenticated but is
// not a contributor for the entry's provider. Accepted entries coexist with
// rejected ones in the response.
func TestPushResources_CallerNotInContributorsRejectedPerEntry(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	deniedDomain := "denied-" + h.publisherDom
	h.publishPublisher(t, deniedDomain, "some-other.example")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.publisherDom, Path: "/articles/ok"},
			{Domain: deniedDomain, Path: "/articles/denied"},
		},
	}))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 1 {
		t.Fatalf("accepted=%d rejected=%d, want 1/1", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
	// W4 of t3vk reduced PushResourcesResponse to accepted/rejected counts;
	// per-entry detail (URI + machine-readable reason) now lives only in the
	// service-internal CatalogPushRejection diagnostic log and is not
	// reachable from a transport-layer test. The count split above proves
	// the partition gate fired on exactly one denied entry; per-entry reason
	// fidelity is a service-layer concern (service.RejectionReasonNotInContributors).
	_ = service.RejectionReasonNotInContributors // symbol-stability touchpoint
}

func assertCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != want {
		t.Fatalf("want %v, got %v", want, err)
	}
}

// NOTE: TestPushResources_PublicEntryMaterializesFreeOffer and
// TestPushResources_ScopeGatedEntryDoesNotMaterializeOffer were removed
// when t3vk W3 deleted src/exchange/internal/repo/offers.go and the
// FREE-offer materialisation feature (j8fh: catalog → FREE per-request
// offer row bridge) that they exercised. The canonical ResourceEntry /
// discovery flow no longer mints a parallel offer row at PushResources
// time; obligation 04's anonymous public-resource flow is now served
// through DiscoverResources directly. Re-introducing transport-level
// coverage of that surface is tracked separately from this build-fix.
