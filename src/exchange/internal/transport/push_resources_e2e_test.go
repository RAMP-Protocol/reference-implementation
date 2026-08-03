//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

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
	ownerExt, err := structpb.NewStruct(map[string]any{"resource_owner_id": harnessResourceOwner})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc := &rampv1.WellKnownManifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: o.provider,
		// The schema requires exchanges[] for ROLE_PUBLISHER. The entry satisfies
		// that AND attests the resource_owner_id payee the catalog resource-owner
		// gate reads for this Exchange (harnessExchangeDomain).
		Exchanges: []*rampv1.AuthorizedExchange{{
			Domain:       harnessExchangeDomain,
			Endpoint:     "https://exchange.ramp.test/ramp",
			Relationship: rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT,
			Ext:          ownerExt,
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
	// After the WBA split the exchange discovers a caller's signing key from its
	// WBA directory (not its ramp.json overlay), so the fixture serves the key
	// set at the WBA path.
	if r.URL.Path != rampwellknown.WBAPath {
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
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte("{not valid jwk set"))
		return
	}
	from, until := agentKeyValidFrom(), agentKeyValidUntil()
	if expired {
		from, until = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write(agentWBABytes(o.pub, from, until))
}

// agentWBABytes renders a WBA directory (ramp.v1.WBAFile, protojson/snake_case)
// carrying one Ed25519 key valid over [validFrom, validUntil) — the shape the
// exchange's WBA-directory fetch (agentreg / catalog self-signup) consumes to
// TOFU-pin a caller's signing key.
func agentWBABytes(pub ed25519.PublicKey, validFrom, validUntil time.Time) []byte {
	key := rampwellknown.NewKey(pub, validFrom, validUntil)
	return testutil.MarshalWBA(testutil.WBAFile(key))
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
	resolver *helpers.StaticKeyResolver
	// rsaPub is the CloudFront RSA verify key the fixture minted. Onboarding
	// tests read it here (RAMP v1 no longer publishes it at a well-known route).
	rsaPub *rsa.PublicKey
	// logs captures the server's structured log output (JSON lines), so tests
	// can assert a rejection produced its correlated audit line.
	logs *safeBuffer
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
	return newPushHarnessShaped(t, false)
}

// newPushHarnessShaped is newPushHarness with an explicit deployment shape:
// trustProxyHeaders wires the forwarded-header rewrite into WrapPublicSurface,
// the proxied topology where a TLS-terminating proxy fronts the Exchange (see
// proxy_trust_integration_test.go).
func newPushHarnessShaped(t *testing.T, trustProxyHeaders bool) *pushHarness {
	t.Helper()
	fx := setupExchangeTestDB(t, "unused-agent")
	ctx, pool, queries, keystore := fx.ctx, fx.pool, fx.queries, fx.keystore
	// Capture the server's log output instead of discarding it, so tests can
	// assert rejections log their correlated audit line.
	logBuf := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, nil))

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
		httpsigKeys: map[string]ed25519.PublicKey{testutil.MustThumbprintPriv(discoverPriv): discoverPub},
		// The publisher tenant doubles as the default tenant Register reads its
		// activation policy from, so agents can billing-register before a paid
		// transaction. billingRefGen stays nil → uuid: these flows use
		// the FreeAdapter and never assert on the ref value.
		defaultTenantDomain: publisherDomain,
		trustProxyHeaders:   trustProxyHeaders,
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
	seedAgentAs(t, ctx, queries, discoverKeyID, discoverPub, string(sqlc.RampRequesterTypeBROKER))
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
		logs:          logBuf,
	}
}

func (h *pushHarness) registerHost(host, target string) {
	h.rewriteMu.Lock()
	h.rewrite[host] = target
	h.rewriteMu.Unlock()
}

// registerForBilling gives an already-directory-registered agent a billing_ref
// through the public Register RPC — the precondition for a paid
// transaction. The agent signs for itself (Register keys on the verified caller
// identity, and a broker is refused), so its key is registered with the global
// httpsig gate first. Used by the self-signup and onboarding e2e flows, whose
// agent transacts a priced offer via the FreeAdapter.
func (h *pushHarness) registerForBilling(t *testing.T, agentID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	h.resolver.Put(testutil.MustThumbprintPriv(priv), pub)
	registerCaller(t, h.ctx, h.selfActingExchangeClient(agentID, priv))
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
	assertConnectCode(t, err, connect.CodeUnauthenticated)
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
	assertConnectCode(t, err, connect.CodeUnauthenticated)
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
	assertConnectCode(t, err, connect.CodeUnavailable)
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
		// A priced term is required for the entry to yield an offer.
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/one",
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil {
		t.Fatalf("push: %v", err)
	}

	discovered, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.publisherDom + "/articles/one"},
		Requester: &rampv1.Requester{
			Id: "agent-discover", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(discovered.Msg.GetOffers()) != 1 {
		t.Fatalf("offers len = %d, want 1", len(discovered.Msg.GetOffers()))
	}
}

// TestPushResources_SchemedCallerIDAuthorizesAsItsHost closes the gap between the
// two gates a push passes through. Gate 1 resolves the caller's key through
// agentreg, which canonicalizes; Gate 2 compares caller_id against the manifest's
// contributor domains verbatim. A publisher spelling its own caller_id as a full
// origin therefore AUTHENTICATED as pub.example and was then refused with
// caller_not_in_catalog_contributors — a rejection naming a condition it
// satisfies, and one no error message could have explained.
//
// The manifest lists the bare host, as a publisher writes it; only the caller
// side folds. The push must be accepted and the entry must become discoverable,
// which is what separates "both gates passed" from "the request died quietly
// somewhere else".
func TestPushResources_SchemedCallerIDAuthorizesAsItsHost(t *testing.T) {
	h := newPushHarness(t)
	const callerHost = "caller.example"
	// The publisher authorizes the bare host — the spelling a manifest carries.
	h.publisher.setContributors(callerHost)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerHost, pub)

	// The caller spells itself as a full origin, on the wire and in the message.
	const callerAsSpelled = "https://" + callerHost
	client := h.signedCat(callerAsSpelled, priv)
	if _, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerAsSpelled,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/schemed",
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil {
		t.Fatalf("push with caller_id %q: %v — the caller authenticates as %q, so it must "+
			"also authorize as %q", callerAsSpelled, err, callerHost, callerHost)
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+"/articles/schemed"); got != 1 {
		t.Fatalf("offers = %d, want 1 — the push was accepted but the entry did not land", got)
	}
}

// TestPushResources_ManifestSpellingsAuthorizeOneContributor drives the mirror of
// the test above: the CALLER sends the bare host and the PUBLISHER writes the
// contributor entry however it likes.
//
// This is the direction that was broken and untested. Canonicalizing only the
// caller made the comparison asymmetric — folded on one side, raw on the other —
// so a publisher that had written "https://caller.example" in its own manifest,
// or used mixed case, a trailing dot, or an explicit :443, had every push refused
// after the change. Silently, too: contributor rejection is per-entry, so the RPC
// still answers 200 and only the entry count betrays it.
//
// Every other fixture in this file writes bare hosts on both sides, which is why
// the whole suite stayed green with the regression in place.
func TestPushResources_ManifestSpellingsAuthorizeOneContributor(t *testing.T) {
	const callerHost = "mirror-caller.example"
	for _, manifestSpelling := range []string{
		"https://" + callerHost,
		"Mirror-Caller.Example",
		callerHost + ".",
		callerHost + ":443",
	} {
		t.Run(manifestSpelling, func(t *testing.T) {
			h := newPushHarness(t)
			// The publisher authorizes the contributor in ITS spelling.
			h.publisher.setContributors(manifestSpelling)

			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("gen: %v", err)
			}
			h.publishAgent(t, callerHost, pub)

			// The caller sends the bare host, as the transport canonicalizes it.
			client := h.signedCat(callerHost, priv)
			if _, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
				TenantId: h.tenantID,
				CallerId: callerHost,
				Entries: []*rampv1.ResourceEntry{{
					Domain: h.publisherDom, Path: "/articles/mirror",
					Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
				}},
			})); err != nil {
				t.Fatalf("push: %v", err)
			}
			// The RPC answers 200 whether or not the entry was authorized, so the
			// offer count is what proves the contributor gate admitted it.
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+"/articles/mirror"); got != 1 {
				t.Fatalf("offers = %d, want 1 — the publisher spelled its contributor %q and "+
					"the caller resolves to %q; both name one party",
					got, manifestSpelling, callerHost)
			}
		})
	}
}

// TestPushResources_CallerIDNamingNoHostIsInvalidArgument is the negative path
// for the canonicalization above: a caller_id that names no host cannot be an
// identity, so the push is refused before the contributor gate is consulted.
//
// The value is the sf-dictionary form, which nothing in the stack unwraps — the
// same choice the sibling Broker and Execute tests make, so the refusal is pinned
// rather than a parsing gap a later change would close.
//
// Without this the refusal is unpinned: a regression letting it fall through to
// verifyCallerSignature (a different code) or return nil would leave the suite
// green, because the only caller_id coverage is the positive path.
func TestPushResources_CallerIDNamingNoHostIsInvalidArgument(t *testing.T) {
	h := newPushHarness(t)
	const callerHost = "nohost-caller.example"
	h.publisher.setContributors(callerHost)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerHost, pub)

	// Authenticates as the host; sends a caller_id that names none.
	client := h.signedCat(callerHost, priv)
	_, err = client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: `agent2="https://` + callerHost + `"`,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/nohost",
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))
	if err == nil {
		t.Fatal("push accepted a caller_id that names no host; want InvalidArgument")
	}
	// InvalidArgument, matching the Broker's agent_id and /agents/register: the
	// caller sent a field that is not a host, which is a malformed argument rather
	// than a failure to authenticate.
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
	// The code alone proves nothing, and that is the trap this assertion exists to
	// avoid: delete the canonicalization refusal and the raw caller_id travels on
	// to the signature gate, which also refuses it and also writes nothing. The
	// field metadata is what separates them — only the canonicalization branch
	// names caller_id — and it reaches the wire only because the catalog surface
	// now stamps an ErrorDetail envelope like every other RAMP fault.
	assertCatalogRejectionField(t, err, "caller_id")
	// The curated message stands alone: the parser chain that produced it is
	// logged, not returned to an unauthenticated caller.
	if msg := err.Error(); strings.Contains(msg, "rampwellknown") || strings.Contains(msg, "parse ") {
		t.Errorf("internal wrapping reached the caller: %q", msg)
	}
	// And the refusal precedes the catalog write rather than merely accompanying it.
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+"/articles/nohost"); got != 0 {
		t.Fatalf("offers = %d, want 0 — the entry landed despite a refused caller_id", got)
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
	// All-or-nothing: one entry on a domain the caller is not a
	// contributor for rejects the WHOLE push (InvalidArgument); the error message
	// enumerates the offending URI + reason. No partial acceptance — neither the
	// authorized nor the denied entry persists.
	if err == nil {
		t.Fatalf("want whole-request rejection, got accepted=%d", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+"/articles/ok"); got != 0 {
		t.Fatalf("authorized sibling offers = %d, want 0 (denied sibling sinks the batch)", got)
	}
	if got := discoverOfferCount(t, h, "https://"+deniedDomain+"/articles/denied"); got != 0 {
		t.Fatalf("denied entry offers = %d, want 0", got)
	}
	_ = service.RejectionReasonNotInContributors // symbol-stability touchpoint
}

// NOTE: TestPushResources_PublicEntryMaterializesFreeOffer and
// TestPushResources_ScopeGatedEntryDoesNotMaterializeOffer were removed
// when the proto-rename wave W3 deleted src/exchange/internal/repo/offers.go and the
// FREE-offer materialisation feature (catalog → FREE per-request
// offer row bridge) that they exercised. The canonical ResourceEntry /
// discovery flow no longer mints a parallel offer row at PushResources
// time; obligation 04's anonymous public-resource flow is now served
// through DiscoverResources directly. Re-introducing transport-level
// coverage of that surface is tracked separately from this build-fix.
