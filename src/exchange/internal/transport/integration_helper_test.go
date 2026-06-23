//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

// allowAllRegistry stores callers in memory and always accepts their
// registration. Tests that exercise the happy PushResources path use this to
// skip the RFC 9421 signature gate without wiring a full fixture origin.
type allowAllRegistry struct {
	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
}

func newAllowAllRegistry() *allowAllRegistry {
	return &allowAllRegistry{keys: map[string]ed25519.PublicKey{}}
}

func (r *allowAllRegistry) put(id string, pub ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[id] = pub
}

func (r *allowAllRegistry) LookupPublicKey(_ context.Context, id string) (ed25519.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[id]; ok {
		return k, nil
	}
	return nil, agentreg.ErrUnknown
}

func (r *allowAllRegistry) RegisterFromManifest(_ context.Context, _ string, _ string) error {
	return errors.New("allowAllRegistry: self-signup not supported in tests")
}

// allowAllManifestCache returns a publisher manifest that lists the caller as
// a catalog_contributor for the requested domain; used to bypass Gate 2 in the
// catch-all test harness. It satisfies service.ManifestCache (Get only).
type allowAllManifestCache struct{ caller string }

func (c *allowAllManifestCache) Get(_ context.Context, domain string) (*rampwellknown.Manifest, error) {
	return &rampwellknown.Manifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: domain,
		CatalogContributors: []*rampv1.CatalogContributor{
			{Domain: c.caller, Relationship: "publisher"},
		},
	}, nil
}

// exchangeServerFixture bundles an httptest server wired with the Exchange
// Connect-Go handlers for CatalogService + ExchangeService, along with the
// baseTransport callers use to build signing HTTP clients on top.
type exchangeServerFixture struct {
	server        *httptest.Server
	baseTransport http.RoundTripper
	exchange      *service.ExchangeService
	catalogSvc    *service.CatalogService
	// resolver exposed so multi-agent tests (cross-tenant, broker-relay)
	// can register additional keyIDs dynamically via resolver.Put after
	// server start.
	resolver *httpsig.StaticResolver
	// rsaPub / rsaKid carry the CloudFront RSA verify key. RAMP v1 no longer
	// publishes it at a well-known route, so onboarding tests read it from the
	// fixture to verify CloudFront-signed URLs.
	rsaPub *rsa.PublicKey
	rsaKid string
}

// exchangeServerDeps names the pieces startExchangeServer needs; grouping them
// here keeps the call site readable and stops the argument list from growing
// past the per-file function-arg lint budget.
type exchangeServerDeps struct {
	pool      *pgxpool.Pool
	queries   sqlc.Querier
	registry  agentreg.Registry
	manifests service.ManifestCache
	bill      billing.Adapter
	signer    *signing.Ed25519Signer
	keystore  *signing.InMemoryKeyStore
	logger    *slog.Logger
	// httpsigKeys registers caller pubkeys with the global httpsig
	// middleware that wraps the mux (mirror of production wiring in
	// cmd/server/main.go::buildWrapped). Tests that issue any /ramp.* RPC
	// MUST register the signer's keyID + pubkey here; the global gate
	// will reject the request with httpsig.ErrUnknownKey otherwise.
	httpsigKeys map[string]ed25519.PublicKey
	// clk is optional. nil → clock.System{}. Pass a DeterministicClock to
	// control time in tests that exercise window-expiry logic.
	clk clock.Clock
	// txRunner overrides the service's transaction runner. nil →
	// PoolRunner{Pool}. A failing runner drives the persist-failure hot path
	txRunner sharedb.TxRunner
	// keystoreOverride replaces the KeyStore the ExchangeService consults
	// when minting signed URLs. nil → deps.keystore. A failing keystore drives
	// the URL-sign-failure hot path. The well-known RSA wiring
	// still uses deps.keystore.
	keystoreOverride signing.KeyStore
	// maxSignatures bounds the inbound signature (hop) chain depth, mirroring
	// the production ceiling (cmd/server/main.go: max_intermediary_hops + 1).
	// 0 → unbounded — the default for tests that do not exercise the hop bound.
	maxSignatures int
}

// startExchangeServer wires the Exchange's public HTTP surface — Connect-Go
// CatalogService + ExchangeService, the three /.well-known/ routes, and the
// public agents/register handler — onto a fresh mux behind
// RequestIDMiddleware + httpsig.Middleware + CatalogSignatureMiddleware,
// serves it via httptest, and returns the fixture. Mirror of
// cmd/server/main.go::buildWrapped so the integration tests exercise the
// SAME middleware chain as production (per ADR-008 D1). Admin-plane
// routes are deliberately absent; the admin_removed_e2e_test asserts that.
//
// Callers still own DB bring-up, tenant seeding, and any post-wiring
// bootstrap (e.g. catalog.Bootstrap). Callers MUST also register every
// signer's keyID + pubkey via deps.httpsigKeys; the global gate rejects
// unknown keyids with httpsig.ErrUnknownKey.
func startExchangeServer(t *testing.T, deps exchangeServerDeps) *exchangeServerFixture {
	t.Helper()
	catalogSvc := service.NewCatalogService(
		repo.NewCatalogRepo(deps.queries), deps.registry, deps.manifests, sharedb.PoolRunner{Pool: deps.pool},
	)
	// NOTE: the SetOfferRepo / FREE-offer materialisation bridge (j8fh) was
	// removed by t3vk W3 along with src/exchange/internal/repo/offers.go.
	// Obligation 04's anonymous public-resource flow is now served by
	// DiscoverResources directly; no parallel offer-row seed runs here.
	txRunner := sharedb.TxRunner(sharedb.PoolRunner{Pool: deps.pool})
	if deps.txRunner != nil {
		txRunner = deps.txRunner
	}
	var svcKeyStore signing.KeyStore = deps.keystore
	if deps.keystoreOverride != nil {
		svcKeyStore = deps.keystoreOverride
	}
	exchangeSvc := service.NewExchangeService(service.ExchangeDeps{
		TxRunner:     txRunner,
		Catalog:      catalogSvc,
		Tenants:      repo.NewTenantRepo(deps.queries),
		Agents:       repo.NewAgentRepo(deps.queries),
		AgentReg:     deps.registry,
		Transactions: repo.NewTransactionRepo(deps.queries),
		Obligations:  repo.NewObligationRepo(deps.queries),
		Billing:      deps.bill,
		OfferSigner:  deps.signer,
		KeyStore:     svcKeyStore,
		Config:       service.ExchangeConfig{Exchange: "exchange.ramp.test"},
		Clk:          deps.clk,
		Logger:       deps.logger,
	})

	mux := http.NewServeMux()
	exchangePath, exchangeHandler := rampconnect.NewExchangeServiceHandler(transport.NewExchangeHandler(exchangeSvc))
	catalogPath, catalogHandler := rampconnect.NewCatalogServiceHandler(transport.NewCatalogHandler(catalogSvc, deps.registry))
	mux.Handle(exchangePath, exchangeHandler)
	mux.Handle(catalogPath, catalogHandler)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const rsaKid = "cf-test"
	// The keystore entry under rsaKid lets tests whose tenant uses
	// AWS_CLOUDFRONT_RSA resolve the RSA key when minting CloudFront URLs.
	// RAMP v1 no longer publishes it at a well-known route (CloudFront verifies
	// natively against a trusted key group); tests read fixture.rsaPub instead.
	deps.keystore.PutRSA(rsaKid, rsaPriv)
	wk, err := wellknown.New(wellknown.Config{
		Domain:            "exchange.ramp.test",
		Endpoint:          "/ramp.v1.ExchangeService",
		CatalogEndpoint:   "/ramp.v1.CatalogService",
		BaseCurrency:      "USD",
		SupportedProfiles: []string{"ramp-news-v1"},
		OfferKeyID:        "exchange-primary",
		OfferKey:          deps.signer.PublicKey(),
		KeyNotBefore:      time.Unix(1700000000, 0).UTC(),
		KeyNotAfter:       time.Unix(1700000000, 0).UTC().Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("wellknown: %v", err)
	}
	wk.RegisterRoutes(mux)

	transport.NewAgentsRegisterHandler(deps.registry, transport.AgentsRegisterOptions{}).
		RegisterRoutes(mux)

	// Production parity: drive the SAME shared constructor cmd/server's
	// buildWrapped uses, so the integration suite exercises the real wiring —
	// including the hop-bound MaxSignatures (deps.maxSignatures), which
	// buildWrapped sets to max_intermediary_hops + 1.
	resolver := httpsig.NewStaticResolver(deps.httpsigKeys)
	replay := httpsig.NewMemoryReplayStore(time.Now)
	server := httptest.NewServer(
		transport.WrapPublicSurface(deps.logger, resolver, replay, deps.maxSignatures, mux),
	)
	t.Cleanup(server.Close)

	base := server.Client().Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &exchangeServerFixture{
		server:        server,
		baseTransport: base,
		exchange:      exchangeSvc,
		catalogSvc:    catalogSvc,
		resolver:      resolver,
		rsaPub:        &rsaPriv.PublicKey,
		rsaKid:        rsaKid,
	}
}

// signingClientTransport is an http.RoundTripper that signs outbound
// /ramp.* requests with the given Ed25519 key so tests can exercise the
// real middleware path. Both ExchangeService and CatalogService paths
// are signed (the CatalogService gets verified by CatalogSignatureMiddleware
// downstream; the global httpsig gate excludes Catalog via the predicate
// but the per-contributor signer still requires the same outbound
// signature). Non-/ramp.* paths (e.g. /exchange/v1/agents/register)
// pass through unsigned — the predicate returns false for them.
type signingClientTransport struct {
	base  http.RoundTripper
	keyID string
	priv  ed25519.PrivateKey
	// counter monotonically increments per signed request to guarantee
	// each signature is unique on the wire. Without this, two
	// back-to-back calls within the same second carry identical body
	// + identical `created` and the replay store at the global httpsig
	// middleware rejects the second as a replay — even when the test
	// is exercising service-layer idempotency (e.g.
	// TestExecuteTransaction_Idempotency). Real clients retrying after
	// a network blip naturally use a fresh second per retry; the test
	// counter simulates that.
	counter atomic.Int64
}

func newSigningTransport(base http.RoundTripper, keyID string, priv ed25519.PrivateKey) *signingClientTransport {
	t := &signingClientTransport{
		base:  base,
		keyID: keyID,
		priv:  priv,
	}
	t.counter.Store(time.Now().Unix())
	return t
}

func (t *signingClientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && strings.HasPrefix(req.URL.Path, "/ramp.") && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.ContentLength = int64(len(body))
		if req.Host == "" {
			req.Host = req.URL.Host
		}
		// Use the RAMP-required coverage set (@method, @target-uri,
		// content-digest, authorization) so the production verifier
		// at internal/httpsig/verifier.go::enforceRequiredComponents
		// accepts the signature. The demo SignRequest covers a
		// different set (@path + @authority instead of @target-uri,
		// no authorization) and would fail enforcement.
		created := t.counter.Add(1)
		if err := httpsig.SignRequestRAMP(req, body, t.keyID, t.priv, created, created+3600); err != nil {
			return nil, err
		}
	}
	return t.base.RoundTrip(req)
}

// testHarness bundles the live server + handles used by each test.
type testHarness struct {
	t              *testing.T
	ctx            context.Context
	pool           *pgxpool.Pool
	queries        *sqlc.Queries
	offerSigner    *signing.Ed25519Signer
	catalog        *service.CatalogService
	exchange       *service.ExchangeService
	exchangeClient rampconnect.ExchangeServiceClient
	catalogClient  rampconnect.CatalogServiceClient
	server         *httptest.Server
	billing        *billing.InMemoryAdapter
	keystore       *signing.InMemoryKeyStore
	clk            *clock.DeterministicClock // nil when harness uses real clock
	tenantID       string
	tenantDomain   string
	// callerPub is the Ed25519 public key the default agent-test caller signs
	// with — the key the httpsig middleware verifies and the delivery-URL
	// binding derives its RFC 7638 thumbprint from (ADR-013).
	callerPub ed25519.PublicKey
	// callerPriv is the Ed25519 private key for the default agent-test caller.
	// Exposed for multisig test setup.
	callerPriv ed25519.PrivateKey
	// resolver lets cross-tenant + broker-relay tests register extra
	// caller keyIDs dynamically (see addCaller below).
	resolver *httpsig.StaticResolver
	// baseTransport is the underlying RoundTripper Connect-Go clients
	// chain their signing transports onto.
	baseTransport http.RoundTripper
	// multisigClient is set only when a multisig harness is created; signs
	// requests with both agent and broker keys.
	multisigClient rampconnect.ExchangeServiceClient
}

// exchangeDBFixture carries the shared test infrastructure produced by
// setupExchangeTestDB: a live testcontainers-backed pool, generated sqlc
// queries, a freshly inserted tenant (with its Ed25519 signing key in
// keystore), and one upserted agent whose id is supplied by the caller.
type exchangeDBFixture struct {
	ctx          context.Context
	logger       *slog.Logger
	pool         *pgxpool.Pool
	queries      *sqlc.Queries
	keystore     *signing.InMemoryKeyStore
	tenantID     string
	tenantDomain string
}

// setupExchangeTestDB brings up a Postgres testcontainer, applies exchange
// migrations, inserts a tenant with an Ed25519 signing key, and upserts a
// single agent under agentID. Shared across harnesses so the DB-bringup
// boilerplate lives in exactly one place.
func setupExchangeTestDB(t *testing.T, agentID string) exchangeDBFixture {
	t.Helper()
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)

	queries := sqlc.New(pool)
	tenantID := "t_" + uuid.NewString()
	tenantDomain := tenantID + ".example"

	keystore := signing.NewInMemoryKeyStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	ed25519Ref := "secret://ed25519/" + tenantID
	keystore.PutEd25519(ed25519Ref, pub, priv)

	if _, err := queries.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   ed25519Ref,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := queries.UpsertAgent(ctx, sqlc.UpsertAgentParams{
		AgentID:       agentID,
		PublicKey:     []byte("stub-agent-key"),
		RequesterType: sqlc.RampRequesterTypeAGENT,
	}); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}

	return exchangeDBFixture{
		ctx:          ctx,
		logger:       logger,
		pool:         pool,
		queries:      queries,
		keystore:     keystore,
		tenantID:     tenantID,
		tenantDomain: tenantDomain,
	}
}

// newTestHarness brings up the standard transport-layer integration fixture:
// a Postgres testcontainer with exchange migrations applied, a tenant seeded
// with an Ed25519 signing key, an `agent-test` agent, the in-memory billing
// adapter prepopulated with a 10 USD balance, and a live httptest server
// wired to the surviving DiscoverResources / ExecuteTransaction /
// ReportUsage surface. v1 carries no biscuit/delegation injection — every
// inbound request is authenticated by its RFC 9421 signature alone.
func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	return newTestHarnessWithClock(t, nil)
}

// newTestHarnessWithClock is newTestHarness with an injected clock.
// Pass a *clock.DeterministicClock to control time (e.g. for window expiry tests).
// nil uses clock.System{} inside the ExchangeService.
func newTestHarnessWithClock(t *testing.T, clk *clock.DeterministicClock) *testHarness {
	t.Helper()
	return newTestHarnessWith(t, harnessOptions{clk: clk})
}

// newRecordingHarnessCapturingLogs is newRecordingHarness with the service
// logger wired to a JSON handler over the returned safeBuffer, so one test can
// assert BOTH billing-call observations (via the recordingAdapter) and
// audit-log lines (via the buffer). Bring-up delegates to newRecordingHarnessWith
// (Testing Doctrine #7). The buffer is safe for concurrent server/test access.
func newRecordingHarnessCapturingLogs(t *testing.T) (*testHarness, *recordingAdapter, *safeBuffer) {
	t.Helper()
	buf := &safeBuffer{}
	h, rec := newRecordingHarnessWith(t, harnessOptions{logger: slog.New(slog.NewJSONHandler(buf, nil))})
	return h, rec, buf
}

// harnessOptions parameterises newTestHarnessWith. All fields are optional.
type harnessOptions struct {
	// clk controls the service clock; nil → clock.System{}.
	clk *clock.DeterministicClock
	// inner is the balance-bearing adapter exposed as testHarness.billing for
	// balance assertions; nil → a fresh InMemoryAdapter seeded with 10 USD for
	// agent-test.
	inner *billing.InMemoryAdapter
	// server is the adapter the Exchange server actually calls; nil → inner.
	// Pass a wrapper (e.g. recordingAdapter) to observe billing calls while
	// inner keeps the real balance semantics.
	server billing.Adapter
	// txRunner overrides the service's transaction runner; nil → PoolRunner.
	// A failing runner drives the persist-failure hot path.
	txRunner sharedb.TxRunner
	// keystore overrides the service's KeyStore; nil → the harness's real
	// InMemoryKeyStore. A failing keystore drives the URL-sign-failure hot
	// path.
	keystore signing.KeyStore
	// logger overrides the service logger; nil → the io.Discard logger from
	// setupExchangeTestDB. Pass a JSON handler over a safeBuffer to assert
	// audit-log lines (e.g. denial outcomes).
	logger *slog.Logger
	// maxSignatures bounds the inbound signature (hop) chain depth at the
	// global httpsig gate; 0 → unbounded. Set to mirror the production ceiling
	// (max_intermediary_hops + 1) when exercising the hop bound.
	maxSignatures int
}

// newTestHarnessWith is the shared bring-up behind every transport integration
// harness: a Postgres testcontainer with exchange migrations applied, a tenant
// seeded with an Ed25519 signing key, an agent-test agent, the billing
// adapter(s) from opts, and a live httptest server on the production middleware
// chain. newTestHarness, newTestHarnessWithClock, and newRecordingHarness all
// delegate here so the bring-up lives in exactly one place (Testing Doctrine #7).
func newTestHarnessWith(t *testing.T, opts harnessOptions) *testHarness {
	t.Helper()
	fx := setupExchangeTestDB(t, "agent-test")
	ctx, logger, pool, queries, keystore := fx.ctx, fx.logger, fx.pool, fx.queries, fx.keystore
	tenantID, tenantDomain := fx.tenantID, fx.tenantDomain
	if opts.logger != nil {
		logger = opts.logger
	}

	offerSigner, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}

	// callerID is BOTH the httpsig keyID AND the seeded agent_id, mirroring
	// the production trust model where keyID == agent_id (implementation
	// plan Q1 decision). Catalog contributions, ExecuteTransaction, and
	// ReportUsage all sign with this key and authorize as this agent.
	callerID := "agent-test"
	callerPub, callerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("caller ed25519: %v", err)
	}
	registry := newAllowAllRegistry()
	registry.put(callerID, callerPub)
	manifests := &allowAllManifestCache{caller: callerID}

	inner := opts.inner
	if inner == nil {
		inner = billing.NewInMemoryAdapter(billing.InMemoryOptions{
			Balances: map[string]billing.Amount{
				callerID: mustBillingAmount(t, "10.00", "USD"),
			},
		})
	}
	serverBilling := opts.server
	if serverBilling == nil {
		serverBilling = inner
	}

	var srvClk clock.Clock
	if opts.clk != nil {
		srvClk = opts.clk
	}
	srv := startExchangeServer(t, exchangeServerDeps{
		pool: pool, queries: queries, registry: registry, manifests: manifests,
		bill: serverBilling, signer: offerSigner, keystore: keystore, logger: logger,
		httpsigKeys:      map[string]ed25519.PublicKey{callerID: callerPub},
		clk:              srvClk,
		txRunner:         opts.txRunner,
		keystoreOverride: opts.keystore,
		maxSignatures:    opts.maxSignatures,
	})
	if err := srv.catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, callerPriv)}

	return &testHarness{
		t:              t,
		ctx:            ctx,
		pool:           pool,
		queries:        queries,
		offerSigner:    offerSigner,
		catalog:        srv.catalogSvc,
		exchange:       srv.exchange,
		exchangeClient: rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		catalogClient:  rampconnect.NewCatalogServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		server:         srv.server,
		billing:        inner,
		keystore:       keystore,
		clk:            opts.clk,
		tenantID:       tenantID,
		tenantDomain:   tenantDomain,
		callerPub:      callerPub,
		callerPriv:     callerPriv,
		resolver:       srv.resolver,
		baseTransport:  srv.baseTransport,
	}
}

// addCaller registers an additional caller with the harness: generates a
// fresh Ed25519 key, puts the pubkey in the httpsig resolver, upserts the
// agents row with the supplied requesterType, and returns a Connect-Go
// ExchangeService client that signs with the new key. agentID becomes the
// caller's keyID AND its agent_id (Q1 trust mapping). requesterType is one
// of "AGENT" or "BROKER".
func (h *testHarness) addCaller(t *testing.T, agentID, requesterType string) rampconnect.ExchangeServiceClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("addCaller ed25519: %v", err)
	}
	h.resolver.Put(agentID, pub)
	if _, err := h.queries.UpsertAgent(h.ctx, sqlc.UpsertAgentParams{
		AgentID:       agentID,
		PublicKey:     pub,
		RequesterType: sqlc.RampRequesterType(requesterType),
	}); err != nil {
		t.Fatalf("upsert agent %q: %v", agentID, err)
	}
	client := &http.Client{Transport: newSigningTransport(h.baseTransport, agentID, priv)}
	return rampconnect.NewExchangeServiceClient(client, h.server.URL, connect.WithGRPC())
}

// addTenant inserts a fresh tenant row + signing key, and registers a
// caller for it via addCaller. Returns the new tenant_id + the new caller's
// ExchangeService client. Used by cross-tenant tests.
func (h *testHarness) addTenant(t *testing.T, tenantSlug, agentID string) (tenantID string, client rampconnect.ExchangeServiceClient) {
	t.Helper()
	tenantID = "t_" + tenantSlug
	tenantDomain := tenantSlug + ".example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("addTenant ed25519: %v", err)
	}
	keyRef := "secret://ed25519/" + tenantID
	h.keystore.PutEd25519(keyRef, pub, priv)
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   keyRef,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant %q: %v", tenantID, err)
	}
	client = h.addCaller(t, agentID, "AGENT")
	return tenantID, client
}

// enableBrokerRelay flips tenants.allow_broker_relay = true for the given
// tenant via the generated sqlc Querier.
func (h *testHarness) enableBrokerRelay(t *testing.T, tenantID string) {
	t.Helper()
	if err := h.queries.SetTenantAllowBrokerRelay(h.ctx, sqlc.SetTenantAllowBrokerRelayParams{
		TenantID:         tenantID,
		AllowBrokerRelay: true,
	}); err != nil {
		t.Fatalf("set allow_broker_relay: %v", err)
	}
}

// newTestHarnessWithBroker creates a test harness with multisig support:
// registers a broker, enables broker relay for the tenant, and creates a
// multisigClient that signs with both agent and broker keys.
func newTestHarnessWithBroker(t *testing.T) *testHarness {
	t.Helper()
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	h.addBrokerAndMultisigClient(t)
	return h
}

// newTestHarnessWithBrokerNoRelay creates a test harness with a broker but
// WITHOUT enabling broker relay (allow_broker_relay=false). Used to test
// rejection scenarios.
func newTestHarnessWithBrokerNoRelay(t *testing.T) *testHarness {
	t.Helper()
	h := newTestHarness(t)
	h.addBrokerAndMultisigClient(t)
	return h
}

// addBrokerAndMultisigClient registers a broker agent and creates a multisig
// client that signs with both agent and broker keys.
func (h *testHarness) addBrokerAndMultisigClient(t *testing.T) {
	t.Helper()
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("broker ed25519: %v", err)
	}
	brokerID := "broker.example"
	h.resolver.Put(brokerID, brokerPub)
	if _, err := h.queries.UpsertAgent(h.ctx, sqlc.UpsertAgentParams{
		AgentID:       brokerID,
		PublicKey:     brokerPub,
		RequesterType: sqlc.RampRequesterType("BROKER"),
	}); err != nil {
		t.Fatalf("upsert broker: %v", err)
	}
	h.multisigClient = newMultisigClient(h.baseTransport, h.server.URL,
		"agent-test", h.callerPriv, brokerID, brokerPriv)
}

// newMultisigClient creates a Connect-Go client that signs with both agent and
// broker keys (multisig). Agent signature first, broker signature appended.
func newMultisigClient(base http.RoundTripper, serverURL, agentID string, agentPriv ed25519.PrivateKey, brokerID string, brokerPriv ed25519.PrivateKey) rampconnect.ExchangeServiceClient {
	client := &http.Client{Transport: &multisigTransport{base, agentID, agentPriv, brokerID, brokerPriv}}
	return rampconnect.NewExchangeServiceClient(client, serverURL, connect.WithGRPC())
}

// multisigTransport adds both agent and broker signatures to requests.
type multisigTransport struct {
	base       http.RoundTripper
	agentID    string
	agentPriv  ed25519.PrivateKey
	brokerID   string
	brokerPriv ed25519.PrivateKey
}

// RoundTrip signs with agent key, then appends broker signature.
func (t *multisigTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	now := time.Now()
	created, expires := now.Unix(), now.Add(5*time.Minute).Unix()
	_ = httpsig.SignRequestRAMP(req, body, t.agentID, t.agentPriv, created, expires)
	_ = httpsig.AppendSignatureRAMP(req, body, t.brokerID, t.brokerPriv, created, expires)
	req.Body = io.NopCloser(bytes.NewReader(body))
	return t.base.RoundTrip(req)
}
