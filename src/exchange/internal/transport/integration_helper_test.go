//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"connectrpc.com/validate"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

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
	resolver *helpers.StaticKeyResolver
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
	// sor is the account System of Record the Register flow depends on. nil → a
	// fresh in-memory SoR so every harness constructs a valid service even when it
	// never calls Register (production wiring is ST-5's job; the harness needs the
	// dep now). Register tests inject their own to assert account state.
	sor sor.Adapter
	// defaultTenantDomain names the single tenant Register reads its
	// activate_new_agents_by_default policy from (ADR-021 §5 decision 1). Empty for
	// harnesses that do not exercise Register.
	defaultTenantDomain string
	// billingRefGen overrides the billing_ref generator; nil → uuid.NewString
	// inside NewExchangeService. Register tests inject a deterministic counter.
	billingRefGen service.BillingRefGen
	// trustProxyHeaders mirrors RAMP_TRUST_PROXY_HEADERS: wire the
	// forwarded-header rewrite into WrapPublicSurface, the proxied deployment
	// shape (client signs https, service socket sees plain HTTP).
	trustProxyHeaders bool
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
		repo.NewCatalogRepo(deps.queries), repo.NewTenantReadRepo(deps.queries),
		deps.registry, deps.manifests, sharedb.PoolRunner{Pool: deps.pool},
		harnessExchangeDomain,
	)
	// Mirror production (cmd/server exchangeSupportedProfiles): the CatalogService
	// must know the advertised profiles so rebuild() pre-renders CoMP — set
	// before any Bootstrap/push, else the comp cache is empty and the
	// CoMP integration suite goes red.
	catalogSvc.SetSupportedProfiles([]string{"ramp-news-v1", "ramp-comp-v1"})
	// NOTE: the SetOfferRepo / FREE-offer materialisation bridge was
	// removed by the proto-rename wave W3 along with src/exchange/internal/repo/offers.go.
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
	sorAdapter := deps.sor
	if sorAdapter == nil {
		sorAdapter = sor.NewInMemoryAdapter()
	}
	exchangeSvc := service.NewExchangeService(service.ExchangeDeps{
		TxRunner:      txRunner,
		Catalog:       catalogSvc,
		Tenants:       repo.NewTenantReadRepo(deps.queries),
		Agents:        repo.NewAgentRepo(deps.queries),
		AgentReg:      deps.registry,
		Transactions:  repo.NewTransactionRepo(deps.queries),
		Obligations:   repo.NewObligationRepo(deps.queries),
		Evidence:      repo.NewEvidenceRepo(deps.queries),
		FeeOverrides:  repo.NewFeeOverrideRepo(deps.queries),
		Billing:       deps.bill,
		OfferSigner:   deps.signer,
		KeyStore:      svcKeyStore,
		SoR:           sorAdapter,
		BillingRefGen: deps.billingRefGen,
		// SupportedProfiles mirrors production (cmd/server/main.go
		// exchangeSupportedProfiles): the Exchange advertises + projects
		// ramp-comp-v1, so profile-aware discovery renders the CoMP ext.
		Config: service.ExchangeConfig{
			Exchange:            harnessExchangeDomain,
			SupportedProfiles:   []string{"ramp-news-v1", "ramp-comp-v1"},
			DefaultTenantDomain: deps.defaultTenantDomain,
		},
		Clk: deps.clk,
	})

	// Production parity (cmd/server/main.go::registerConnect): the ExchangeService
	// Connect handler is built via connectserver.NewExchangeServiceHandler which
	// wraps request-id (outermost) → RFC 9421 verify middleware → connect
	// interceptors (protovalidate bidirectional). The resolver and replay store for
	// the ExchangeService surface are constructed inline from httpsigKeys +
	// maxSignatures, mirroring cmd/server buildHTTPSigDeps / registerConnect.
	// CatalogService uses its own per-contributor signature check and is registered
	// with plain rampconnect.NewCatalogServiceHandler (no global verify gate).
	// Omitting protovalidate or the EmitUnpopulated codec made the harness silently
	// accept production-invalid requests OR fork the response wire shape; the wiring
	// below is the EXACT ServerOption set the production ExchangeService handler
	// wires (cmd/server/main.go::registerConnect). WithValidation(Strict) ALONE
	// installs the SDK's bidirectional protovalidate interceptor (requests +
	// responses + error details, via sdkconnect.NewValidateInterceptor) — a separate
	// WithInterceptors(validate...) would only re-add the same shared engine, so
	// production wires none and neither does this harness. WithEmitUnpopulated keeps
	// zero-valued response fields on the JSON wire (the platform JSON contract), and
	// WithOnReject audit-logs gate rejections — both present in production.
	resolver := helpers.NewStaticKeyResolver(deps.httpsigKeys)
	replayAdapter := replay.NewCoreAdapter(replay.NewMemoryStore(time.Now))
	svrOpts := []connectserver.ServerOption{
		connectserver.WithKeyResolver(resolver),
		connectserver.WithReplayStore(replayAdapter),
		connectserver.WithMaxSignatures(deps.maxSignatures),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		connectserver.WithOnReject(transport.LogHTTPSigReject),
		// Production parity: the same request-body read cap the server wires
		// (cmd/server/main.go::registerConnect), so the harness enforces
		// WithReadMaxBytes exactly as production does.
		connectserver.WithHandlerOptions(connect.WithReadMaxBytes(transport.MaxRPCReadBytes)),
	}
	mux := http.NewServeMux()
	exchangePath, exchangeHandler := connectserver.NewExchangeServiceHandler(
		transport.NewExchangeHandler(exchangeSvc), svrOpts...,
	)
	mux.Handle(exchangePath, exchangeHandler)
	codecOpt := connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec())
	validateOpt := connect.WithInterceptors(validate.NewInterceptor())
	// The read cap rides on the catalog mount too, matching production
	// (cmd/server/main.go). Without it an over-cap catalog push is refused in
	// production and accepted in every integration test.
	readCapOpt := connect.WithReadMaxBytes(transport.MaxRPCReadBytes)
	catalogPath, catalogHandler := rampconnect.NewCatalogServiceHandler(
		transport.NewCatalogHandler(catalogSvc, deps.registry), codecOpt, validateOpt, readCapOpt)
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
		Domain:            harnessExchangeDomain,
		Endpoint:          "/ramp.v1.ExchangeService",
		CatalogEndpoint:   "/ramp.v1.CatalogService",
		BaseCurrency:      "USD",
		SupportedProfiles: []string{"ramp-news-v1"},
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

	// ExchangeService verification is handled by
	// connectserver.NewExchangeServiceHandler registered above;
	// CatalogSignatureMiddleware handles the Catalog path. trustProxyHeaders
	// wires the same forwarded-header rewrite production wires under
	// RAMP_TRUST_PROXY_HEADERS.
	server := httptest.NewServer(transport.WrapPublicSurface(deps.logger, mux,
		runhttp.PublicSurfaceOptions{TrustProxyHeaders: deps.trustProxyHeaders}))
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

// newSigningTransport builds the canonical RAMP RFC 9421 signing
// http.RoundTripper (sdk/go/core.NewSigningTransport) so tests exercise the
// real middleware path with byte-identical signatures to production. Both
// ExchangeService and CatalogService /ramp.* paths are signed (the
// CatalogService gets verified by CatalogSignatureMiddleware downstream;
// the global httpsig gate excludes Catalog via the predicate but the
// per-contributor signer still requires the same outbound signature).
// Non-/ramp.* paths (e.g. /exchange/v1/agents/register) pass through
// unsigned — the shared transport skips them.
//
// expires is sourced from a per-transport monotonic counter
// (seeded at the wall-clock second) rather than the wall clock. The signing
// library stamps created=now() itself (no caller override), so expires is
// the sole caller-controlled freshness axis; a strictly-increasing expires
// is what keeps each on-the-wire signature unique. Without it, two
// back-to-back calls within the same second carry identical body +
// identical created + identical expires, producing the same signature, and
// the replay store at the global httpsig
// middleware rejects the second as a replay — even when the test is
// exercising service-layer idempotency (e.g.
// TestExecuteTransaction_Idempotency). Real clients retrying after a
// network blip naturally advance the clock per retry; the counter
// simulates that. The +3600 keeps the value inside the verifier's window
// check while the increment guarantees signature uniqueness.
func newSigningTransport(base http.RoundTripper, keyID string, priv ed25519.PrivateKey) http.RoundTripper {
	var counter atomic.Int64
	counter.Store(time.Now().Unix())
	// Both axes derive from the monotonic counter so back-to-back signatures
	// stay unique (the replay-store dodge). The +3600 keeps expires inside the
	// verifier's freshness window; created is the counter base so created ≤ expires.
	win := core.Window(func() (created, expires int64) {
		base := counter.Add(1)
		return base, base + 3600
	})
	// After the WBA split keyID names the signer's directory (Signature-Agent);
	// the RFC 9421 keyid is priv's RFC 7638 thumbprint.
	return core.NewSigningTransport(mustSigner(priv), base,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(keyID),
		core.WithWindow(win),
	)
}

// mustSigner derives the thumbprint keyid and builds the Ed25519 signer.
func mustSigner(priv ed25519.PrivateKey) helpers.Signer {
	keyid, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	signer, err := helpers.NewEd25519Signer(keyid, priv)
	if err != nil {
		panic(err)
	}
	return signer
}

// mustSigningClient wires the ingest push path's signed client for tests.
func mustSigningClient(t *testing.T, kid string, priv ed25519.PrivateKey) *http.Client {
	t.Helper()
	client, err := ingest.NewSigningClient(kid, priv, nil)
	if err != nil {
		t.Fatalf("build signing client: %v", err)
	}
	return client
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
	// billingRef is the account handle the default agent-test caller was
	// registered under during bring-up (ADR-021 D5): the charge path
	// keys the ledger account on this ref, not on the agent id, so every test that
	// seeds or asserts a balance reads it through h.billingRef instead of
	// hardcoding the account key. Empty when the harness opted out of registration
	// (harnessOptions.skipRegister) — an UNregistered agent has no ref.
	billingRef string
	// callerPub is the Ed25519 public key the default agent-test caller signs
	// with — the key the httpsig middleware verifies and the delivery-URL
	// binding derives its RFC 7638 thumbprint from (ADR-013). It is ALSO the
	// agent-test agents-row registered key, so the body offer-acceptance
	// verifies against it.
	callerPub ed25519.PublicKey
	// callerPriv is the matching private key the default caller signs both the
	// transport request AND the body offer-acceptance with. Also
	// exposed for multisig test setup (the superseded agent+broker harnesses).
	callerPriv ed25519.PrivateKey
	// resolver lets cross-tenant + broker-relay tests register extra
	// caller keyIDs dynamically (see addCaller below).
	resolver *helpers.StaticKeyResolver
	// baseTransport is the underlying RoundTripper Connect-Go clients
	// chain their signing transports onto.
	baseTransport http.RoundTripper
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
	// agentPub/agentPriv is the seeded agent's Ed25519 key. The agents row is
	// upserted with agentPub, so a caller that signs with agentPriv and names
	// this agent as its Signature-Agent satisfies the identity↔key binding (the
	// verified key must equal the key the directory pins).
	agentPub  ed25519.PublicKey
	agentPriv ed25519.PrivateKey
}

// deferredRSAKeyRef mirrors the production default RAMP_DEMO_RSA_KEY_REF
// ("cf-rsa-primary"): the ref installRSAKey (cmd/server/keys.go) registers the
// deferred refusal provider under when the Exchange boots without RSA material.
const deferredRSAKeyRef = "cf-rsa-primary"

// setupExchangeTestDB resets the shared package Postgres to its migrated
// baseline (see TestMain), inserts a tenant with an Ed25519 signing key, and
// upserts a single agent under agentID. Shared across harnesses so the DB
// boilerplate lives in exactly one place.
func setupExchangeTestDB(t *testing.T, agentID string) exchangeDBFixture {
	return setupExchangeTestDBDeferredRSA(t, agentID, false)
}

// setupExchangeTestDBDeferredRSA is setupExchangeTestDB with a choice of tenant
// signing scheme. deferredRSA=true seeds the tenant on AWS_CLOUDFRONT_RSA with
// its rsa_key_ref resolving only to the deferred-boot refusal provider — the
// exact shape installRSAKey wires when the Exchange starts without an RSA key —
// so transport tests can drive the FailedPrecondition refusal end to end.
func setupExchangeTestDBDeferredRSA(t *testing.T, agentID string, deferredRSA bool) exchangeDBFixture {
	t.Helper()
	ctx := context.Background()
	logger := testutil.DiscardLogger()
	pool := acquireTestDB(t, ctx)

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

	insert := sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   ed25519Ref,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}
	if deferredRSA {
		insert.SigningScheme = sqlc.RampSigningSchemeAWSCLOUDFRONTRSA
		insert.RsaKeyRef = pgtype.Text{String: deferredRSAKeyRef, Valid: true}
		insert.CloudfrontKeyPairID = pgtype.Text{String: "cf-deferred-test", Valid: true}
		keystore.PutRSAFunc(deferredRSAKeyRef, func() (*rsa.PrivateKey, error) {
			return nil, fmt.Errorf(
				"%w — set RAMP_RSA_PRIVATE_PEM or RAMP_RSA_PRIVATE_PEM_FILE",
				signing.ErrRSAKeyUnavailable)
		})
	}
	if _, err := queries.InsertTenant(ctx, insert); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent ed25519 gen: %v", err)
	}
	seedAgent(t, ctx, queries, agentID, agentPub)

	return exchangeDBFixture{
		ctx:          ctx,
		logger:       logger,
		pool:         pool,
		agentPub:     agentPub,
		agentPriv:    agentPriv,
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
	// logger overrides the service logger; nil → the discard logger from
	// setupExchangeTestDB. Pass a JSON handler over a safeBuffer to assert
	// audit-log lines (e.g. denial outcomes).
	logger *slog.Logger
	// maxSignatures bounds the inbound signature (hop) chain depth at the
	// global httpsig gate; 0 → unbounded. Set to mirror the production ceiling
	// (max_intermediary_hops + 1) when exercising the hop bound.
	maxSignatures int
	// manifests overrides the catch-all manifest cache; nil → an
	// allowAllManifestCache that authorizes the caller and attests
	// harnessResourceOwner. Inject a non-attesting cache to drive the
	// resource-owner rejection path.
	manifests service.ManifestCache
	// skipRegister, when true, leaves the default agent-test caller UNregistered
	// (no billing_ref on its agents row). Bring-up neither calls the Register RPC
	// nor sets h.billingRef, so a paid transaction denies before Authorize
	// (DENIAL_REASON_BILLING_REF_INACTIVE). Used by the unregistered-agent negative
	// path; the default (false) registers the caller so paid tests can charge.
	skipRegister bool
	// sor overrides the account System of Record the service is wired with;
	// nil → a fresh in-memory SoR inside startExchangeServer. Inject to hold the
	// concrete adapter (e.g. to flip an account's active flag the way the
	// operator would, or to wrap it in the production sor.CachingAdapter).
	sor sor.Adapter
	// deferredRSATenant seeds the default tenant on the AWS_CLOUDFRONT_RSA
	// scheme whose RSA key resolves only to the deferred-boot refusal provider
	// (see setupExchangeTestDBDeferredRSA), driving the FailedPrecondition
	// refusal through the full transport surface.
	deferredRSATenant bool
}

// newTestHarnessWith is the shared bring-up behind every transport integration
// harness: a Postgres testcontainer with exchange migrations applied, a tenant
// seeded with an Ed25519 signing key, an agent-test agent, the billing
// adapter(s) from opts, and a live httptest server on the production middleware
// chain. newTestHarness, newTestHarnessWithClock, and newRecordingHarness all
// delegate here so the bring-up lives in exactly one place (Testing Doctrine #7).
//
// Unless opts.skipRegister is set, bring-up also registers the agent-test caller
// for billing through the public Register RPC (minting its billing_ref and
// exposing it as h.billingRef) so paid transactions can charge; skipRegister
// leaves the agent unregistered, so its paid transactions are denied before
// Authorize.
func newTestHarnessWith(t *testing.T, opts harnessOptions) *testHarness {
	t.Helper()
	fx := setupExchangeTestDBDeferredRSA(t, "agent-test", opts.deferredRSATenant)
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
	// R4: the agent's REGISTERED key (agents row) is the key the body
	// offer-acceptance verifies against. setupExchangeTestDB seeded agent-test
	// with a stub key; re-seed it with the caller's real signing key so the
	// transport signature and the body acceptance share one identity.
	seedAgent(t, ctx, queries, callerID, callerPub)
	registry := newAllowAllRegistry()
	registry.put(callerID, callerPub)
	var manifests service.ManifestCache = newAllowAllManifestCache(callerID)
	if opts.manifests != nil {
		manifests = opts.manifests
	}

	inner := opts.inner
	if inner == nil {
		// Seed the balance under the billing_ref the caller will be registered
		// under, NOT the agent id: after the billing_ref repoint the charge path keys the ledger
		// account on the ref. The ref is known ahead of registration because the
		// harness injects a deterministic billing_ref generator (see the
		// startExchangeServer deps below), so the account exists before Register's
		// EnsureAgentAccount runs (which then no-ops over the seeded balance).
		inner = billing.NewInMemoryAdapter(billing.InMemoryOptions{
			Balances: map[string]billing.Amount{
				defaultCallerBillingRef: mustBillingAmount(t, "10.00", "USD"),
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
		// The httpsig resolver keys by RFC 9421 keyid — an RFC 7638 thumbprint
		// after the WBA split — not by the caller's directory identity.
		httpsigKeys:      map[string]ed25519.PublicKey{rwtestutil.MustThumbprintPriv(callerPriv): callerPub},
		clk:              srvClk,
		txRunner:         opts.txRunner,
		keystoreOverride: opts.keystore,
		maxSignatures:    opts.maxSignatures,
		// Register (bring-up below) needs the default tenant to resolve
		// its activation policy, and a deterministic billing_ref so the seeded
		// balance's account key is known ahead of time.
		defaultTenantDomain: tenantDomain,
		billingRefGen:       func() string { return defaultCallerBillingRef },
		sor:                 opts.sor,
	})
	if err := srv.catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, callerPriv)}
	exchangeClient := rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC())

	// Register the caller through the public Register RPC: the same
	// production path a real agent takes to mint its billing_ref, create its
	// ledger account, and store the ref on its agents row. After this the paid
	// charge path authorizes against h.billingRef. skipRegister leaves the caller
	// unregistered (empty ref) for the negative path.
	var billingRef string
	if !opts.skipRegister {
		billingRef = registerDefaultCaller(t, ctx, exchangeClient)
	}

	return &testHarness{
		t:              t,
		ctx:            ctx,
		pool:           pool,
		queries:        queries,
		offerSigner:    offerSigner,
		catalog:        srv.catalogSvc,
		exchange:       srv.exchange,
		exchangeClient: exchangeClient,
		catalogClient:  rampconnect.NewCatalogServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		server:         srv.server,
		billing:        inner,
		keystore:       keystore,
		clk:            opts.clk,
		tenantID:       tenantID,
		tenantDomain:   tenantDomain,
		billingRef:     billingRef,
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
	client, _, _ := h.addCallerWithKey(t, agentID, requesterType)
	return client
}
