//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

// This file holds the Exchange HTTP server fixture: the httptest server wired
// with the CatalogService and ExchangeService mounts, and the Connect-JSON
// twins built over the same signed transport. The test harness that stands a
// database and a tenant up around it is in integration_helper_test.go, which
// this file was split out of when the two together crossed the test-file cap.

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
	// httpsigKeys registers caller pubkeys with the connectserver verify
	// middleware that wraps the mux (mirror of production wiring in
	// cmd/server/main.go::buildWrapped). Tests that issue any /ramp.* RPC
	// MUST register the signer's keyID + pubkey here; the global gate
	// will reject the request with helpers.ErrUnknownKey otherwise.
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
	// regSchema is the operator-configured registration schema the Register gate
	// enforces. nil → no schema published, so registration_data passes through
	// uninspected — the shape every harness that does not exercise the gate uses.
	regSchema *regschema.Schema
	// termsDigest is the terms digest this Exchange publishes. Empty → no terms
	// versioning, so a submitted digest is ignored and none is recorded.
	termsDigest string
	// trustProxyHeaders mirrors RAMP_TRUST_PROXY_HEADERS: wire the
	// forwarded-header rewrite into WrapPublicSurface, the proxied deployment
	// shape (client signs https, service socket sees plain HTTP).
	trustProxyHeaders bool
	// auditWrap decorates the pool-bound audit repo instead of replacing it, so
	// a test repo can delegate to real appends and start failing only when it is
	// armed. Same seam shape as txRunner above; nil leaves the real repo in
	// place. An audit append that fails INSIDE the registration transaction is
	// the only injection point that tells one transaction apart from two
	// sequential ones.
	auditWrap func(repo.AuditRepo) repo.AuditRepo
}

// startExchangeServer wires the Exchange's public HTTP surface — Connect-Go
// CatalogService + ExchangeService, the three /.well-known/ routes, and the
// public agents/register handler — onto a fresh mux behind
// RequestIDMiddleware + the connectserver verify middleware + CatalogSignatureMiddleware,
// serves it via httptest, and returns the fixture. Mirror of
// cmd/server/main.go::buildWrapped so the integration tests exercise the
// SAME middleware chain as production (per ADR-008 D1). Admin-plane
// routes are deliberately absent; the admin_removed_e2e_test asserts that.
//
// Callers still own DB bring-up, tenant seeding, and any post-wiring
// bootstrap (e.g. catalog.Bootstrap). Callers MUST also register every
// signer's keyID + pubkey via deps.httpsigKeys; the global gate rejects
// unknown keyids with helpers.ErrUnknownKey.
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
	auditRepo := repo.NewAuditRepo(deps.queries)
	if deps.auditWrap != nil {
		auditRepo = deps.auditWrap(auditRepo)
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
		Audit:         auditRepo,
		RegSchema:     deps.regSchema,
		BillingRefGen: deps.billingRefGen,
		// SupportedProfiles mirrors production (cmd/server/main.go
		// exchangeSupportedProfiles): the Exchange advertises + projects
		// ramp-comp-v1, so profile-aware discovery renders the CoMP ext.
		Config: service.ExchangeConfig{
			Exchange:            harnessExchangeDomain,
			SupportedProfiles:   []string{"ramp-news-v1", "ramp-comp-v1"},
			DefaultTenantDomain: deps.defaultTenantDomain,
			// Set explicitly, as cmd/server does: ExchangeConfig has no
			// currency default, so wiring that leaves this empty makes the
			// welcome-credit grant fail the billing gate. The harness runs on
			// the in-memory adapter, whose currency is billing.DemoCurrency.
			LedgerCurrency: billing.DemoCurrency,
			TermsDigest:    deps.termsDigest,
		},
		Clk: deps.clk,
	})

	// The ExchangeService Connect handler is built via
	// connectserver.NewExchangeServiceHandler, which wraps request-id (outermost)
	// → RFC 9421 verify middleware → connect interceptors (protovalidate
	// bidirectional). The resolver and replay store are constructed inline from
	// httpsigKeys + maxSignatures, mirroring cmd/server buildHTTPSigDeps.
	// CatalogService uses its own per-contributor signature check and is
	// registered with plain rampconnect.NewCatalogServiceHandler (no global
	// verify gate).
	resolver := helpers.NewStaticKeyResolver(deps.httpsigKeys)
	replayAdapter := replay.NewCoreAdapter(replay.NewMemoryStore(time.Now))
	// The recipient check, built from this harness's own Exchange domain — the
	// same value the served manifest and the issued offers carry. Production
	// mounts it on BOTH surfaces, so the harness does too: a request naming a
	// different Exchange has to be refused here exactly as it is in production.
	audience := audiencetest.MustInterceptor(t, harnessExchangeDomain)
	// Built by the function production builds it with, for the reason the catalog
	// mount below already gives. Written out here instead, the list drifted:
	// omitting protovalidate or the emit-unpopulated codec makes the harness
	// silently accept production-invalid requests or fork the response wire
	// shape, and a test that reads what the mount SERVES then reads this copy
	// rather than the one that ships.
	svrOpts, err := transport.ExchangeMountOptions(
		resolver, replayAdapter, deps.maxSignatures, audience,
	)
	if err != nil {
		t.Fatalf("exchange mount options: %v", err)
	}
	mux := http.NewServeMux()
	exchangePath, exchangeHandler := connectserver.NewExchangeServiceHandler(
		transport.NewExchangeHandler(exchangeSvc), svrOpts...,
	)
	mux.Handle(exchangePath, exchangeHandler)
	// Built by the function production builds it with, not by a list assembled
	// here. Hand-assembling it is how the two came apart: this harness installed
	// a bare protovalidate interceptor where production installs the SDK's, which
	// validates responses as well and shares one ruleset with the ExchangeService
	// mount. The codec, that interceptor, the recipient check and the message
	// read cap all arrive through this one call, so a change to the mount reaches
	// the tests. The cap used to be a separate append here and in cmd/server, so
	// a copy dropped on one side went unnoticed by the other.
	catalogOpts, err := transport.CatalogMountOptions(audience)
	if err != nil {
		t.Fatalf("catalog mount options: %v", err)
	}
	catalogPath, catalogHandler := rampconnect.NewCatalogServiceHandler(
		transport.NewCatalogHandler(catalogSvc, deps.registry), catalogOpts...,
	)
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
		Clock:             clock.NewDeterministic(time.Unix(1700000000, 0).UTC()),
		KeyLifetime:       10 * 365 * 24 * time.Hour,
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

// jsonWire is the pair of Connect-JSON clients and the capture belonging to
// EACH. One capture shared between them would hold only the last response, so a
// test asserting on the wire would be reading whichever call happened to run
// last — correct or not depending on the order its own statements appear in.
type jsonWire struct {
	exchange        rampconnect.ExchangeServiceClient
	exchangeCapture *testutil.CaptureBody
	catalog         rampconnect.CatalogServiceClient
	catalogCapture  *testutil.CaptureBody
}

// jsonWireClients builds Connect-JSON twins of the harness's clients over the
// SAME signed transport, each with its own capture of the raw response bytes.
//
// The harness's own clients speak gRPC, where proto framing carries every field
// and the response codec is unobservable. JSON is the wire the codec governs, so
// a test that asserts what the codec actually produced has to drive the call
// this way — which is why the codec's field-naming half went unchecked on these
// two mounts until now.
func (h *testHarness) jsonWireClients() jsonWire {
	newCapture := func() *testutil.CaptureBody {
		return &testutil.CaptureBody{
			Base: newSigningTransport(h.baseTransport, h.callerID, h.callerPriv),
		}
	}
	exCapture, catCapture := newCapture(), newCapture()
	return jsonWire{
		exchange: rampconnect.NewExchangeServiceClient(
			&http.Client{Transport: exCapture}, h.server.URL, connect.WithProtoJSON(),
		),
		exchangeCapture: exCapture,
		catalog: rampconnect.NewCatalogServiceClient(
			&http.Client{Transport: catCapture}, h.server.URL, connect.WithProtoJSON(),
		),
		catalogCapture: catCapture,
	}
}
