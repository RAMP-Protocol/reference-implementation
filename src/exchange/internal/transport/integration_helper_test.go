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
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1/rampadminv1connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

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
	// adminURL caches the operator admin surface once a test has needed it, so
	// an assertion helper can read an obligation through the same RPC an
	// operator uses without every caller standing the surface up itself. Empty
	// until the first adminBaseURL call.
	adminURL string
	// adminClient is the client for adminURL, cached with it so one bring-up
	// serves both the tests that read evidence and the tests that write policy.
	adminClient  rampadminv1connect.AdminServiceClient
	tenantID     string
	tenantDomain string
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
	// callerID is the directory the default caller presents as its
	// Signature-Agent, which in this harness is also its seeded agent_id. It is
	// NOT the RFC 9421 keyid — that is the key's RFC 7638 thumbprint, derived
	// from callerPriv. Kept so a test can build a second client over the same
	// signed transport.
	callerID string
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
	// The tenant id is a database key and carries an underscore; the domain is a
	// host and may not (ResourceEntry.domain is a bare-host wire rule, and the
	// catalog URI is built from it), so the fixture domain is derived from the
	// uuid alone, never from the id.
	tenantDomain := "tenant-" + strings.TrimPrefix(tenantID, "t_") + ".example"

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
				signing.ErrRSAKeyUnavailable,
			)
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

// now returns the instant the service under test is reading. A test that moved
// a DeterministicClock must compare against this, not the wall clock: deadlines
// and expiries are written from the service clock, so the two have drifted
// apart on purpose. Falls back to the wall clock for a harness built without a
// deterministic one, where the two agree.
func (h *testHarness) now() time.Time {
	if h.clk != nil {
		return h.clk.Now()
	}
	return time.Now().UTC()
}

// adminSurface starts the operator admin surface on first use and returns the
// client beside its base URL, reusing both afterwards. The allowlist is the
// loopback range every other admin test uses, because the request comes from the
// test process.
//
// The client is cached and not just the URL: a test that needs the client used
// to call startAdminServer itself, which gave the package two bring-up paths for
// one surface and started a second listener the moment such a test also read an
// obligation through the cached one.
func (h *testHarness) adminSurface(t *testing.T) (rampadminv1connect.AdminServiceClient, string) {
	t.Helper()
	if h.adminURL == "" {
		h.adminClient, h.adminURL = startAdminServer(t, h, "127.0.0.0/8")
	}
	return h.adminClient, h.adminURL
}

// adminBaseURL is adminSurface for the readers that need only the URL.
func (h *testHarness) adminBaseURL(t *testing.T) string {
	t.Helper()
	_, url := h.adminSurface(t)
	return url
}

// newRecordingHarnessCapturingLogs is newRecordingHarness with the service
// logger wired to a JSON handler over the returned safeBuffer, so one test can
// assert BOTH billing-call observations (via the recordingAdapter) and
// audit-log lines (via the buffer). Bring-up delegates to newRecordingHarnessWith
// (Testing Doctrine #7). The buffer is safe for concurrent server/test access.
//
// clk is the service clock, and may be nil for a harness that does not drive
// time. It is a parameter rather than a second constructor because a test that
// needs a deterministic clock alongside the recorder and the log buffer wants
// this same bring-up, and a private copy of it in one test file is the shape
// Testing Doctrine #7 exists to prevent.
func newRecordingHarnessCapturingLogs(
	t *testing.T, clk *clock.DeterministicClock,
) (*testHarness, *recordingAdapter, *safeBuffer) {
	t.Helper()
	buf := &safeBuffer{}
	h, rec := newRecordingHarnessWith(t, harnessOptions{
		clk:    clk,
		logger: slog.New(slog.NewJSONHandler(buf, nil)),
	})
	return h, rec, buf
}

// pastReportingWindow is how far a deterministic clock is moved to put an
// obligation's deadline behind it. The default reporting window is 24h, so any
// value above that works; an hour of margin keeps the intent obvious.
const pastReportingWindow = 25 * time.Hour

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
	// txRunnerWrap decorates the real PoolRunner instead of replacing it, so a
	// test runner can delegate to a working transaction during harness bring-up
	// and start failing only afterwards. It is handed the pool runner and returns
	// what the service gets. nil leaves txRunner (or the plain PoolRunner) in
	// place; setting both is a wiring mistake and fails the test.
	txRunnerWrap func(sharedb.TxRunner) sharedb.TxRunner
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
	// (DENIAL_REASON_ACCOUNT_NOT_REGISTERED). Used by the unregistered-agent negative
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

// harnessTxRunner resolves the transaction runner the service gets: a wrapper
// around the real pool runner when txRunnerWrap is set, the replacement when
// txRunner is set, and the plain pool runner otherwise.
func harnessTxRunner(t *testing.T, opts harnessOptions, pool *pgxpool.Pool) sharedb.TxRunner {
	t.Helper()
	if opts.txRunnerWrap == nil {
		return opts.txRunner
	}
	if opts.txRunner != nil {
		t.Fatal("harnessOptions sets both txRunner and txRunnerWrap; the wrapper would have " +
			"nothing to decorate")
	}
	return opts.txRunnerWrap(sharedb.PoolRunner{Pool: pool})
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

	// callerID is BOTH the caller's Signature-Agent directory AND the seeded
	// agent_id, mirroring the production trust model where the directory names
	// the agent. It is not the RFC 9421 keyid: after the Web Bot Auth split that
	// is callerPriv's RFC 7638 thumbprint, which is what the httpsig resolver
	// keys on below. Catalog contributions, ExecuteTransaction, and ReportUsage
	// all sign with this key and authorize as this agent.
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
		txRunner:         harnessTxRunner(t, opts, pool),
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
		callerID:       callerID,
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
