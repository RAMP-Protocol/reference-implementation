//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/jackc/pgx/v5/pgxpool"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	rwktestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// registerHarness wires the Exchange plane for Register tests: a real
// Postgres, a real agentreg.Registry routed at fixture WBA origins via a
// rewriting transport (so an unregistered agent self-signs up on its first signed
// call, exactly like the production self-signup path), an in-memory SoR + billing
// adapter (so account state is asserted through the same surfaces production
// uses), and a deterministic billing_ref generator so returned ids are
// predictable. The seeded tenant from setupExchangeTestDB is the single default
// tenant Register reads its activation policy from.
type registerHarness struct {
	ctx           context.Context
	pool          *pgxpool.Pool
	queries       *sqlc.Queries
	server        string
	baseTransport http.RoundTripper
	resolver      *helpers.StaticKeyResolver
	sorAdapter    *sor.InMemoryAdapter
	billing       billing.Adapter
	rewriteMu     *sync.Mutex
	rewrite       map[string]string
	tenantID      string
	tenantDomain  string
	// logs captures the server's structured output when the harness was built
	// with a capturing logger; nil under the default discard logger.
	logs *safeBuffer
	// deps is the exact dependency set this harness's server was started with,
	// kept so a test can stand up a SECOND Exchange over the SAME database with
	// one setting changed. See republishingTerms.
	deps exchangeServerDeps
}

func newRegisterHarness(t *testing.T) *registerHarness {
	t.Helper()
	return newRegisterHarnessWith(t, registerHarnessOptions{billing: billing.NewInMemoryAdapter(billing.InMemoryOptions{})})
}

// registerHarnessOptions is the configurable wiring for newRegisterHarnessWith,
// following the package's newXHarnessWith(t, opts) constructor convention.
// billing selects the adapter the Exchange server calls (nil → the in-memory
// demo adapter via newRegisterHarness).
type registerHarnessOptions struct {
	billing billing.Adapter
	// logs, when non-nil, receives the server's structured log output through a
	// JSON handler, so a test can assert on an audit line the RPC verdict alone
	// does not carry. nil leaves the fixture's discard logger in place. Same
	// seam as harnessOptions.logger on the main transport harness.
	logs *safeBuffer
	// regSchema is the registration schema the Exchange publishes and therefore
	// enforces. nil → nothing published, which is the pass-through case.
	regSchema *regschema.Schema
	// termsDigest is the terms digest the Exchange publishes. Empty → no terms
	// versioning.
	termsDigest string
	// billingRefGen overrides the deterministic candidate generator. The gate
	// tests use it as a barrier: it is called inside firstRegister, after the
	// fast-path check, so a generator that blocks there puts two concurrent
	// callers past the fast path by construction.
	billingRefGen service.BillingRefGen
	// txRunnerWrap decorates the real pool runner instead of replacing it, so a
	// test runner can delegate to a working transaction and start failing only
	// when it is armed. It is handed the pool runner and returns what the
	// service gets; nil leaves the plain pool runner in place. Same seam as
	// harnessOptions.txRunnerWrap on the main transport harness.
	txRunnerWrap func(sharedb.TxRunner) sharedb.TxRunner
	// auditWrap decorates the audit repo the same way, so a test can fail the
	// audit append from INSIDE the registration transaction. nil leaves the real
	// repo in place.
	auditWrap func(repo.AuditRepo) repo.AuditRepo
}

// newRegisterHarnessWith is newRegisterHarness with explicit options, so the
// default-credit registration flows run against both the in-memory demo
// adapter and a real TigerBeetle ledger through the same harness.
func newRegisterHarnessWith(t *testing.T, opts registerHarnessOptions) *registerHarness {
	t.Helper()
	billingAdapter := opts.billing
	fx := setupExchangeTestDB(t, "unused-register-agent")

	rewriteMu := &sync.Mutex{}
	rewrite := map[string]string{}
	rewriteClient := &http.Client{Transport: &rewritingTransport{
		base: http.DefaultTransport, mu: rewriteMu, rewrite: rewrite,
	}}

	registry := agentreg.New(agentreg.Config{
		Repo: repo.NewAgentRepo(fx.queries),
		HTTP: rewriteClient,
	})

	offerSigner, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}

	sorAdapter := sor.NewInMemoryAdapter()

	// Deterministic candidate ids ("billing-ref-1", "billing-ref-2", ...) so a
	// test can both name the expected id and prove the fast path consumed no new
	// candidate.
	var genCounter atomic.Int64
	var gen service.BillingRefGen = func() string {
		return fmt.Sprintf("billing-ref-%d", genCounter.Add(1))
	}
	if opts.billingRefGen != nil {
		gen = opts.billingRefGen
	}

	var txRunner sharedb.TxRunner
	if opts.txRunnerWrap != nil {
		txRunner = opts.txRunnerWrap(sharedb.PoolRunner{Pool: fx.pool})
	}

	deps := exchangeServerDeps{
		pool: fx.pool, queries: fx.queries, registry: registry,
		txRunner:            txRunner,
		manifests:           newAllowAllManifestCache("unused-register-agent"),
		bill:                billingAdapter,
		signer:              offerSigner,
		keystore:            fx.keystore,
		logger:              harnessLogger(fx.logger, opts.logs),
		httpsigKeys:         map[string]ed25519.PublicKey{},
		sor:                 sorAdapter,
		defaultTenantDomain: fx.tenantDomain,
		billingRefGen:       gen,
		regSchema:           opts.regSchema,
		termsDigest:         opts.termsDigest,
		auditWrap:           opts.auditWrap,
	}
	srv := startExchangeServer(t, deps)

	return &registerHarness{
		ctx: fx.ctx, pool: fx.pool, queries: fx.queries, server: srv.server.URL,
		baseTransport: srv.baseTransport, resolver: srv.resolver,
		sorAdapter: sorAdapter, billing: billingAdapter,
		rewriteMu: rewriteMu, rewrite: rewrite,
		tenantID: fx.tenantID, tenantDomain: fx.tenantDomain,
		logs: opts.logs, deps: deps,
	}
}

// republishingTerms starts a SECOND Exchange over the SAME database, identical to
// this one except for the terms digest it publishes. It is how a test spells "the
// operator revised its terms": the accounts and their recorded acceptances stay
// exactly where the first Exchange left them, and only what the manifest
// advertises changes.
//
// It cannot be done by rebuilding the harness. newRegisterHarnessWith acquires a
// database and resets it to the post-migration baseline, so a second harness
// would start with no accounts at all — which is the state that makes this
// question unaskable.
//
// The returned harness shares the database and differs in its server URL, its
// signing transport and its key resolver. An agent registered against the first
// Exchange therefore needs its key put into the second's resolver before it can
// be heard; clientOn does that.
func (h *registerHarness) republishingTerms(t *testing.T, digest string) *registerHarness {
	t.Helper()
	deps := h.deps
	deps.termsDigest = digest
	srv := startExchangeServer(t, deps)

	revised := *h
	revised.server = srv.server.URL
	revised.baseTransport = srv.baseTransport
	revised.resolver = srv.resolver
	revised.deps = deps
	return &revised
}

// clientOn builds a client for an EXISTING agent against this harness's server,
// registering the agent's key with this harness's resolver first. It is what lets
// an agent created on one Exchange be heard by another over the same database.
func (h *registerHarness) clientOn(a *registerAgent) rampconnect.ExchangeServiceClient {
	h.resolver.Put(rwktestutil.MustThumbprintPriv(a.priv), a.pub)
	return h.clientFor(a.id, a.priv)
}

// harnessLogger returns a JSON logger over logs when a test asked to capture
// them, and the fixture's own logger otherwise. Written here rather than at the
// call site so "capturing" is one decision the constructor makes.
func harnessLogger(fallback *slog.Logger, logs *safeBuffer) *slog.Logger {
	if logs == nil {
		return fallback
	}
	return slog.New(slog.NewJSONHandler(logs, nil))
}

func (h *registerHarness) registerHost(host, target string) {
	h.rewriteMu.Lock()
	h.rewrite[host] = target
	h.rewriteMu.Unlock()
}

// registerAgent is a fresh, unregistered agent plus a client that signs with its
// directory key. On its first signed Register the Exchange self-signs it up
// (lazy registration) from origin, then runs the account flow. client is built
// ONCE and reused for every self-signed call: each signing transport seeds its
// uniqueness counter from the wall clock, so two transports for the same key
// built in the same second would produce colliding signatures the replay store
// rejects.
type registerAgent struct {
	id     string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	origin *pushAgentOrigin
	client rampconnect.ExchangeServiceClient
}

// newSignupAgent is the one self-signup agent fixture both harnesses build
// theirs from: generate a keypair, publish the agent's WBA directory origin
// (the agents row is NOT pre-seeded — the first Register triggers lazy
// self-signup), register the key thumbprint with the global httpsig gate so
// the signature reaches resolveCaller, and build the signing client.
func newSignupAgent(
	t *testing.T, agentID string,
	publish func(*testing.T, string, ed25519.PublicKey) *pushAgentOrigin,
	resolver *helpers.StaticKeyResolver,
	clientFor func(string, ed25519.PrivateKey) rampconnect.ExchangeServiceClient,
) *registerAgent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	origin := publish(t, agentID, pub)
	resolver.Put(rwktestutil.MustThumbprintPriv(priv), pub)
	return &registerAgent{
		id: agentID, pub: pub, priv: priv, origin: origin,
		client: clientFor(agentID, priv),
	}
}

// publishAgentOrigin stands up a fresh fixture origin serving the agent's WBA
// directory and wires host rewriting through the given harness registerHost —
// the one publish operation both harnesses' publishAgent methods delegate to,
// and the shape of the publish closure newSignupAgent takes.
func publishAgentOrigin(
	t *testing.T, registerHost func(host, target string), agentID string, pub ed25519.PublicKey,
) *pushAgentOrigin {
	t.Helper()
	origin := newPushAgentOrigin(t, agentID, pub)
	registerHost(agentID, origin.server.URL)
	return origin
}

// publishAgent runs the shared publishAgentOrigin operation on this harness's
// rewrite table.
func (h *registerHarness) publishAgent(t *testing.T, agentID string, pub ed25519.PublicKey) *pushAgentOrigin {
	return publishAgentOrigin(t, h.registerHost, agentID, pub)
}

// newAgent stands up a fresh agent whose WBA directory serves the given key.
func (h *registerHarness) newAgent(t *testing.T, agentID string) *registerAgent {
	t.Helper()
	return newSignupAgent(t, agentID, h.publishAgent, h.resolver, h.clientFor)
}

// clientFor builds an ExchangeService client signing with keyID/priv.
func (h *registerHarness) clientFor(keyID string, priv ed25519.PrivateKey) rampconnect.ExchangeServiceClient {
	return h.clientWith(keyID, priv)
}

// clientWith is clientFor with extra client options, for a test that needs the
// same signing client to speak differently on the wire — gzip, for one. It is a
// separate method rather than a variadic clientFor because clientFor is passed
// by value where a two-argument function is expected.
func (h *registerHarness) clientWith(
	keyID string, priv ed25519.PrivateKey, opts ...connect.ClientOption,
) rampconnect.ExchangeServiceClient {
	return rampconnect.NewExchangeServiceClient(
		&http.Client{Transport: newSigningTransport(h.baseTransport, keyID, priv)},
		h.server, append([]connect.ClientOption{connect.WithGRPC()}, opts...)...,
	)
}

// newBrokerCaller pre-seeds an agents row whose requester_type is BROKER and
// returns a client signing with its key. Register decides the broker rejection
// straight from requester_type, so no WBA origin / lazy signup is needed — the
// row already exists with the matching key.
func (h *registerHarness) newBrokerCaller(t *testing.T, agentID string) rampconnect.ExchangeServiceClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("broker keypair: %v", err)
	}
	if _, err := h.queries.UpsertAgent(h.ctx, sqlc.UpsertAgentParams{
		AgentID:       agentID,
		PublicKey:     pub,
		RequesterType: sqlc.RampRequesterTypeBROKER,
	}); err != nil {
		t.Fatalf("seed broker agent: %v", err)
	}
	h.resolver.Put(rwktestutil.MustThumbprintPriv(priv), pub)
	return h.clientFor(agentID, priv)
}

// TestExchangeRegister_HappyPath drives a signed Register through the real
// Connect-Go router + httpsig gate: the agent self-signs up, an account is
// created, and the reply carries billing_ref + active. Round-trip: the write goes
// RPC → service → SoR/ledger/agents; the account is observed back through the
// same production surfaces (AgentRepo, billing.GetBalance, sor.IsActive), never
// raw SQL (Testing Doctrine §9).
func TestExchangeRegister_HappyPath(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "reg-agent.example")

	resp, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{
		"legal_entity": "Acme AI Ltd",
		"email":        "ops@acme.example",
	}))))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	ref := resp.Msg.GetBillingRef()
	if ref != "billing-ref-1" {
		t.Fatalf("billing_ref = %q, want billing-ref-1 (first candidate)", ref)
	}
	if !resp.Msg.GetActive() {
		t.Fatal("active = false, want true (tenant activate_new_agents_by_default defaults TRUE)")
	}

	// The stored billing_ref, observed through its public read surface — the
	// GetAccountStatus RPC — driven through the same signed client. This is
	// strictly stronger than reading the agents row directly: it also proves the
	// handler resolves the stored ref back out and reports it as active.
	status, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf("GetAccountStatus: %v", err)
	}
	if got := status.Msg.GetBillingRef(); got != ref {
		t.Fatalf("GetAccountStatus billing_ref = %q, want %q (the ref Register stored)", got, ref)
	}
	if !status.Msg.GetActive() {
		t.Fatal("GetAccountStatus active = false, want true (registered active)")
	}

	// Ledger account exists under the billing_ref with a zero balance, observed
	// through the billing surface production uses.
	bal, err := h.billing.GetBalance(h.ctx, ref)
	if err != nil {
		t.Fatalf("GetBalance(%q): %v", ref, err)
	}
	if bal.Value.Sign() != 0 {
		t.Fatalf("new ledger account balance = %s, want 0", bal.Value.String())
	}

	// SoR record exists and is active, observed through the adapter surface.
	active, err := h.sorAdapter.IsActive(h.ctx, ref)
	if err != nil {
		t.Fatalf("sor.IsActive(%q): %v", ref, err)
	}
	if !active {
		t.Fatal("sor reports inactive, want active")
	}
}

// TestExchangeRegister_IdempotentRepeat proves the fast path (ADR-021 D4): a
// second Register for the same agent — even with different registration_data —
// returns the same billing_ref and consumes no new candidate id (proven by a
// third, distinct agent receiving billing-ref-2). Together these show the fast
// path answered and the store was not written again, rather than a fresh
// registration that happened to reuse the id.
func TestExchangeRegister_IdempotentRepeat(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "reg-agent.example")

	resp1, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{"legal_entity": "Acme AI Ltd"}))))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if resp1.Msg.GetBillingRef() != "billing-ref-1" {
		t.Fatalf("first billing_ref = %q, want billing-ref-1", resp1.Msg.GetBillingRef())
	}

	resp2, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{"legal_entity": "Acme AI GmbH (changed)"}))))
	if err != nil {
		t.Fatalf("repeat Register: %v", err)
	}
	if resp2.Msg.GetBillingRef() != resp1.Msg.GetBillingRef() {
		t.Fatalf("repeat billing_ref = %q, want %q (stable)", resp2.Msg.GetBillingRef(), resp1.Msg.GetBillingRef())
	}
	if resp2.Msg.GetActive() != resp1.Msg.GetActive() {
		t.Fatalf("repeat active = %v, want %v (unchanged)", resp2.Msg.GetActive(), resp1.Msg.GetActive())
	}

	// The repeat took the fast path, so it never called the generator: a fresh,
	// distinct agent gets the NEXT counter value (billing-ref-2), which holds only
	// if the repeat above consumed no candidate.
	b := h.newAgent(t, "other-agent.example")
	respB, err := b.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("second agent Register: %v", err)
	}
	if respB.Msg.GetBillingRef() != "billing-ref-2" {
		t.Fatalf("second agent billing_ref = %q, want billing-ref-2 (repeat must not consume a candidate)",
			respB.Msg.GetBillingRef())
	}
}

// TestExchangeRegister_KeyRotationSameRef proves the account link survives a
// directory key rotation (ADR-021 D3): after the agent rotates its directory key,
// a fresh Register re-pins the new key and returns the SAME billing_ref, because
// the identity write never touches billing_ref.
func TestExchangeRegister_KeyRotationSameRef(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "reg-agent.example")

	resp1, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("initial Register: %v", err)
	}
	ref := resp1.Msg.GetBillingRef()

	// Rotate: a new directory key, served by a fresh origin at the same host, and
	// registered with the httpsig gate.
	keyBPub, keyBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("rotated keypair: %v", err)
	}
	originB := newPushAgentOrigin(t, a.id, keyBPub)
	h.registerHost(a.id, originB.server.URL)
	h.resolver.Put(rwktestutil.MustThumbprintPriv(keyBPriv), keyBPub)

	resp2, err := h.clientFor(a.id, keyBPriv).Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("post-rotation Register: %v", err)
	}
	if resp2.Msg.GetBillingRef() != ref {
		t.Fatalf("post-rotation billing_ref = %q, want %q (unchanged across key rotation)",
			resp2.Msg.GetBillingRef(), ref)
	}
}

// TestExchangeRegister_TenantActivationDefaultOff proves the starting active
// state follows the tenant's activate_new_agents_by_default policy: flipping it
// off makes a fresh registration start inactive.
func TestExchangeRegister_TenantActivationDefaultOff(t *testing.T) {
	h := newRegisterHarness(t)
	setTenantActivationDefault(t, h.arrange(), false)

	a := h.newAgent(t, "reg-agent.example")
	resp, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.Msg.GetActive() {
		t.Fatal("active = true, want false (tenant activation default flipped off)")
	}
	active, err := h.sorAdapter.IsActive(h.ctx, resp.Msg.GetBillingRef())
	if err != nil {
		t.Fatalf("sor.IsActive: %v", err)
	}
	if active {
		t.Fatal("sor reports active, want inactive")
	}
}

// TestExchangeRegister_Negatives drives each failure mode through the same public
// surface and asserts the connect.Code AND the absence of the side effect
// (Testing Doctrine §10).
func TestExchangeRegister_Negatives(t *testing.T) {
	t.Run("unsigned request is Unauthenticated", func(t *testing.T) {
		h := newRegisterHarness(t)
		// A client with the bare base transport sends no RFC 9421 signature; the
		// global httpsig gate rejects it before the handler runs.
		unsigned := rampconnect.NewExchangeServiceClient(
			&http.Client{Transport: h.baseTransport}, h.server, connect.WithGRPC(),
		)
		_, err := unsigned.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
		}
	})

	t.Run("key not published by directory is Unauthenticated", func(t *testing.T) {
		h := newRegisterHarness(t)
		// The directory serves keyA, but the caller signs with keyB. The signature
		// clears the gate (keyB registered there), yet the directory-binding check
		// fails: the proven key is not the one the directory publishes.
		dirPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("directory key: %v", err)
		}
		signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("signing key: %v", err)
		}
		const agentID = "mismatch.example"
		origin := newPushAgentOrigin(t, agentID, dirPub)
		h.registerHost(agentID, origin.server.URL)
		h.resolver.Put(rwktestutil.MustThumbprintPriv(signPriv), signPub)

		_, err = h.clientFor(agentID, signPriv).Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
		}
		// No account was written for the mismatched identity.
		agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, agentID)
		if err == nil && agent.BillingRef != "" {
			t.Fatalf("billing_ref was written on a rejected register: %q", agent.BillingRef)
		}
	})

	t.Run("broker caller is PermissionDenied", func(t *testing.T) {
		h := newRegisterHarness(t)
		const brokerID = "broker.example"
		client := h.newBrokerCaller(t, brokerID)
		// A broker carries no agent identity of its own, so it has nothing to
		// register: Register refuses it before any account write.
		_, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied (err=%v)", got, err)
		}
		// No side effect: the broker's row keeps an empty billing_ref.
		agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, brokerID)
		if err != nil {
			t.Fatalf("AgentRepo.ByID: %v", err)
		}
		if agent.BillingRef != "" {
			t.Fatalf("broker billing_ref = %q, want empty (Register must not write it)", agent.BillingRef)
		}
	})

	t.Run("directory host down is Unavailable", func(t *testing.T) {
		h := newRegisterHarness(t)
		a := h.newAgent(t, "down.example")
		// The directory returns 503 before the agent ever registered, so lazy
		// self-signup meets a transient upstream failure → Unavailable (retryable).
		a.origin.mu.Lock()
		a.origin.unavailable = true
		a.origin.mu.Unlock()

		_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
		if got := connect.CodeOf(err); got != connect.CodeUnavailable {
			t.Fatalf("code = %v, want Unavailable (err=%v)", got, err)
		}
		// The agent was never persisted (lazy signup failed before the write).
		if _, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, a.id); !errors.Is(err, repo.ErrAgentNotFound) {
			t.Fatalf("agent row should be absent after a failed signup, got err=%v", err)
		}
	})
}
