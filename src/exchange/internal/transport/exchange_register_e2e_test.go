//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/structpb"

	rwktestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
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
	queries       *sqlc.Queries
	server        string
	baseTransport http.RoundTripper
	resolver      *helpers.StaticKeyResolver
	sorAdapter    *sor.InMemoryAdapter
	billing       *billing.InMemoryAdapter
	rewriteMu     *sync.Mutex
	rewrite       map[string]string
	tenantID      string
	tenantDomain  string
}

func newRegisterHarness(t *testing.T) *registerHarness {
	t.Helper()
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
	billingAdapter := billing.NewInMemoryAdapter(billing.InMemoryOptions{})

	// Deterministic candidate ids ("billing-ref-1", "billing-ref-2", ...) so a
	// test can both name the expected id and prove the fast path consumed no new
	// candidate.
	var genCounter atomic.Int64
	gen := func() string { return fmt.Sprintf("billing-ref-%d", genCounter.Add(1)) }

	srv := startExchangeServer(t, exchangeServerDeps{
		pool: fx.pool, queries: fx.queries, registry: registry,
		manifests:           newAllowAllManifestCache("unused-register-agent"),
		bill:                billingAdapter,
		signer:              offerSigner,
		keystore:            fx.keystore,
		logger:              fx.logger,
		httpsigKeys:         map[string]ed25519.PublicKey{},
		sor:                 sorAdapter,
		defaultTenantDomain: fx.tenantDomain,
		billingRefGen:       gen,
	})

	return &registerHarness{
		ctx: fx.ctx, queries: fx.queries, server: srv.server.URL,
		baseTransport: srv.baseTransport, resolver: srv.resolver,
		sorAdapter: sorAdapter, billing: billingAdapter,
		rewriteMu: rewriteMu, rewrite: rewrite,
		tenantID: fx.tenantID, tenantDomain: fx.tenantDomain,
	}
}

func (h *registerHarness) registerHost(host, target string) {
	h.rewriteMu.Lock()
	h.rewrite[host] = target
	h.rewriteMu.Unlock()
}

// registerAgent is a fresh, unregistered agent plus a client that signs with its
// directory key. On its first signed Register the Exchange self-signs it up
// (lazy registration) from origin, then runs the account flow.
type registerAgent struct {
	id     string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	origin *pushAgentOrigin
	client rampconnect.ExchangeServiceClient
}

// newAgent stands up a fresh agent whose WBA directory serves the given key. The
// agents row is NOT pre-seeded — the first Register triggers lazy self-signup.
func (h *registerHarness) newAgent(t *testing.T, agentID string) *registerAgent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	origin := newPushAgentOrigin(t, agentID, pub)
	h.registerHost(agentID, origin.server.URL)
	// The global httpsig gate keys by the RFC 7638 thumbprint; register the
	// signing key there so the signature clears the gate and reaches resolveCaller.
	h.resolver.Put(rwktestutil.MustThumbprintPriv(priv), pub)
	return &registerAgent{
		id: agentID, pub: pub, priv: priv, origin: origin,
		client: h.clientFor(agentID, priv),
	}
}

// clientFor builds an ExchangeService client signing with keyID/priv.
func (h *registerHarness) clientFor(keyID string, priv ed25519.PrivateKey) rampconnect.ExchangeServiceClient {
	return rampconnect.NewExchangeServiceClient(
		&http.Client{Transport: newSigningTransport(h.baseTransport, keyID, priv)},
		h.server, connect.WithGRPC(),
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

func mustRegistrationStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return s
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

	resp, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
		Ver: "1.0",
		RegistrationData: mustRegistrationStruct(t, map[string]any{
			"legal_entity": "Acme AI Ltd",
			"email":        "ops@acme.example",
		}),
	}))
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
	status, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(&rampv1.GetAccountStatusRequest{Ver: "1.0"}))
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

	resp1, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
		Ver:              "1.0",
		RegistrationData: mustRegistrationStruct(t, map[string]any{"legal_entity": "Acme AI Ltd"}),
	}))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if resp1.Msg.GetBillingRef() != "billing-ref-1" {
		t.Fatalf("first billing_ref = %q, want billing-ref-1", resp1.Msg.GetBillingRef())
	}

	resp2, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
		Ver:              "1.0",
		RegistrationData: mustRegistrationStruct(t, map[string]any{"legal_entity": "Acme AI GmbH (changed)"}),
	}))
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
	respB, err := b.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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

	resp1, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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

	resp2, err := h.clientFor(a.id, keyBPriv).Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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
	// Flip the single default tenant's activation policy off. This mutates tenant
	// configuration, which has no production write path (set out of band), so the
	// sqlc fixture mutator is the sanctioned arrange surface (see repo.TenantRepo).
	if err := h.queries.SetTenantActivateNewAgentsByDefault(h.ctx, sqlc.SetTenantActivateNewAgentsByDefaultParams{
		TenantID: h.tenantID, ActivateNewAgentsByDefault: false,
	}); err != nil {
		t.Fatalf("flip activation default off: %v", err)
	}

	a := h.newAgent(t, "reg-agent.example")
	resp, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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
		_, err := unsigned.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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

		_, err = h.clientFor(agentID, signPriv).Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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
		_, err := client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
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

		_, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{Ver: "1.0"}))
		if got := connect.CodeOf(err); got != connect.CodeUnavailable {
			t.Fatalf("code = %v, want Unavailable (err=%v)", got, err)
		}
		// The agent was never persisted (lazy signup failed before the write).
		if _, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, a.id); !errors.Is(err, repo.ErrAgentNotFound) {
			t.Fatalf("agent row should be absent after a failed signup, got err=%v", err)
		}
	})
}
