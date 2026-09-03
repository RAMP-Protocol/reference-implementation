//go:build integration

package transport_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	rwktestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// agentHarness is a thin wrapper around pushHarness that adds an admin-path
// guard RoundTripper around the base Transport and exposes helpers specific
// to the §7.2 self-signup flow. Composition, not duplication — all the real
// wiring lives in newPushHarness.
type agentHarness struct {
	*pushHarness
	baseRT http.RoundTripper
}

// newAgentHarness builds an agentHarness atop newPushHarness and rebuilds
// the client set on top of an admin-path-guard transport so any stray
// /admin/* request made during self-signup scenarios fails the test.
func newAgentHarness(t *testing.T) *agentHarness {
	t.Helper()
	ph := newPushHarness(t)
	guarded := &agentAdminGuardTransport{base: ph.baseTransport, t: t}
	ph.signedCat = func(id string, priv ed25519.PrivateKey) rampconnect.CatalogServiceClient {
		c := &http.Client{Transport: newSigningTransport(guarded, id, priv)}
		return rampconnect.NewCatalogServiceClient(c, ph.server.URL, connect.WithGRPC())
	}
	// Layer the global-httpsig signing transport on top of the admin guard.
	// Post-1rnxh every /ramp.v1.ExchangeService/* call must be signed; the
	// pushHarness pre-registered discoverKeyID's pubkey at startExchangeServer
	// time, so the request clears the static-resolver gate.
	ph.exchange = rampconnect.NewExchangeServiceClient(
		&http.Client{Transport: newSigningTransport(guarded, ph.discoverKeyID, ph.discoverPriv)},
		ph.server.URL, connect.WithGRPC(),
	)
	return &agentHarness{pushHarness: ph, baseRT: guarded}
}

// seedPublisherEntries stands up a publisher caller with its own directory and
// pushes entries under the harness tenant through the signed catalog surface,
// asserting every one was accepted.
//
// It is the precondition several tests in this package need, and none of them
// varies it: a caller domain distinct from the publisher's keeps the two
// ramp.json documents on separate hosts so the rewriting map routes them to
// different httptest servers, and the caller is a listed contributor with a
// reachable manifest so CatalogHandler.verifyCallerSignature admits it on first
// contact. Each entry must carry a priced term to yield an offer.
func (h *pushHarness) seedPublisherEntries(
	t *testing.T, pubCallerID string, entries ...*rampv1.ResourceEntry,
) {
	t.Helper()
	h.publisher.setContributors(pubCallerID)
	pubPub, pubPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("publisher keypair: %v", err)
	}
	h.publishAgent(t, pubCallerID, pubPub)
	pushResp, err := h.signedCat(pubCallerID, pubPriv).PushResources(h.ctx,
		connect.NewRequest(newPushRequest(h.tenantID, pubCallerID, entries)))
	if err != nil {
		t.Fatalf("seed push as %q: %v", pubCallerID, err)
	}
	// PushResourcesResponse carries only accepted/rejected counts (per-entry
	// detail lives in the service-internal diagnostic log), so surface the split.
	if got, want := pushResp.Msg.GetAccepted(), int32(len(entries)); got != want {
		t.Fatalf("seed push accepted = %d, want %d (rejected=%d)",
			got, want, pushResp.Msg.GetRejected())
	}
}

// insertTenant inserts a fresh Ed25519-scheme tenant row for domain.
func (h *agentHarness) insertTenant(t *testing.T, tenantID, domain string) {
	t.Helper()
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          domain,
		Ed25519KeyRef:   "secret://ed25519/" + tenantID,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
}

// agentCombinedOrigin serves the /.well-known/ramp.json of a publisher that
// also self-registers to push its own catalog. In the unified RAMP model a
// manifest has a single role, so this is a role=PUBLISHER manifest that carries
// the publisher's signing key in its WBA directory (consumed by lazy self-signup via
// agentreg, which resolves a caller's key regardless of role) alongside its
// catalog_contributors (consumed by the publisher cache for contributor authz).
type agentCombinedOrigin struct {
	server       *httptest.Server
	mu           sync.Mutex
	provider     string
	contributors []string
	agentID      string
	agentPub     ed25519.PublicKey
}

func newAgentCombinedOrigin(t *testing.T, provider string, contributors []string, agentID string, agentPub ed25519.PublicKey) *agentCombinedOrigin {
	t.Helper()
	o := &agentCombinedOrigin{
		provider: provider, contributors: contributors,
		agentID: agentID, agentPub: agentPub,
	}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *agentCombinedOrigin) handle(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// After the WBA split identity keys live in the pure WBA directory, not the
	// keyless ramp.json overlay. Serve the agent's key by thumbprint there so the
	// Exchange's self-signup fetch (which resolves the Signature-Agent directory)
	// learns it.
	if r.URL.Path == rampwellknown.WBAPath {
		key := rampwellknown.NewKey(o.agentPub, agentKeyValidFrom(), agentKeyValidUntil())
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(rwktestutil.MarshalWBA(rwktestutil.WBAFile(key)))
		return
	}
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	ownerExt, err := structpb.NewStruct(map[string]any{"resource_owner_id": harnessResourceOwner})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m := &rampv1.WellKnownManifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: o.provider,
		// Attest the resource_owner_id payee the catalog resource-owner gate reads
		// for this Exchange. endpoint + relationship are required by the well-known
		// schema (this manifest is fetched and schema-validated on lazy self-signup).
		// PublicKeys stays OUT: after the WBA split the ramp.json overlay is keyless
		// (the signing key is served at the WBA-directory path above), so the
		// resource-owner feature from v1.1 is grafted WITHOUT re-adding keys here.
		Exchanges: []*rampv1.AuthorizedExchange{{
			Domain:       harnessExchangeDomain,
			Endpoint:     "https://exchange.ramp.test/ramp",
			Relationship: rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT,
			Ext:          ownerExt,
		}},
	}
	for _, c := range o.contributors {
		m.CatalogContributors = append(m.CatalogContributors, &rampv1.CatalogContributor{
			Domain: c, Relationship: "publisher",
		})
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// agentAdminGuardTransport fails the test if any request hits /admin/*.
// The admin plane is intentionally removed (design §9); this is a cheap
// regression alarm for self-signup contracts.
type agentAdminGuardTransport struct {
	base http.RoundTripper
	t    *testing.T
}

// RoundTrip implements http.RoundTripper.
func (a *agentAdminGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && strings.Contains(req.URL.Path, "/admin/") {
		a.t.Errorf("admin-plane path invoked: %q (forbidden by self-signup contract)", req.URL.Path)
	}
	return a.base.RoundTrip(req)
}

// TestAgentSelfSignup_ExplicitRegister walks the explicit-register path:
// pre-seed a three-URI catalog via a signed publisher push, stand up a fresh
// agent, POST /exchange/v1/agents/register, then DiscoverResources →
// ExecuteTransaction → ReportUsage, end-to-end Ed25519-verified, zero admin
// endpoints touched.
func TestAgentSelfSignup_ExplicitRegister(t *testing.T) {
	h := newAgentHarness(t)

	// Step 1: a separate publisher caller pushes three URIs against the harness's
	// tenant domain. The term's Pricing.estimated_quantity is set so the
	// zero-estimate strict-reject branch of the validator does not fire when the
	// e2e flow later reports ConsumedQuantity = 1.
	entries := []*rampv1.ResourceEntry{
		{Domain: h.publisherDom, Path: "/articles/one", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: h.publisherDom, Path: "/articles/two", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: h.publisherDom, Path: "/articles/three", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
	}
	h.seedPublisherEntries(t, "pub-caller.example", entries...)

	// Step 2-3: fresh agent stands up its own /.well-known/ramp.json.
	const agentID = "test-agent.example"
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	h.publishAgent(t, agentID, agentPub)

	// Step 4: POST /exchange/v1/agents/register. Uses the harness's
	// guarded base transport so any accidental /admin/* hit fails the test.
	registerBody, _ := json.Marshal(map[string]string{
		"agent_id":      agentID,
		"discovery_url": agentID,
	})
	regReq, err := http.NewRequestWithContext(h.ctx, http.MethodPost,
		h.server.URL+"/exchange/v1/agents/register", bytes.NewReader(registerBody))
	if err != nil {
		t.Fatalf("new register request: %v", err)
	}
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := (&http.Client{Transport: h.baseRT}).Do(regReq)
	if err != nil {
		t.Fatalf("register do: %v", err)
	}
	if regResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(regResp.Body)
		_ = regResp.Body.Close()
		t.Fatalf("register status = %d, body=%s", regResp.StatusCode, body)
	}
	_ = regResp.Body.Close()

	// Step 5: agents row now carries the fixture pubkey. Read through the
	// production repository surface, not the raw sqlc Querier (Testing Doctrine pt9).
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, agentID)
	if err != nil {
		t.Fatalf("AgentRepo.ByID: %v", err)
	}
	if !bytes.Equal(agent.PublicKey, agentPub) {
		t.Fatalf("stored pubkey != fixture pubkey")
	}

	// The agent is directory-registered but not yet billing-registered; a paid
	// transaction needs a billing_ref, so register it for billing
	// through the public Register RPC before the execute below.
	h.registerForBilling(t, agentID, agentPub, agentPriv)

	// Step 6: DiscoverResources returns three Ed25519-signed offers.
	uris := make([]string, len(entries))
	for i, e := range entries {
		uris[i] = "https://" + e.GetDomain() + e.GetPath()
	}
	discResp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester(agentID, agentID), uris)))
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	offers := discResp.Msg.GetOffers()
	if len(offers) != 3 {
		t.Fatalf("offers len = %d, want 3", len(offers))
	}
	first := offers[0]
	if first.GetSignature() == "" || first.GetSignatureAlgorithm() != "EdDSA" {
		t.Fatalf("offer missing Ed25519 signature: %+v", first)
	}

	// Step 7: ExecuteTransaction → signed URL + transaction_log row.
	// Items-only contract (C4 collapse) with body AgentAcceptance binding
	// The self-registered agent's key — the agents-row key the
	// Exchange verifies the acceptance against — was learned via the well-known
	// manifest fetch during self-signup, so no manual resolver seeding or
	// multisig transport client is needed here.
	idempotencyKey := "tx-" + uuid.NewString()
	execReqr := newRequester(agentID, agentID)
	execResp, err := h.exchange.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: idempotencyKey,
		Requester: execReqr,
		// R4: body acceptance signed by the self-registered agent's
		// key (the agents-row key the Exchange verifies against), over the EXACT
		// requester (domain == agentID) the request carries.
		Items: []*rampv1.TransactionItem{
			{Offer: first, AgentAcceptance: signAcceptanceFor(t, agentPriv, first, execReqr, idempotencyKey)},
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction: %v", err)
	}
	item := singleResultItem(t, execResp)
	if item.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	if item.GetRetrievalEndpoint() == "" {
		t.Fatal("retrieval_endpoint missing from the single batch item")
	}
	if _, err := url.Parse(item.GetRetrievalEndpoint()); err != nil {
		t.Fatalf("signed url parse: %v", err)
	}
	// The items[] path persists under the DERIVED key idempotency_key:offer_id.
	txRec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, idempotencyKey+":"+first.GetOfferId())
	if err != nil {
		t.Fatalf("TransactionRepo.ByIdempotencyKey: %v", err)
	}
	if len(txRec.SignedURLHash) != 32 {
		t.Fatalf("signed_url_hash len = %d, want 32", len(txRec.SignedURLHash))
	}

	// Step-7 invariant: the registered pubkey really does verify a
	// signature produced by the matching private key. Future RFC 9421
	// gates on Discover/Execute will rely on this.
	probe := []byte("post-register probe payload")
	if !ed25519.Verify(ed25519.PublicKey(agent.PublicKey), probe, ed25519.Sign(agentPriv, probe)) {
		t.Fatal("registered pubkey does not verify agent signatures")
	}

	// Step 8: ReportUsage accepted=true.
	repResp, err := h.exchange.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-"+uuid.NewString(), item.GetTransactionId(), item.GetBillingId(), &rampv1.Usage{ConsumedQuantity: 1, Function: []string{"ai_input"}})))
	if err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if repResp.Msg.GetReportId() == "" {
		t.Fatalf("accepted report missing report_id")
	}
}

// TestAgentSelfSignup_LazyFirstSeen exercises the first-seen path. A brand-new publisher "lazy-agent.example" signs
// PushResources without any prior /agents/register call. Its ramp.json
// lists itself as the sole catalog_contributor and its ramp.json is
// reachable, so CatalogHandler.verifyCallerSignature sees ErrUnknown,
// invokes RegisterFromDirectory(caller_id, caller_id), re-verifies, and
// admits. No admin endpoint is touched.
func TestAgentSelfSignup_LazyFirstSeen(t *testing.T) {
	h := newAgentHarness(t)

	const lazyAgentID = "lazy-agent.example"
	lazyTenantID := "t_" + uuid.NewString()
	h.insertTenant(t, lazyTenantID, lazyAgentID)

	// Single combined origin serves both ramp.json (self-listed
	// contributor) and ramp.json (currently-valid Ed25519 key).
	// One host → one rewrite entry, so both fetches land here.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("lazy keypair: %v", err)
	}
	combined := newAgentCombinedOrigin(t, lazyAgentID, []string{lazyAgentID}, lazyAgentID, pub)
	h.registerHost(lazyAgentID, combined.server.URL)

	// Precondition: no agents row yet.
	if _, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, lazyAgentID); err == nil {
		t.Fatal("agent row exists before lazy first-seen; setup bug")
	}

	client := h.signedCat(lazyAgentID, priv)
	pushResp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(lazyTenantID, lazyAgentID, []*rampv1.ResourceEntry{
		{Domain: lazyAgentID, Path: "/feed/latest"},
	})))
	if err != nil {
		t.Fatalf("lazy push: %v", err)
	}
	if got, want := pushResp.Msg.GetAccepted(), int32(1); got != want {
		// See note above on PushResourcesResponse wire-shape reduction.
		t.Fatalf("accepted=%d want=%d (rejected=%d)",
			got, want, pushResp.Msg.GetRejected())
	}
	if got := pushResp.Msg.GetRejected(); got != 0 {
		t.Fatalf("rejected = %d, want 0", got)
	}

	// Lazy first-seen populated the agents row with the fixture key and the
	// WBA directory URL (after the WBA split identity keys are learned from the
	// pure WBA directory, not the keyless ramp.json overlay).
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, lazyAgentID)
	if err != nil {
		t.Fatalf("AgentRepo.ByID after lazy signup: %v", err)
	}
	if !bytes.Equal(agent.PublicKey, pub) {
		t.Fatalf("stored pubkey != fixture pubkey")
	}
	if !strings.Contains(agent.DiscoveryURL, rampwellknown.WBAPath) {
		t.Fatalf("discovery_url = %q, want WBA directory URL", agent.DiscoveryURL)
	}
}

// TestAgentSelfSignup_RotatedKeyRepinnedAndAccepted proves the key-rotation
// lockout fix on the catalog-push surface (finding pair with the ReportUsage
// binding): a contributor that self-signed up with keyA, then rotated its
// directory to keyB, has its next push re-pinned and accepted — no operator DB
// surgery. Before the fix a rotated key was a terminal Unauthenticated because
// self-signup fired only on ErrUnknown, never on a known-caller key mismatch.
//
// Round-trip: both pushes drive CatalogService/PushResources through the
// Connect-Go router + RFC 9421 verification; the re-pin is observed back through
// the production repository surface (AgentRepo.ByID), never a raw DB read
// (Testing Doctrine §9).
func TestAgentSelfSignup_RotatedKeyRepinnedAndAccepted(t *testing.T) {
	h := newAgentHarness(t)

	const agentID = "rotating-agent.example"
	tenantID := "t_" + uuid.NewString()
	h.insertTenant(t, tenantID, agentID)

	// keyA: the contributor's initial key. The first push is first-contact
	// self-signup (ErrUnknown) and TOFU-pins keyA.
	keyAPub, keyAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keyA: %v", err)
	}
	originA := newAgentCombinedOrigin(t, agentID, []string{agentID}, agentID, keyAPub)
	h.registerHost(agentID, originA.server.URL)

	if _, err := h.signedCat(agentID, keyAPriv).PushResources(h.ctx,
		connect.NewRequest(newPushRequest(tenantID, agentID, []*rampv1.ResourceEntry{{Domain: agentID, Path: "/feed/a"}}))); err != nil {
		t.Fatalf("first push (self-signup with keyA): %v", err)
	}

	// The contributor rotates its signing key: its directory now publishes keyB.
	keyBPub, keyBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keyB: %v", err)
	}
	originB := newAgentCombinedOrigin(t, agentID, []string{agentID}, agentID, keyBPub)
	h.registerHost(agentID, originB.server.URL) // overwrite: the host now serves keyB

	// A push signed with the ROTATED key keyB: the pinned key is still keyA, so
	// verify fails; the handler re-pins from the directory (now keyB) and the
	// re-verify succeeds → accepted.
	resp, err := h.signedCat(agentID, keyBPriv).PushResources(h.ctx,
		connect.NewRequest(newPushRequest(tenantID, agentID, []*rampv1.ResourceEntry{{Domain: agentID, Path: "/feed/b"}})))
	if err != nil {
		t.Fatalf("post-rotation push (should re-pin keyB and accept): %v", err)
	}
	if got := resp.Msg.GetAccepted(); got != 1 {
		t.Fatalf("post-rotation accepted = %d, want 1 (rejected=%d)", got, resp.Msg.GetRejected())
	}

	// The agents row now carries the rotated key keyB — the re-pin persisted.
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, agentID)
	if err != nil {
		t.Fatalf("AgentRepo.ByID after rotation: %v", err)
	}
	if !bytes.Equal(agent.PublicKey, keyBPub) {
		t.Fatal("stored pubkey != rotated key keyB (re-pin did not persist)")
	}
}
