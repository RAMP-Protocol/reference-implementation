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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
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

// publishAgentOrigin stands up a fresh fixture origin serving
// /.well-known/ramp.json for agentID and wires host rewriting.
func (h *agentHarness) publishAgentOrigin(t *testing.T, agentID string, pub ed25519.PublicKey) *pushAgentOrigin {
	return h.pushHarness.publishAgent(t, agentID, pub)
}

// insertTenant inserts a fresh Ed25519-scheme tenant row for domain.
func (h *agentHarness) insertTenant(t *testing.T, tenantID, domain string) {
	t.Helper()
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          domain,
		HmacSecretRef:   "unused",
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
// the publisher's signing key in public_keys (consumed by lazy self-signup via
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
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	m := &rampv1.WellKnownManifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: o.provider,
		PublicKeys: []*rampv1.JsonWebKey{
			rampwellknown.NewKey("k1", o.agentPub, agentKeyValidFrom(), agentKeyValidUntil()),
		},
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

// TestAgentSelfSignup_ExplicitRegister walks design-demo-bootstrap.md §7.2:
// pre-seed a three-URI catalog via a signed publisher push, stand up a fresh
// agent, POST /exchange/v1/agents/register, then DiscoverResources →
// ExecuteTransaction → ReportUsage, end-to-end Ed25519-verified, zero admin
// endpoints touched.
func TestAgentSelfSignup_ExplicitRegister(t *testing.T) {
	h := newAgentHarness(t)

	// Step 1: a separate publisher caller pushes three URIs against the
	// harness's tenant domain. Mirrors TestPushResources auto-register
	// path — caller is listed as contributor and manifest is reachable,
	// so CatalogHandler.verifyCallerSignature admits on first contact.
	// Using a distinct caller domain keeps ramp.json (publisher) and
	// ramp.json (caller) on separate hosts so the rewriting map
	// routes them to different httptest servers.
	const pubCallerID = "pub-caller.example"
	h.publisher.setContributors(pubCallerID)

	pubPub, pubPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("publisher keypair: %v", err)
	}
	h.publishAgentOrigin(t, pubCallerID, pubPub)

	// EstimatedQuantity is set so the zero-estimate strict-reject branch
	// of the validator (implementation plan Q2) does not fire when the
	// e2e flow later reports ConsumedQuantity = 1.
	est := int32(1)
	entries := []*rampv1.ResourceEntry{
		{Domain: h.publisherDom, Path: "/articles/one", EstimatedQuantity: &est},
		{Domain: h.publisherDom, Path: "/articles/two", EstimatedQuantity: &est},
		{Domain: h.publisherDom, Path: "/articles/three", EstimatedQuantity: &est},
	}
	pushResp, err := h.signedCat(pubCallerID, pubPriv).PushResources(h.ctx,
		connect.NewRequest(&rampv1.PushResourcesRequest{
			TenantId: h.tenantID, CallerId: pubCallerID, Entries: entries,
		}))
	if err != nil {
		t.Fatalf("pre-seed push: %v", err)
	}
	if got := pushResp.Msg.GetAccepted(); got != 3 {
		// PushResourcesResponse no longer carries a per-entry Rejections
		// slice (W4 of t3vk reduced the wire shape to accepted/rejected
		// counts; per-entry detail is kept only in the service-internal
		// CatalogPushRejection diagnostic log). Surface the count split.
		t.Fatalf("pre-seed accepted = %d, want 3 (rejected=%d)",
			got, pushResp.Msg.GetRejected())
	}

	// Step 2-3: fresh agent stands up its own /.well-known/ramp.json.
	const agentID = "test-agent.example"
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	h.publishAgentOrigin(t, agentID, agentPub)

	// Step 4: POST /exchange/v1/agents/register. Uses the harness's
	// guarded base transport so any accidental /admin/* hit fails the test.
	registerBody, _ := json.Marshal(map[string]string{
		"agent_id":     agentID,
		"manifest_url": agentID,
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

	// Step 5: agents row now carries the fixture pubkey.
	row, err := h.queries.GetAgent(h.ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if !bytes.Equal(row.PublicKey, agentPub) {
		t.Fatalf("stored pubkey != fixture pubkey")
	}

	// Step 6: DiscoverResources returns three Ed25519-signed offers.
	uris := make([]string, len(entries))
	for i, e := range entries {
		uris[i] = "https://" + e.GetDomain() + e.GetPath()
	}
	discResp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q-" + uuid.NewString(),
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: uris,
		},
	}))
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
	txRequestID := "tx-" + uuid.NewString()
	offerID := first.GetOfferId()
	offerSig := first.GetSignature()
	execResp, err := h.exchange.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: txRequestID,
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester: &rampv1.Requester{
			Id: agentID, Domain: agentID,
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction: %v", err)
	}
	if execResp.Msg.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	signedURL := extractSignedURL(t, execResp.Msg)
	if _, err := url.Parse(signedURL); err != nil {
		t.Fatalf("signed url parse: %v", err)
	}
	txRow, err := h.queries.GetTransactionByRequestID(h.ctx, txRequestID)
	if err != nil {
		t.Fatalf("GetTransactionByRequestID: %v", err)
	}
	if len(txRow.SignedUrlHash) != 32 {
		t.Fatalf("signed_url_hash len = %d, want 32", len(txRow.SignedUrlHash))
	}

	// Step-7 invariant: the registered pubkey really does verify a
	// signature produced by the matching private key. Future RFC 9421
	// gates on Discover/Execute will rely on this.
	probe := []byte("post-register probe payload")
	if !ed25519.Verify(ed25519.PublicKey(row.PublicKey), probe, ed25519.Sign(agentPriv, probe)) {
		t.Fatal("registered pubkey does not verify agent signatures")
	}

	// Step 8: ReportUsage accepted=true.
	repResp, err := h.exchange.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-" + uuid.NewString(),
		TransactionId: execResp.Msg.GetTransactionId(),
		BillingId:     execResp.Msg.GetBillingId(),
		Usage:         &rampv1.Usage{ConsumedQuantity: 1, Function: []string{"ai_input"}},
	}))
	if err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if !repResp.Msg.GetAccepted() {
		t.Fatalf("report accepted=false, reason=%q", repResp.Msg.GetRejectionReason())
	}
}

// TestAgentSelfSignup_LazyFirstSeen exercises the design-demo-bootstrap.md
// §5.3 first-seen path. A brand-new publisher "lazy-agent.example" signs
// PushResources without any prior /agents/register call. Its ramp.json
// lists itself as the sole catalog_contributor and its ramp.json is
// reachable, so CatalogHandler.verifyCallerSignature sees ErrUnknown,
// invokes RegisterFromManifest(caller_id, caller_id), re-verifies, and
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
	if _, err := h.queries.GetAgent(h.ctx, lazyAgentID); err == nil {
		t.Fatal("agent row exists before lazy first-seen; setup bug")
	}

	client := h.signedCat(lazyAgentID, priv)
	pushResp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: lazyTenantID, CallerId: lazyAgentID,
		Entries: []*rampv1.ResourceEntry{
			{Domain: lazyAgentID, Path: "/feed/latest"},
		},
	}))
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

	// Lazy first-seen populated the agents row with the fixture key and
	// the canonical ramp.json URL.
	row, err := h.queries.GetAgent(h.ctx, lazyAgentID)
	if err != nil {
		t.Fatalf("GetAgent after lazy signup: %v", err)
	}
	if !bytes.Equal(row.PublicKey, pub) {
		t.Fatalf("stored pubkey != fixture pubkey")
	}
	if !row.ManifestUrl.Valid || !strings.Contains(row.ManifestUrl.String, "/.well-known/ramp.json") {
		t.Fatalf("manifest_url = %+v, want ramp.json URL", row.ManifestUrl)
	}
}
