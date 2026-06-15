//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

type fixture struct {
	resolve  *transport.ResolveHandler
	exchange *mockExchange
	pg       string
	logger   *slog.Logger
}

type fixtureOpts struct {
	providerDomain string
	unlicensed     bool
	budgetMinor    int64
}

func newFixture(tb testing.TB, ctx context.Context, opts fixtureOpts) *fixture {
	tb.Helper()
	logger := testutil.DiscardLogger()
	dsn := setupPostgres(tb, ctx)
	redisClient := startRedis(tb, ctx)

	pool := sharedb.OpenForTest(tb, ctx, dsn)

	// Seed exchange row (domain must match the manifest payload).
	exchangeRepo := repo.NewExchangeRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)

	// Start the mock Exchange Connect-Go server. The mock surfaces an offer
	// with EstimatedQuantity=42 so the relay-path test can assert the Broker
	// actually forwards Usage.ConsumedQuantity. A non-zero
	// value is required because zero quantities also pass the validator's
	// zero-estimate REJECT rule by reporting consumed=0; using 42 makes both
	// the propagation AND the equality assertion non-vacuous.
	exSrv := &mockExchange{
		offerUnitCost:          0.10,
		signedURL:              "https://edge.example/signed?tok=abc",
		offerEstimatedQuantity: 42,
	}
	exchangeURL := startMockExchange(tb, exSrv)

	// Upsert exchange row pointing at the mock Exchange.
	if _, err := exchangeRepo.UpsertFromBootstrap(ctx, repo.Exchange{
		ID:                "mp-acme",
		Domain:            "mp.acme.example",
		Endpoint:          exchangeURL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		tb.Fatalf("upsert exchange: %v", err)
	}

	// Provider fixture hosts /.well-known/ramp.json.
	var providerBase string
	if opts.unlicensed {
		providerBase = startUnlicensedProvider(tb).URL
	} else {
		providerBase = startProviderFixture(tb, exchangeURL).URL
	}
	providerURL, err := url.Parse(providerBase)
	if err != nil {
		tb.Fatalf("parse provider url: %v", err)
	}

	// Wire probe to hit the provider via loopback.
	probeClient := &rewritingHTTPClient{targets: map[string]string{
		opts.providerDomain: providerBase,
		// also handle :port case from http.Request (host may include port).
		opts.providerDomain + ":" + providerURL.Port(): providerBase,
	}}
	prober := probe.New(probeClient, logger, probe.Options{Scheme: "http"})

	// Discovery: static client with our provider domain.
	discovery := &exa.StaticClient{Candidates: []exa.Candidate{
		{URL: "https://" + opts.providerDomain + "/x", Domain: opts.providerDomain, Score: 0.9},
	}}

	signer, err := signing.LoadFromEnv("broker.local", "broker-test", nil)
	if err != nil {
		tb.Fatalf("signer: %v", err)
	}
	xpool := xclient.NewPool(nil)
	budgetSvc := budget.NewRedis(redisClient, 0, nil)

	resolver := transport.NewResolveHandler(transport.Deps{
		Exchanges: exchangeRepo,
		Log:       logRepo,
		Discovery: discovery,
		Prober:    prober,
		Exchange:  xpool,
		Budget:    budgetSvc,
		Signer:    signer,
	})
	return &fixture{resolve: resolver, exchange: exSrv, pg: dsn, logger: logger}
}

// post is the standard happy-path POST helper: derives the verified keyID from
// the request's requester.id (matching the production invariant where a verified
// agent acts on its own behalf) and stamps the httpsig context so the handler
// authz check passes. Negative-path tests use postWithKey directly.
func (f *fixture) post(t *testing.T, body *rampv1.RAMPRequest) *http.Response {
	t.Helper()
	return f.postWithKey(t, body, body.GetRequester().GetId())
}

// postWithKey issues a canonical proto-JSON RAMPRequest POST with an explicit
// verified keyID. An empty keyID simulates a request that bypassed the httpsig
// middleware (no verified context at all) — used for the Unauthenticated branch.
func (f *fixture) postWithKey(t *testing.T, body *rampv1.RAMPRequest, keyID string) *http.Response {
	t.Helper()
	buf, err := protojson.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/broker/v1/resolve", bytes.NewReader(buf))
	if keyID != "" {
		ctx := httpsig.NewContext(req.Context(), &httpsig.VerifiedRequest{KeyID: keyID})
		req = req.WithContext(ctx)
	}
	chain := transport.RequestIDMiddleware(f.logger, f.resolve)
	chain.ServeHTTP(rr, req)
	return rr.Result()
}

// reqOpts carries the optional RAMPRequest fields the resolve tests vary.
type reqOpts struct {
	query       string
	uri         string
	licenseID   string
	budgetMinor int64
	maxHops     *int32
}

// buildRAMPRequest assembles a canonical RAMPRequest for the resolve tests.
// budgetMinor is expressed in minor units and mapped onto constraints.period_budget
// (major units) the same way the production handler inverts it.
func buildRAMPRequest(agentID string, o reqOpts) *rampv1.RAMPRequest {
	req := &rampv1.RAMPRequest{Requester: &rampv1.Requester{Id: agentID}}
	if o.query != "" {
		q := o.query
		req.Query = &q
	}
	if o.uri != "" {
		req.Requester.Uris = []string{o.uri}
	}
	if o.licenseID != "" {
		lic := o.licenseID
		req.Requester.LicenseId = &lic
	}
	if o.budgetMinor > 0 || o.maxHops != nil {
		c := &rampv1.RequestConstraints{MaxHops: o.maxHops}
		if o.budgetMinor > 0 {
			c.PeriodBudget = &rampv1.Cost{Amount: float64(o.budgetMinor) / 100, Currency: "USD"}
		}
		req.Constraints = c
	}
	return req
}

// decodeRAMPResponse parses the canonical proto-JSON RAMPResponse body.
func decodeRAMPResponse(t *testing.T, resp *http.Response) *rampv1.RAMPResponse {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out rampv1.RAMPResponse
	if uerr := protojson.Unmarshal(body, &out); uerr != nil {
		t.Fatalf("unmarshal RAMPResponse: %v; body=%s", uerr, body)
	}
	return &out
}

func extBool(out *rampv1.RAMPResponse, key string) bool {
	return out.GetExt().GetFields()[key].GetBoolValue()
}

func extString(out *rampv1.RAMPResponse, key string) string {
	return out.GetExt().GetFields()[key].GetStringValue()
}

func TestResolve_LicensedFlow(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.post(t, buildRAMPRequest("agent-1", reqOpts{
		query:       "RAMP intro",
		licenseID:   "lic-a",
		budgetMinor: 10000,
	}))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	out := decodeRAMPResponse(t, resp)
	if !extBool(out, "ramp.broker.licensed") {
		t.Fatal("expected ramp.broker.licensed=true")
	}
	if out.GetRetrievalEndpoint() == "" {
		t.Error("expected retrieval_endpoint")
	}
	if out.GetTransactionId() == "" {
		t.Error("expected transaction_id")
	}
	if !strings.HasPrefix(extString(out, "ramp.broker.offer_id"), "offer-") {
		t.Errorf("offer_id = %q", extString(out, "ramp.broker.offer_id"))
	}
	budget := out.GetExt().GetFields()["ramp.broker.budget"].GetStructValue()
	if budget == nil || budget.GetFields()["consumed_minor"].GetNumberValue() <= 0 {
		t.Errorf("budget state = %v", budget)
	}
	if fx.exchange.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1", fx.exchange.discoverCalls)
	}
	if fx.exchange.executeCalls != 1 {
		t.Errorf("execute calls = %d, want 1", fx.exchange.executeCalls)
	}
	if fx.exchange.reportCalls != 1 {
		t.Errorf("report calls = %d, want 1", fx.exchange.reportCalls)
	}
	// Pin the contract of the relay payload itself, not just that a call
	// happened. The relay synthesises a UsageReport that
	// echoes the offer's EstimatedQuantity as Usage.ConsumedQuantity; a
	// future regression that drops the field surfaces here, not in CI green.
	if fx.exchange.lastReport == nil {
		t.Fatal("relay did not capture a UsageReport")
	}
	if got := fx.exchange.lastReport.GetUsage().GetConsumedQuantity(); got != 42 {
		t.Errorf("relay Usage.ConsumedQuantity = %d, want 42", got)
	}
	if fx.exchange.lastReport.GetTransactionId() == "" {
		t.Error("relay UsageReport missing transaction_id")
	}
	if fx.exchange.lastReport.GetBillingId() == "" {
		t.Error("relay UsageReport missing billing_id")
	}
}

// TestResolve_NoRampJSON_RefusesNotInCatalog locks in the v1 contract:
// a publisher that does not host /.well-known/ramp.json is refused with
// NOT_IN_CATALOG. The bare-URL fallback that legacy bot-grade fetchers
// relied on has been removed — there is no more "silently accept and
// hand back the bare URL" tolerance (see beads agentic-content-access-af06d).
func TestResolve_NoRampJSON_RefusesNotInCatalog(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "bare.example", unlicensed: true})

	resp := fx.post(t, buildRAMPRequest("agent-1", reqOpts{uri: "https://bare.example/item"}))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	out := decodeRAMPResponse(t, resp)
	if extBool(out, "ramp.broker.licensed") {
		t.Error("expected licensed=false for unmanifested domain")
	}
	if out.GetRetrievalEndpoint() != "" {
		t.Error("refusal must not include retrieval_endpoint")
	}
	wantReason := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG.String()
	if got := extString(out, "ramp.broker.absence_reason"); got != wantReason {
		t.Errorf("absence_reason = %q, want %q", got, wantReason)
	}
	if fx.exchange.executeCalls != 0 {
		t.Errorf("no transaction should happen: executeCalls = %d", fx.exchange.executeCalls)
	}
}

func TestResolve_BudgetExhausted(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.post(t, buildRAMPRequest("agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		licenseID:   "lic-b",
		budgetMinor: 1, // deliberately tiny (offer cost = $0.10 = 10 minor)
	}))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	out := decodeRAMPResponse(t, resp)
	if extBool(out, "ramp.broker.licensed") {
		t.Error("expected licensed=false after budget exhaustion")
	}
	if got := extString(out, "ramp.broker.error"); !strings.Contains(strings.ToLower(got), "budget") {
		t.Errorf("error = %q, want budget-exhaustion message", got)
	}
	if fx.exchange.executeCalls != 0 {
		t.Errorf("budget-exhausted must not call ExecuteTransaction: got %d", fx.exchange.executeCalls)
	}
}

// TestResolve_ScopeInsufficientRefusal locks the propagation contract
// for the OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT path: when an upstream
// Exchange returns zero offers plus an OfferGroup tagged
// SCOPE_INSUFFICIENT, the Broker surfaces "proof missing" as the error
// vocabulary and MUST NOT call ExecuteTransaction or mint a signed URL.
func TestResolve_ScopeInsufficientRefusal(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	fx.exchange.scopeRestricted = true

	resp := fx.post(t, buildRAMPRequest("agent-1", reqOpts{uri: "https://acme.example/article-42"}))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	out := decodeRAMPResponse(t, resp)
	if extBool(out, "ramp.broker.licensed") {
		t.Error("expected licensed=false on SCOPE_INSUFFICIENT upstream")
	}
	if out.GetRetrievalEndpoint() != "" {
		t.Errorf("expected no retrieval_endpoint, got %q", out.GetRetrievalEndpoint())
	}
	if got := extString(out, "ramp.broker.error"); got != "proof missing" {
		t.Errorf("error = %q, want %q", got, "proof missing")
	}
	if fx.exchange.executeCalls != 0 {
		t.Errorf("SCOPE_INSUFFICIENT must not call ExecuteTransaction: got %d", fx.exchange.executeCalls)
	}
}

// TestResolve_NoVerifiedCaller_Unauthenticated pins the self-action invariant:
// a request reaching ResolveHandler with no httpsig context (e.g. the
// middleware was bypassed or never verified the caller) is rejected with
// 401 Unauthenticated, and no upstream side effects fire.
func TestResolve_NoVerifiedCaller_Unauthenticated(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.postWithKey(t, buildRAMPRequest("agent-1", reqOpts{query: "RAMP intro"}), "")
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401, body = %s", resp.StatusCode, body)
	}
	if fx.exchange.discoverCalls != 0 || fx.exchange.executeCalls != 0 {
		t.Errorf("upstream calls leaked: discover=%d execute=%d",
			fx.exchange.discoverCalls, fx.exchange.executeCalls)
	}
}

// TestResolve_CallerImpersonation_PermissionDenied pins the self-action
// invariant: a request whose verified keyID does not equal req.AgentID is
// rejected with 403 PermissionDenied. Without this gate any agent that
// holds a valid httpsig key could resolve resources naming any other agent
// as the principal.
func TestResolve_CallerImpersonation_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.postWithKey(t, buildRAMPRequest("agent-victim", reqOpts{query: "RAMP intro"}), "agent-attacker")
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403, body = %s", resp.StatusCode, body)
	}
	if fx.exchange.discoverCalls != 0 || fx.exchange.executeCalls != 0 {
		t.Errorf("upstream calls leaked: discover=%d execute=%d",
			fx.exchange.discoverCalls, fx.exchange.executeCalls)
	}
}

// TestResolve_MaxHopsBelowBrokerHopBudget_Rejected pins the RequestConstraints
// max_hops self-cap: a request whose max_hops cannot accommodate the Broker's
// own relay hop is rejected with 400 InvalidArgument before any upstream
// discovery/execute fires. Reverting the enforceHopBudget call in
// validateResolveRequest (or dropping the json:"max_hops" tag) makes this case
// proceed to discovery and the assertion fails — the wiring is exercised end to
// end through a real HTTP POST, not just the isolated enforceHopBudget unit.
func TestResolve_MaxHopsBelowBrokerHopBudget_Rejected(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	maxHops := int32(0) // 0 < 1 broker relay hop ⇒ the chain is impossible.
	resp := fx.post(t, buildRAMPRequest("agent.example", reqOpts{
		query:   "RAMP intro",
		maxHops: &maxHops,
	}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400, body = %s", resp.StatusCode, body)
	}
	if fx.exchange.discoverCalls != 0 || fx.exchange.executeCalls != 0 {
		t.Errorf("max_hops rejection must not reach upstream: discover=%d execute=%d",
			fx.exchange.discoverCalls, fx.exchange.executeCalls)
	}
}
