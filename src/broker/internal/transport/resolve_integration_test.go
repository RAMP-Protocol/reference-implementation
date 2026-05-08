//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dsn := setupPostgres(tb, ctx)
	redisClient := startRedis(tb, ctx)

	pool := sharedb.OpenForTest(tb, ctx, dsn)

	// Seed marketplace row (domain must match the manifest payload).
	marketRepo := repo.NewMarketplaceRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)

	// Start the mock Exchange Connect-Go server.
	exSrv := &mockExchange{offerUnitCost: 0.10, signedURL: "https://edge.example/signed?tok=abc"}
	exchangeURL := startMockExchange(tb, exSrv)

	// Upsert marketplace row pointing at the mock Exchange.
	if _, err := marketRepo.UpsertFromBootstrap(ctx, repo.Marketplace{
		ID:                "mp-acme",
		Domain:            "mp.acme.example",
		Endpoint:          exchangeURL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		tb.Fatalf("upsert marketplace: %v", err)
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
	prober := probe.New(probeClient, redisClient, logger, probe.Options{Scheme: "http"})

	// Discovery: static client with our provider domain.
	discovery := &exa.StaticClient{Candidates: []exa.Candidate{
		{URL: "https://" + opts.providerDomain + "/x", Domain: opts.providerDomain, Score: 0.9},
	}}

	signer, err := signing.LoadFromEnv("broker.local", "broker-test")
	if err != nil {
		tb.Fatalf("signer: %v", err)
	}
	xpool := xclient.NewPool(nil)
	budgetSvc := budget.NewRedis(redisClient, 0)
	routes := transport.NewTransactionRouteStore()

	resolver := transport.NewResolveHandler(transport.Deps{
		Marketplaces: marketRepo,
		Log:          logRepo,
		Discovery:    discovery,
		Prober:       prober,
		Exchange:     xpool,
		Budget:       budgetSvc,
		Signer:       signer,
		Routes:       routes,
		Logger:       logger,
	})
	return &fixture{resolve: resolver, exchange: exSrv, pg: dsn, logger: logger}
}

func (f *fixture) post(t *testing.T, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/broker/v1/resolve", bytes.NewReader(buf))
	transport.RequestIDMiddleware(f.resolve).ServeHTTP(rr, req)
	return rr.Result()
}

func TestResolve_LicensedFlow(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.post(t, transport.ResolveRequest{
		AgentID:     "agent-1",
		Query:       "RAMP intro",
		LicenseID:   "lic-a",
		BudgetMinor: 10000,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var out transport.ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Licensed {
		t.Fatal("expected licensed=true")
	}
	if out.SignedURL == "" {
		t.Error("expected signed_url")
	}
	if out.TransactionID == "" {
		t.Error("expected transaction_id")
	}
	if !strings.HasPrefix(out.OfferID, "offer-") {
		t.Errorf("offer_id = %q", out.OfferID)
	}
	if out.Budget == nil || out.Budget.Consumed <= 0 {
		t.Errorf("budget state = %+v", out.Budget)
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
}

func TestResolve_BareURLFallback_NoRampJSON(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "bare.example", unlicensed: true})

	resp := fx.post(t, transport.ResolveRequest{
		AgentID: "agent-1",
		URI:     "https://bare.example/item",
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var out transport.ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Licensed {
		t.Error("expected licensed=false for unlicensed domain")
	}
	if out.BareURL != "https://bare.example/item" {
		t.Errorf("bare_url = %q", out.BareURL)
	}
	if out.SignedURL != "" {
		t.Error("bare-URL response must not include signed_url")
	}
	if fx.exchange.executeCalls != 0 {
		t.Errorf("no transaction should happen: executeCalls = %d", fx.exchange.executeCalls)
	}
}

func TestResolve_BudgetExhausted(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	resp := fx.post(t, transport.ResolveRequest{
		AgentID:     "agent-1",
		URI:         "https://acme.example/article-42",
		LicenseID:   "lic-b",
		BudgetMinor: 1, // deliberately tiny (offer cost = $0.10 = 10 minor)
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var out transport.ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Licensed {
		t.Error("expected licensed=false after budget exhaustion")
	}
	if !strings.Contains(strings.ToLower(out.Error), "budget") {
		t.Errorf("error = %q, want budget-exhaustion message", out.Error)
	}
	if fx.exchange.executeCalls != 0 {
		t.Errorf("budget-exhausted must not call ExecuteTransaction: got %d", fx.exchange.executeCalls)
	}
}
