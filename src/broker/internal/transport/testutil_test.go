//go:build integration

package transport_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/redis/go-redis/v9"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
)

// setupPostgres returns a DSN for a fresh testcontainers postgres and applies
// the Broker migrations against it.
func setupPostgres(tb testing.TB, ctx context.Context) string {
	tb.Helper()
	dsn := sharedb.StartPostgres(tb, ctx)
	logger := testutil.DiscardLogger()
	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      brokerdb.Migrations,
		MigrationsDir:   brokerdb.MigrationsDir,
		MigrationsTable: brokerdb.MigrationsTable,
	}, logger)
	if err != nil {
		tb.Fatalf("pg setup: %v", err)
	}
	tb.Cleanup(pool.Close)
	return dsn
}

// startRedis is a thin shim around testutil.StartRedis kept so the call sites
// already inside this _test.go file (and the integration test next door) do
// not need to be rewritten. The actual implementation lives in
// internal/testutil/redis.go — see review finding L17.
func startRedis(tb testing.TB, ctx context.Context) *redis.Client {
	tb.Helper()
	return testutil.StartRedis(tb, ctx)
}

// -----------------------------------------------------------------------------
// Mock EXA server.

type mockExa struct {
	server *httptest.Server
	domain string
}

func newMockExa(tb testing.TB, resultDomain string) *mockExa {
	m := &mockExa{domain: resultDomain}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"url":"https://`+resultDomain+`/article-42","title":"Example","score":0.9}]}`)
	}))
	tb.Cleanup(m.server.Close)
	return m
}

func (m *mockExa) URL() string { return m.server.URL }

// -----------------------------------------------------------------------------
// Mock Exchange (Connect-Go handler).

type mockExchange struct {
	mu              sync.Mutex
	discoverCalls   int
	executeCalls    int
	reportCalls     int
	offerUnitCost   float64
	signedURL       string
	denyTransaction bool
	// scopeRestricted makes DiscoverResources return an empty Offers slice
	// plus an OfferGroup with OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT, the
	// shape an Exchange uses to advertise a resource the caller's scopes
	// don't cover.
	scopeRestricted bool
	// offerEstimatedQuantity, when > 0, is set as the offer's
	// Pricing.EstimatedQuantity. The Broker relay echoes this value as
	// Usage.ConsumedQuantity on the synthesised UsageReport so tests can
	// pin that the relay actually populated the payload.
	offerEstimatedQuantity int32
	// lastReport captures the most-recent UsageReport seen by ReportUsage so
	// tests can assert the full payload (e.g. Usage.ConsumedQuantity is what
	// the broker relay populated). Without this, a finger-counter on
	// reportCalls cannot pin the contract.
	lastReport *rampv1.UsageReport
}

func (m *mockExchange) DiscoverResources(_ context.Context, req *connect.Request[rampv1.ResourceQuery]) (*connect.Response[rampv1.ResourceResponse], error) {
	m.mu.Lock()
	m.discoverCalls++
	cost := m.offerUnitCost
	scopeRestricted := m.scopeRestricted
	m.mu.Unlock()
	if scopeRestricted {
		absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT
		uri := "https://acme.example/article-42"
		if uris := req.Msg.GetRequester().GetUris(); len(uris) > 0 {
			uri = uris[0]
		}
		return connect.NewResponse(&rampv1.ResourceResponse{
			Ver: "0.3",
			Id:  req.Msg.GetId(),
			OfferGroups: []*rampv1.OfferGroup{{
				Uri:           uri,
				AbsenceReason: &absence,
			}},
		}), nil
	}
	pricing := &rampv1.Pricing{Rate: cost, Currency: "USD", UnitCost: &cost}
	if est := m.offerEstimatedQuantity; est > 0 {
		pricing.EstimatedQuantity = &est
	}
	url := "https://acme.example/article-42"
	offer := &rampv1.Offer{
		OfferId:            "offer-1",
		Pricing:            pricing,
		DeliveryMethod:     rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		Signature:          "sig-x",
		SignatureAlgorithm: "EdDSA",
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl: &url,
		},
		Reporting: &rampv1.ReportingObligation{Required: true},
	}
	return connect.NewResponse(&rampv1.ResourceResponse{
		Ver:    "0.3",
		Id:     req.Msg.GetId(),
		Offers: []*rampv1.Offer{offer},
	}), nil
}

func (m *mockExchange) ExecuteTransaction(_ context.Context, req *connect.Request[rampv1.TransactionRequest]) (*connect.Response[rampv1.TransactionResponse], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeCalls++
	if m.denyTransaction {
		reason := rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE
		return connect.NewResponse(&rampv1.TransactionResponse{
			Ver:          "0.3",
			Id:           req.Msg.GetId(),
			DenialReason: &reason,
		}), nil
	}
	txID := "tx-" + req.Msg.GetId()
	billID := "bill-" + req.Msg.GetId()
	// Mirror production buildTxResponse: surface the signed URL on the canonical
	// retrieval_endpoint field (TransactionResponse field 18) that extractSignedURL
	// reads. Copy to a local so the returned message does not alias the
	// mutex-guarded struct field.
	signedURL := m.signedURL
	return connect.NewResponse(&rampv1.TransactionResponse{
		Ver:               "0.3",
		Id:                req.Msg.GetId(),
		TransactionId:     &txID,
		BillingId:         &billID,
		Cost:              &rampv1.Cost{Amount: m.offerUnitCost, Currency: "USD"},
		RetrievalEndpoint: &signedURL,
	}), nil
}

func (m *mockExchange) ReportUsage(_ context.Context, req *connect.Request[rampv1.UsageReport]) (*connect.Response[rampv1.UsageReportResponse], error) {
	m.mu.Lock()
	m.reportCalls++
	m.lastReport = req.Msg
	m.mu.Unlock()
	return connect.NewResponse(&rampv1.UsageReportResponse{Accepted: true, ReportId: "rep-" + req.Msg.GetId()}), nil
}

func (m *mockExchange) DisputeTransaction(_ context.Context, _ *connect.Request[rampv1.DisputeRequest]) (*connect.Response[rampv1.DisputeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (m *mockExchange) RequestDomainVerification(_ context.Context, _ *connect.Request[rampv1.DomainVerificationRequest]) (*connect.Response[rampv1.DomainVerificationChallenge], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (m *mockExchange) ConfirmDomainVerification(_ context.Context, _ *connect.Request[rampv1.DomainVerificationConfirmation]) (*connect.Response[rampv1.DomainVerificationResult], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func startMockExchange(tb testing.TB, m *mockExchange) string {
	tb.Helper()
	mux := http.NewServeMux()
	path, h := rampv1connect.NewExchangeServiceHandler(m)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	tb.Cleanup(srv.Close)
	return srv.URL
}

// startProviderFixture serves a /.well-known/ramp.json pointing at the given
// Exchange endpoint. Returns the provider's domain.
func startProviderFixture(tb testing.TB, exchangeEndpoint string) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"ver":"1.0","role":"ROLE_PUBLISHER","domain":"acme.example","exchanges":[{"domain":"mp.acme.example","endpoint":"`+exchangeEndpoint+`","relationship":"PROVIDER_RELATIONSHIP_DIRECT"}],"supported_profiles":["ramp-news-v1"]}`)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// noRampProvider serves 404 for /.well-known/ramp.json — used for bare-URL test.
func startUnlicensedProvider(tb testing.TB) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// rewritingHTTPClient maps probes for arbitrary domains onto a loopback address
// so tests can exercise the real fetch path.
type rewritingHTTPClient struct {
	targets map[string]string // domain -> base URL
}

func (c *rewritingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if base, ok := c.targets[strings.ToLower(req.URL.Host)]; ok {
		u := base + req.URL.Path
		if req.URL.RawQuery != "" {
			u += "?" + req.URL.RawQuery
		}
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, u, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}
