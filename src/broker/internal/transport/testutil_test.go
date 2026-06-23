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
	// lastQuery captures the inbound ResourceQuery so tests can assert the Broker
	// stamps Ver = "1.0" on the message it emits upstream (version-skew fix).
	// Without capture, a regression to "0.3" would pass CI green.
	lastQuery *rampv1.ResourceQuery
	// lastExecuteVer captures the ver on the inbound TransactionRequest the
	// Exchange received. The Broker relays the agent's signed body byte-for-byte
	// (it must not re-marshal, or it would break the agent's Content-Digest), so
	// this is the agent's ver passed through unchanged. Tests assert it equals the
	// canonical wire version to pin that the relay leg carries a 1.0-stamped agent
	// message; without capture, a stale "0.3" would slip through silently.
	lastExecuteVer string
}

func (m *mockExchange) DiscoverResources(_ context.Context, req *connect.Request[rampv1.ResourceQuery]) (*connect.Response[rampv1.ResourceResponse], error) {
	m.mu.Lock()
	m.discoverCalls++
	m.lastQuery = req.Msg
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
			Ver: "1.0",
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
		Ver:    "1.0",
		Id:     req.Msg.GetId(),
		Offers: []*rampv1.Offer{offer},
	}), nil
}

func (m *mockExchange) ExecuteTransaction(_ context.Context, req *connect.Request[rampv1.TransactionRequest]) (*connect.Response[rampv1.TransactionResponse], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeCalls++
	m.lastExecuteVer = req.Msg.GetVer()
	if m.denyTransaction {
		reason := rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE
		return connect.NewResponse(&rampv1.TransactionResponse{
			Ver:          "1.0",
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
		Ver:               "1.0",
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

// assertEmittedVer fails the test unless got equals the canonical RAMP wire
// version "1.0". Used to pin that the Broker stamps the protocol version on
// every proto message it emits upstream (version-skew fix). The literal "1.0"
// is asserted directly — not internal/proto.Ver — so the test pins the wire
// contract value rather than echoing whatever the constant currently holds.
func assertEmittedVer(t *testing.T, name, got string) {
	t.Helper()
	if got != "1.0" {
		t.Errorf("emitted %s.Ver = %q, want %q", name, got, "1.0")
	}
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
