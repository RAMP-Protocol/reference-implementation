//go:build integration

package transport_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	"github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/types/known/structpb"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
)

// setupPostgres returns a DSN for a fresh testcontainers postgres and applies
// the Broker migrations against it.
func setupPostgres(tb testing.TB, ctx context.Context) string {
	tb.Helper()
	dsn := sharedb.StartPostgres(tb, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
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

// startRedis boots a redis testcontainer and returns a *redis.Client ready to use.
func startRedis(tb testing.TB, ctx context.Context) *redis.Client {
	tb.Helper()
	c, err := tcredis.Run(ctx, "redis:7-alpine",
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		tb.Fatalf("start redis: %v", err)
	}
	tb.Cleanup(func() {
		if termErr := c.Terminate(context.Background()); termErr != nil {
			tb.Logf("terminate redis: %v", termErr)
		}
	})
	conn, err := c.ConnectionString(ctx)
	if err != nil {
		tb.Fatalf("redis conn string: %v", err)
	}
	opts, err := redis.ParseURL(conn)
	if err != nil {
		tb.Fatalf("parse redis url: %v", err)
	}
	client := redis.NewClient(opts)
	if pingErr := client.Ping(ctx).Err(); pingErr != nil {
		tb.Fatalf("redis ping: %v", pingErr)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return client
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
}

func (m *mockExchange) DiscoverResources(_ context.Context, req *connect.Request[rampv1.ResourceQuery]) (*connect.Response[rampv1.ResourceResponse], error) {
	m.mu.Lock()
	m.discoverCalls++
	cost := m.offerUnitCost
	m.mu.Unlock()
	pricing := &rampv1.Pricing{Rate: cost, Currency: "USD", UnitCost: &cost}
	url := "https://acme.example/article-42"
	return connect.NewResponse(&rampv1.ResourceResponse{
		Ver: "0.3",
		Id:  req.Msg.GetId(),
		Offers: []*rampv1.Offer{{
			OfferId:            "offer-1",
			Pricing:            pricing,
			DeliveryMethod:     rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
			Signature:          "sig-x",
			SignatureAlgorithm: "EdDSA",
			Identity: &rampv1.ResourceIdentity{
				CanonicalUrl: &url,
			},
			Reporting: &rampv1.ReportingObligation{Required: true},
		}},
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
	ext, _ := structpb.NewStruct(map[string]any{"signed_url": m.signedURL})
	return connect.NewResponse(&rampv1.TransactionResponse{
		Ver:           "0.3",
		Id:            req.Msg.GetId(),
		TransactionId: &txID,
		BillingId:     &billID,
		Cost:          &rampv1.Cost{Amount: m.offerUnitCost, Currency: "USD"},
		Ext:           ext,
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
		_, _ = io.WriteString(w, `{"ver":"0.3","provider":"acme.example","exchanges":[{"domain":"mp.acme.example","endpoint":"`+exchangeEndpoint+`","supported_profiles":["ramp-news-v1"]}]}`)
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
