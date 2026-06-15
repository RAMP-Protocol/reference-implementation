// Package xclient wraps the Connect-Go ExchangeService client. Handlers call
// Pool.For(endpoint) to get a cached client keyed on the exchange endpoint,
// avoiding per-request dial overhead.
package xclient

import (
	"context"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// ExchangeCaller is the narrow interface the Broker depends on.
type ExchangeCaller interface {
	DiscoverResources(
		ctx context.Context, endpoint string, req *rampv1.ResourceQuery,
	) (*rampv1.ResourceResponse, error)
	ExecuteTransaction(
		ctx context.Context, endpoint string, req *rampv1.TransactionRequest,
	) (*rampv1.TransactionResponse, error)
	ReportUsage(
		ctx context.Context, endpoint string, req *rampv1.UsageReport,
	) (*rampv1.UsageReportResponse, error)
}

// Pool caches one rampv1connect.ExchangeServiceClient per endpoint.
type Pool struct {
	http    *http.Client
	mu      sync.RWMutex
	clients map[string]rampv1connect.ExchangeServiceClient
}

// NewPool constructs an empty pool using the given HTTP client.
func NewPool(httpClient *http.Client) *Pool {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Pool{
		http:    httpClient,
		clients: make(map[string]rampv1connect.ExchangeServiceClient),
	}
}

// For returns a cached client for endpoint, creating it on first use.
func (p *Pool) For(endpoint string) rampv1connect.ExchangeServiceClient {
	p.mu.RLock()
	c, ok := p.clients[endpoint]
	p.mu.RUnlock()
	if ok {
		return c
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok = p.clients[endpoint]; ok {
		return c
	}
	c = rampv1connect.NewExchangeServiceClient(p.http, endpoint)
	p.clients[endpoint] = c
	return c
}

// DiscoverResources sends a signed ResourceQuery to the given endpoint.
// The CoSigner stamps the Broker as an intermediary hop and adds a detached
// Ed25519 signature header.
func (p *Pool) DiscoverResources(
	ctx context.Context, endpoint string, req *rampv1.ResourceQuery,
) (*rampv1.ResourceResponse, error) {
	client := p.For(endpoint)
	return call(ctx, client.DiscoverResources, req, p.signer(ctx))
}

// ExecuteTransaction sends a TransactionRequest to the given endpoint.
func (p *Pool) ExecuteTransaction(
	ctx context.Context, endpoint string, req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	creq := connect.NewRequest(req)
	if signer, ok := signerFromCtx(ctx); ok {
		creq.Header().Set(signing.Header, signer.Domain())
	}
	resp, err := p.For(endpoint).ExecuteTransaction(ctx, creq)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange execute")
	}
	return resp.Msg, nil
}

// ReportUsage relays a UsageReport to the Exchange.
func (p *Pool) ReportUsage(
	ctx context.Context, endpoint string, req *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	creq := connect.NewRequest(req)
	resp, err := p.For(endpoint).ReportUsage(ctx, creq)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange report usage")
	}
	return resp.Msg, nil
}

// discoverFn is the DiscoverResources client method signature.
type discoverFn func(
	context.Context, *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error)

// call issues a DiscoverResources request with signer context wired in.
func call(
	ctx context.Context, do discoverFn, req *rampv1.ResourceQuery, sig string,
) (*rampv1.ResourceResponse, error) {
	creq := connect.NewRequest(req)
	if sig != "" {
		creq.Header().Set(signing.Header, sig)
	}
	resp, err := do(ctx, creq)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange discover")
	}
	return resp.Msg, nil
}

// signer returns the detached signature from ctx, empty if no signer configured.
func (p *Pool) signer(ctx context.Context) string {
	if sig, ok := ctx.Value(sigCtxKey{}).(string); ok {
		return sig
	}
	return ""
}

// sigCtxKey is the context key used to pass a pre-computed detached signature.
type sigCtxKey struct{}

// WithSignature attaches a detached Broker signature to ctx for DiscoverResources.
func WithSignature(ctx context.Context, sig string) context.Context {
	return context.WithValue(ctx, sigCtxKey{}, sig)
}

// signerFromCtx is used by ExecuteTransaction to attach the broker domain.
type brokerSigner interface{ Domain() string }

func signerFromCtx(ctx context.Context) (brokerSigner, bool) {
	s, ok := ctx.Value(brokerSignerKey{}).(brokerSigner)
	return s, ok
}

type brokerSignerKey struct{}

// WithBrokerSigner attaches the Broker's signer (for domain header) to ctx.
func WithBrokerSigner(ctx context.Context, s brokerSigner) context.Context {
	return context.WithValue(ctx, brokerSignerKey{}, s)
}
