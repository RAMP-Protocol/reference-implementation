// Package xclient wraps the Connect-Go ExchangeService client. Handlers call
// Pool.For(endpoint) to get a cached client keyed on the exchange endpoint,
// avoiding per-request dial overhead.
package xclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// ExchangeCaller is the narrow interface the Broker depends on.
type ExchangeCaller interface {
	DiscoverResources(
		ctx context.Context, endpoint string, req *rampv1.ResourceQuery,
	) (*rampv1.ResourceResponse, error)
	ExecuteTransactionRaw(
		ctx context.Context, endpoint string, rawBody []byte,
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

// ExecuteTransactionRaw relays an agent-signed TransactionRequest using the
// exact raw body bytes the agent signed. This preserves the Content-Digest
// binding so the agent's sig1 remains valid when the broker appends sig2.
//
// The context MUST carry incoming signature headers via WithIncomingSignatures.
// The raw body bytes MUST be the exact JSON the agent signed.
//
// This bypasses Connect-Go's client to avoid re-marshaling the body.
func (p *Pool) ExecuteTransactionRaw(
	ctx context.Context, endpoint string, rawBody []byte,
) (*rampv1.TransactionResponse, error) {
	// Create raw HTTP request with exact body bytes
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint+rampv1connect.ExchangeServiceExecuteTransactionProcedure,
		bytes.NewReader(rawBody),
	)
	if err != nil {
		return nil, broker.Wrapf(broker.KindInvalidArgument, err, "create request")
	}

	// Set Connect-Go content type
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(rawBody))

	// Propagate incoming agent signature headers (including Content-Digest)
	if incoming, ok := incomingSignaturesFromCtx(ctx); ok {
		req.Header.Set("Signature-Input", incoming.SignatureInput)
		req.Header.Set("Signature", incoming.Signature)
		if incoming.ContentDigest != "" {
			req.Header.Set("Content-Digest", incoming.ContentDigest)
		}
	}
	if signer, ok := signerFromCtx(ctx); ok {
		req.Header.Set(signing.Header, signer.Domain())
	}

	// Send via the pool's HTTP client (includes signing transport)
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange execute")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, broker.Newf(broker.KindUpstreamUnavailable,
			"exchange execute: status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, broker.Wrapf(broker.KindInternal, err, "read response")
	}

	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(respBody, &txResp); err != nil {
		return nil, broker.Wrapf(broker.KindInternal, err, "parse response")
	}

	return &txResp, nil
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

// incomingSignatureHeaders holds the Signature, Signature-Input, and Content-Digest
// headers from an incoming agent-signed request, to be propagated when relaying to Exchange.
type incomingSignatureHeaders struct {
	SignatureInput string
	Signature      string
	ContentDigest  string
}

type incomingSignatureKey struct{}

// WithIncomingSignatures attaches the incoming request's signature headers to ctx
// so they can be propagated when relaying ExecuteTransaction to Exchange, enabling
// multi-label signing (agent sig1 + broker sig2 on the same body).
func WithIncomingSignatures(ctx context.Context, signatureInput, signature, contentDigest string) context.Context {
	if signatureInput == "" || signature == "" {
		return ctx
	}
	headers := incomingSignatureHeaders{
		SignatureInput: signatureInput,
		Signature:      signature,
		ContentDigest:  contentDigest,
	}
	return context.WithValue(ctx, incomingSignatureKey{}, headers)
}

func incomingSignaturesFromCtx(ctx context.Context) (incomingSignatureHeaders, bool) {
	h, ok := ctx.Value(incomingSignatureKey{}).(incomingSignatureHeaders)
	return h, ok
}
