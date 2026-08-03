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

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
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
	DiscoverResourcesRaw(
		ctx context.Context, endpoint string, rawBody []byte,
	) (*rampv1.ResourceResponse, error)
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

// NewPool constructs an empty pool using the given HTTP client. The client is
// REQUIRED: it is the caller-influenced Broker→Exchange relay client the
// composition root injects (a nil client is a wiring bug, so fail loud at boot
// rather than silently fabricating a fail-open &http.Client that would downgrade
// the relay to an unguarded default).
func NewPool(httpClient *http.Client) *Pool {
	if httpClient == nil {
		panic("xclient: NewPool requires a non-nil HTTP client")
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
	// The Connect protocol (the connect-go default — deliberately NOT
	// connect.WithGRPC()): the relay crosses real proxies/LBs on a plain
	// HTTP/1.1 client, and gRPC depends on HTTP trailers, which are reliable
	// in-process (the WithGRPC integration tests and the ingest CLI run
	// against local servers) but not across intermediaries; Connect has no
	// trailer dependency. This is also the protocol the full e2e stack
	// proves, and it keeps the pool single-protocol with the byte-verbatim
	// Connect-JSON raw relay (DiscoverResourcesRaw).
	c = rampv1connect.NewExchangeServiceClient(p.http, endpoint)
	p.clients[endpoint] = c
	return c
}

// seatRequestID copies this request's correlation id onto an upstream request, so
// the Exchange records the id the Broker minted or accepted rather than minting a
// second one nobody upstream ever saw.
//
// It matters most on the execute leg: the Exchange writes the id it sees into an
// append-once evidence row and documents it as the key that correlates that row
// outward against the edge delivery log and the reconciliation sweep. Without
// this the deployed agent → MCP → Broker → Exchange path stores a value that
// appears in no other log, and the row's own provenance flag reports it honestly
// as minted — which is to say, as a join that resolves to nothing.
//
// Nothing is set when the context carries no id (a direct service call, a queue
// consumer, any driver not behind RequestIDMiddleware): the Exchange mints one in
// that case, which is the correct outcome rather than a blank header.
//
// Safe against the RFC 9421 gate for the reason the middleware documents: no RAMP
// client signs x-request-id, and the verifier rebuilds the signature base from
// the signer's own component list. The signing.Header set beside it is the same
// shape.
func seatRequestID(ctx context.Context, h http.Header) {
	if id := reqctx.RequestID(ctx); id != "" {
		h.Set(helpers.RequestIDHeader, id)
	}
}

// DiscoverResources sends a signed ResourceQuery to the given endpoint.
// The CoSigner adds the Broker's detached Ed25519 forwarding-signature header
// (RFC 9421 hop-by-hop; the signature stack is the chain, no in-message hop).
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
	seatRequestID(ctx, creq.Header())
	resp, err := p.For(endpoint).ExecuteTransaction(ctx, creq)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange execute")
	}
	return resp.Msg, nil
}

// DiscoverResourcesRaw relays an agent-signed ResourceQuery using the EXACT raw
// body bytes the agent signed (known-URL discover relay). It bypasses the
// Connect-Go client so the body is never re-marshaled, preserving the agent's
// Content-Digest and its sig1. The ctx MUST carry the agent's incoming signature
// headers via WithIncomingSignatures; the pool's append-aware signing transport
// then chains the broker's sig2 over sig1. rawBody MUST be the exact bytes the
// agent signed. (The execute relay no longer uses a raw path — it re-packages a
// typed broker→Exchange request under the re-package model.)
func (p *Pool) DiscoverResourcesRaw(
	ctx context.Context, endpoint string, rawBody []byte,
) (*rampv1.ResourceResponse, error) {
	respBody, err := p.relayRaw(
		ctx, endpoint+rampv1connect.ExchangeServiceDiscoverResourcesProcedure, rawBody, "discover")
	if err != nil {
		return nil, err
	}
	var rResp rampv1.ResourceResponse
	if err := protojson.Unmarshal(respBody, &rResp); err != nil {
		return nil, broker.Wrapf(broker.KindInternal, err, "parse relay response")
	}
	return &rResp, nil
}

// relayRaw performs the verbatim Broker→Exchange relay POST used by
// DiscoverResourcesRaw: it builds the request to the fully-qualified procedure
// URL with the exact agent-signed body, pre-seats the agent's incoming sig1
// headers (so the append-aware signing transport chains the broker's sig2),
// propagates the agent's Authorization, attaches the broker domain header,
// executes the round-trip, and returns the upstream response body on 200. op
// names the operation for error context ("discover").
func (p *Pool) relayRaw(
	ctx context.Context, procedureURL string, rawBody []byte, op string,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, procedureURL, bytes.NewReader(rawBody))
	if err != nil {
		return nil, broker.Wrapf(broker.KindInvalidArgument, err, "create relay request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(rawBody))
	seatRelayHeaders(ctx, req)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exchange %s (relay)", op)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, broker.Wrapf(broker.KindInternal, err, "read relay response")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, broker.Newf(broker.KindUpstreamUnavailable,
			"exchange %s (relay): status %d: %s", op, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// seatRelayHeaders copies the relay-binding headers from ctx onto req: the
// agent's incoming sig1 headers (so the append-aware signing transport chains
// sig2 and the Exchange sees both), the agent's Authorization (so sig2 covers
// the SAME Authorization bytes sig1 covered — the RAMP covered set binds
// Authorization even when empty; absent → unset, matching the common no-token
// case), and the broker domain header.
func seatRelayHeaders(ctx context.Context, req *http.Request) {
	if in, ok := incomingSignaturesFromCtx(ctx); ok {
		req.Header.Set("Signature-Input", in.SignatureInput)
		req.Header.Set("Signature", in.Signature)
		if in.ContentDigest != "" {
			req.Header.Set("Content-Digest", in.ContentDigest)
		}
		// Re-set the agent's Signature-Agent (its directory identity) verbatim: it
		// is a COVERED component of the agent's sig1 after the WBA split, so the
		// Exchange rebuilds sig1's base from this header value. Without it the
		// broker's signing transport would stamp ITS OWN directory (its
		// "set own only when absent" guard), breaking sig1 at the Exchange.
		if in.SignatureAgent != "" {
			req.Header.Set(helpers.SignatureAgentHeader, in.SignatureAgent)
		}
	}
	if authz, ok := incomingAuthorizationFromCtx(ctx); ok && authz != "" {
		req.Header.Set("Authorization", authz)
	}
	if signer, ok := signerFromCtx(ctx); ok {
		req.Header.Set(signing.Header, signer.Domain())
	}
	seatRequestID(ctx, req.Header)
}

// incomingSignatureHeaders carries the Signature, Signature-Input,
// Content-Digest, and Signature-Agent headers from an incoming agent-signed
// request so they can be relayed verbatim when forwarding to the Exchange
// (enabling the agent sig1 + broker sig2 chain on the same body). Signature-Agent
// is a covered component of the agent's sig1 after the WBA split, so it MUST be
// forwarded unchanged for sig1 to verify at the Exchange.
type incomingSignatureHeaders struct {
	SignatureInput string
	Signature      string
	ContentDigest  string
	SignatureAgent string
}

type incomingSignatureKey struct{}

// WithIncomingSignatures attaches the incoming request's signature headers to
// ctx so DiscoverResourcesRaw can propagate them to the Exchange. A call with
// an empty Signature-Input or Signature is a no-op (nothing to chain onto).
func WithIncomingSignatures(
	ctx context.Context, signatureInput, signature, contentDigest, signatureAgent string,
) context.Context {
	if signatureInput == "" || signature == "" {
		return ctx
	}
	return context.WithValue(ctx, incomingSignatureKey{}, incomingSignatureHeaders{
		SignatureInput: signatureInput,
		Signature:      signature,
		ContentDigest:  contentDigest,
		SignatureAgent: signatureAgent,
	})
}

func incomingSignaturesFromCtx(ctx context.Context) (incomingSignatureHeaders, bool) {
	h, ok := ctx.Value(incomingSignatureKey{}).(incomingSignatureHeaders)
	return h, ok
}

type incomingAuthorizationKey struct{}

// WithIncomingAuthorization attaches the agent's incoming Authorization header
// (bearer / entitlement-biscuit) to ctx so DiscoverResourcesRaw forwards it on
// the relay request, keeping the broker's sig2 covered bytes identical to the
// agent's sig1. An empty value is a no-op.
func WithIncomingAuthorization(ctx context.Context, authorization string) context.Context {
	if authorization == "" {
		return ctx
	}
	return context.WithValue(ctx, incomingAuthorizationKey{}, authorization)
}

func incomingAuthorizationFromCtx(ctx context.Context) (string, bool) {
	a, ok := ctx.Value(incomingAuthorizationKey{}).(string)
	return a, ok
}

// ReportUsage relays a UsageReport to the Exchange.
func (p *Pool) ReportUsage(
	ctx context.Context, endpoint string, req *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	creq := connect.NewRequest(req)
	seatRequestID(ctx, creq.Header())
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
	seatRequestID(ctx, creq.Header())
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
