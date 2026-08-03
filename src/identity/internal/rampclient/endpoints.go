package rampclient

import (
	"context"
	"net/http"
	"sync"

	"connectrpc.com/connect"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// endpointResolver turns a signed Offer.exchange domain into the origin that
// Exchange advertises for its own ExchangeService, by reading the top-level
// endpoint of its /.well-known/ramp.json. *helpers.WellKnownEndpointResolver
// satisfies it. Declared as an interface so a test can drive reporting without
// standing up a manifest server, and because this package must never be able to
// take a report endpoint from configuration: the endpoint always comes from the
// issuing Exchange's own manifest.
type endpointResolver interface {
	ResolveEndpoint(ctx context.Context, host string) (string, error)
}

// newEndpointResolver builds the host-keyed well-known resolver. The fetch
// client defaults to the SSRF-guarded one because the host it dials comes from an
// offer rather than from configuration: the domain is signature-covered, but a
// signature says nothing about where DNS points that name, so the dial-time
// public-IP guard is what refuses a domain that resolves to a private or
// metadata address. The resolver caches per host, so a burst of reports to one
// Exchange fetches its manifest once.
func newEndpointResolver(cfg Config) *resolvers.WellKnownEndpointResolver {
	fetch := cfg.Fetch
	if fetch == nil {
		fetch = resolvers.NewGuardedClientFromEnv()
	}
	return resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		HTTP: fetch,
		// Now comes from the injected clock so the manifest cache's freshness
		// window is driven by the same time source as the signature window,
		// rather than reading the wall clock behind the port's back.
		Now:    cfg.Clock.Now,
		Scheme: cfg.Scheme,
	})
}

// maxPooledExchanges bounds the Connect-client pool. The key space is
// open-ended and caller-driven — an agent reports to whichever Exchange issued
// each offer — so an unbounded map is a place an authenticated caller can make
// the process grow without limit. A real deployment talks to a handful of
// Exchanges; well past that, evicting is cheaper than remembering, and a
// re-created client costs one struct allocation because the connection pool
// lives in the shared transport underneath.
const maxPooledExchanges = 256

// exchangePool caches one Connect client per Exchange origin. An agent reports to
// whichever Exchange issued each offer, so the set of origins is open-ended and
// discovered at runtime; caching keeps a burst of calls to the same Exchange from
// re-dialing per request. Every client shares the one signing http.Client, so a
// pooled client is still signed as the agent of the CURRENT request — the pool
// caches transport plumbing, never identity.
type exchangePool struct {
	http    connect.HTTPClient
	mu      sync.RWMutex
	clients map[string]rampv1connect.ExchangeServiceClient
}

func newExchangePool(httpClient *http.Client) *exchangePool {
	return &exchangePool{
		http:    httpClient,
		clients: make(map[string]rampv1connect.ExchangeServiceClient),
	}
}

// clientFor returns the cached client for origin, creating it on first use. The
// pool is cleared wholesale once it exceeds maxPooledExchanges: the cache exists
// to spare a burst of calls to one Exchange, not to remember every origin
// forever, and dropping the map is the cheapest bound that cannot itself be
// gamed by the order in which a caller names hosts.
func (p *exchangePool) clientFor(origin string) rampv1connect.ExchangeServiceClient {
	p.mu.RLock()
	c, ok := p.clients[origin]
	p.mu.RUnlock()
	if ok {
		return c
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok = p.clients[origin]; ok {
		return c
	}
	if len(p.clients) >= maxPooledExchanges {
		p.clients = make(map[string]rampv1connect.ExchangeServiceClient, 1)
	}
	c = rampv1connect.NewExchangeServiceClient(p.http, origin, connectReadCap)
	p.clients[origin] = c
	return c
}

// unary runs one Connect unary call and unwraps the response message. It keeps
// the connect.Request/Response envelopes in this one place so the tool layer
// deals in protocol messages only. Errors pass through as *connect.Error, which
// carries the code and the typed ErrorDetail the caller branches on.
func unary[Req, Res any](
	ctx context.Context,
	call func(context.Context, *connect.Request[Req]) (*connect.Response[Res], error),
	msg *Req,
) (*Res, error) {
	resp, err := call(ctx, connect.NewRequest(msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
