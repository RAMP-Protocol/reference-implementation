// Package rampclient is what remains of the Identity Service's hand-written
// outbound RAMP leg: the two account RPCs, each dialled at the Exchange the
// calling agent names, and the raw POST that carries a purchase to the Broker's
// relay route.
//
// There is no client for "the service's own Exchange" and no configuration that
// could name one. An account is per-Exchange and which one is the agent's choice
// per call, so every account request is routed from the domain on the request
// itself, through that Exchange's own manifest.
//
// # One transport, many agents
//
// Every call here leaves signed as the agent the INBOUND request authenticated,
// not as the service. That is what makes each MCP user a distinct RAMP agent
// rather than all of them hiding behind one registry identity. The key is
// resolved per request by the KeySource (agentsign.Resolver.Source), reading the
// authenticated subdomain off the context — so one http.Client serves every
// agent, and a request that carries no identity is refused rather than signed as
// anyone.
//
// This package therefore holds NO key material and takes no subdomain argument:
// the identity travels on the context, and the only way to change who a call is
// signed as is to change who authenticated it.
//
// # What is left here, and why
//
// Two Connect RPCs and one raw POST. Register and GetAccountStatus go to the
// Exchange the REQUEST names — an account is per-Exchange, and which one is the
// agent's choice per call, not a deployment's choice once. Both are unary RPCs
// on /ramp.* paths, which the canonical outbound signer (internal/ramphttpsig)
// covers unchanged. The purchase is the exception: the Broker's execute relay is
// not a Connect route, so it needs a raw protojson POST and a signer that
// applies the RAMP covered set to a non-/ramp.* target.
//
// # Where an account call goes, and why it is not configurable
//
// The destination is read off the request's own exchange field and resolved
// through that Exchange's well-known manifest, by the SAME resolver the report
// leg uses. There is no configuration slot for an Exchange origin here, and that
// absence is the mechanism: a signature covers the domain a sender meant but
// says nothing about where that domain's endpoint lives, so the endpoint always
// comes from the Exchange itself, and leaving nowhere for a configured origin to
// arrive is what keeps that structural rather than conventional.
//
// # Two transports, and why only one is guarded
//
// The Broker's relay route is an operator-configured origin, trusted as far as
// that configuration is, so the purchase dials it over the ordinary transport.
// An Exchange an agent named is not: the caller supplies a domain, the manifest
// that domain serves names an endpoint, and a signed request then goes there. So
// the account RPCs dial under the SDK's SSRF guard, and the guard sits UNDER the
// signer — a finished, guarded http.Client cannot wrap the signing transport, it
// has to be what the signing transport dials through.
//
// Everything else this package used to carry has moved. Discovery, the usage
// report and the content fetch are the protocol SDK's, reached through rampsdk.
//
// This package goes when the two account RPCs land in the SDK. What remains
// until then is the registration surface and the relay purchase, and nothing
// else belongs here.
package rampclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	lru "github.com/hashicorp/golang-lru/v2"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampsdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramproute"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampsdk"
)

// The outbound-call defaults are one decision with one home, in rampsdk. Both
// packages are the same service's outbound leg, signing with the same key source
// against peers applying the same freshness rules, and both are configured from
// the same settings — so a decision to shorten the outbound signature lifetime
// has to be a single edit or it is not a decision at all. The dependency points
// this way round deliberately: rampsdk is what survives when this package goes.
const (
	// DefaultTimeout bounds one outbound RAMP call.
	DefaultTimeout = rampsdk.DefaultTimeout
	// DefaultSignatureTTL is how long an outbound RFC 9421 signature stays valid.
	DefaultSignatureTTL = rampsdk.DefaultSignatureTTL
)

// The outbound-call fields below are declared in rampsdk as well, and the
// duplication is knowing rather than missed. The VALUES already have one home —
// the constants above alias rampsdk's — so what repeats is three lines of
// defaulting, and both packages are handed the same numbers by the composition
// root. This package goes when the two account RPCs land in the SDK, so folding
// its config into the survivor now is churn that deletion undoes.

// Config wires a Client. Keys, BrokerURL, Endpoints and ExchangeBase are
// required; the rest take defaults.
type Config struct {
	// Keys resolves the key each outbound request is signed with, per request,
	// from the authenticated identity on the context. Pass
	// agentsign.Resolver.Source().
	//
	// Named as rampsdk names it. One collaborator wired from one expression, and
	// two names for it is one more thing a reader has to notice is the same thing
	// — on the seam whose own comment argues it is the one place the two legs
	// could be made to disagree.
	Keys ramphttpsig.KeySource

	// BrokerURL is the Broker's origin. The relay route this package posts a
	// purchase to is built from it; discovery is the SDK-backed leg's and does
	// not come through here.
	BrokerURL string

	// Endpoints resolves an Exchange domain to the origin that Exchange
	// advertises for itself, and refuses an endpoint on a host unrelated to the
	// one that served the manifest.
	//
	// REQUIRED, and it is the SAME instance the SDK-backed report leg holds —
	// injected rather than built here, because two resolvers would be two
	// manifest caches and two chances for the same-host rule to be applied on one
	// leg and not the other. It also carries the deployment's Exchange policy,
	// which is why nothing here consults that policy again.
	Endpoints rampsdkconnect.EndpointResolver

	// ExchangeBase is the round-tripper the account RPCs dial through, UNDER the
	// RFC 9421 signer.
	//
	// REQUIRED, and it MUST be SSRF-guarded (resolvers.NewGuardedTransport): the
	// target is an Exchange the CALLER named, reached at an endpoint a manifest
	// that caller's domain served advertised. That is the same threat shape the
	// report leg dials under. Fail-loud on nil rather than defaulted, because a
	// default here would be the plain transport and the downgrade would be
	// invisible.
	ExchangeBase http.RoundTripper

	// Timeout bounds a single outbound call. Defaults to DefaultTimeout.
	Timeout time.Duration

	// SignatureTTL caps an outbound signature's lifetime. Defaults to
	// DefaultSignatureTTL.
	SignatureTTL time.Duration

	// Clock is the time source the signature window reads. Defaults to the
	// system clock.
	Clock clock.Clock
}

// MaxRPCReadBytes caps the response body a single outbound RAMP call will read.
// It mirrors the cap the Exchange applies to inbound messages
// (src/exchange/internal/transport.MaxRPCReadBytes): a RAMP response for a
// realistic batch is small, and the bound is what stops a hostile or
// misconfigured peer — including one an offer named — from buffering an
// unbounded body into this process.
const MaxRPCReadBytes = 1 << 20 // 1 MiB

// Client is the outbound RAMP leg this repository still implements: the two
// account RPCs against whichever Exchange a request names, and the purchase
// through the Broker's execute relay.
//
// Discovery, the usage report and the content fetch are no longer here. They
// moved to the protocol SDK's client, which routes a report to the Exchange an
// offer names rather than to any configured origin — see rampsdk.
type Client struct {
	// keys resolves the current caller's key. Execute needs it directly — not
	// just through the transport — because it detached-signs each offer
	// acceptance with the agent's own key before the body is serialized.
	keys ramphttpsig.KeySource

	// The two signing clients, and the split IS this package's outbound posture.
	// relayHTTP dials the Broker's operator-configured origin over the ordinary
	// transport; exchangeHTTP dials an Exchange the caller named, under the SSRF
	// guard. Both sign as whoever the inbound request authenticated.
	relayHTTP    *http.Client
	exchangeHTTP *http.Client

	// relayURL is the Broker's execute-relay endpoint, the one RAMP call that is
	// not a Connect route.
	relayURL string

	// endpoints answers where an Exchange domain is reached, from that
	// Exchange's own manifest.
	endpoints rampsdkconnect.EndpointResolver

	// pool holds one generated Connect client per RESOLVED ORIGIN.
	//
	// Bounded, because which origins appear is driven by what authenticated
	// agents ask for, and an unbounded map over a caller-influenced key space is
	// somewhere a caller can make this process grow. Evicting the least recently
	// used rather than dropping the map keeps which entries survive from being a
	// function of the order a caller names Exchanges. An evicted entry costs a
	// struct and never a socket: the connection pool lives in the shared
	// transport underneath, not in the Connect client.
	pool *lru.Cache[string, rampv1connect.ExchangeServiceClient]
}

// maxPooledExchanges bounds the per-origin client pool. The same bound the SDK
// puts on its own, for the same reason and over the same kind of key space.
const maxPooledExchanges = 256

// New builds a Client from cfg. It fails on missing required configuration
// rather than nil-panicking on the first tool call.
func New(cfg Config) (*Client, error) {
	if cfg.Keys == nil {
		return nil, errors.New("rampclient: Config.Keys is required")
	}
	if cfg.BrokerURL == "" {
		return nil, errors.New("rampclient: Config.BrokerURL is required")
	}
	if cfg.Endpoints == nil {
		return nil, errors.New(
			"rampclient: Config.Endpoints is required; inject the resolver the " +
				"composition root builds, so this leg and the report leg resolve alike")
	}
	if cfg.ExchangeBase == nil {
		return nil, errors.New(
			"rampclient: Config.ExchangeBase is required and must be SSRF-guarded; " +
				"an account call dials a host the CALLER named")
	}
	cfg = cfg.withDefaults()
	relayURL := strings.TrimRight(cfg.BrokerURL, "/") + relayExecutePath
	// Two signing clients over two transports. The relay's destination is
	// operator-configured, so it dials plainly; an Exchange's is caller-named, so
	// it dials under the guard. Both wrap the SAME signer settings, because who a
	// request is signed as is not a function of where it goes.
	relayHTTP, err := signingClient(cfg, http.DefaultTransport, relayURL)
	if err != nil {
		return nil, err
	}
	exchangeHTTP, err := signingClient(cfg, cfg.ExchangeBase, relayURL)
	if err != nil {
		return nil, err
	}
	pool, err := lru.New[string, rampv1connect.ExchangeServiceClient](maxPooledExchanges)
	if err != nil {
		return nil, fmt.Errorf("rampclient: build exchange pool: %w", err)
	}
	return &Client{
		keys:         cfg.Keys,
		relayHTTP:    relayHTTP,
		exchangeHTTP: exchangeHTTP,
		relayURL:     relayURL,
		endpoints:    cfg.Endpoints,
		pool:         pool,
	}, nil
}

// exchangeClient turns the domain a request is addressed to into the client that
// reaches it.
//
// The endpoint comes from that domain's own manifest and from nowhere else, and
// the resolver it comes from is the one the report leg uses — so the deployment's
// Exchange policy, the SSRF-guarded manifest read and the "an endpoint may name
// only the host that served the manifest" rule are all applied once, there,
// rather than restated here. Restating any of them would be a second spelling
// that can disagree with the first, on the leg where disagreeing means a signed
// registration going somewhere nobody chose.
//
// The wire-shape rule is NOT one of them, and this is the correction that
// matters most on this list. The resolver runs helpers.IsBareHost, which asks
// whether a value can safely be built into a URL; the contract's rule is
// helpers.IsBareDomain, which is narrower, and the SDK keeps the two apart on
// purpose. A trailing root dot, a leading or trailing hyphen, an underscore and
// a bracketed IPv6 literal all pass the first and none is a value the wire
// accepts. So nothing on this path gets the contract's rule from the resolver:
// exchacct runs it on the argument before either account call, which is where
// this leg's guarantee actually comes from.
//
// Refusals are reported as the SDK's own *rampsdkconnect.CallError, exactly as
// Execute reports a signature it could not produce. A local Kind would be a
// second vocabulary that has to keep agreeing with the first by spelling, and it
// would agree only where somebody remembered to teach the reading layer about
// it: the SDK's report leg answers these same conditions with CallNotSent, so an
// account leg answering with a token of its own would make one refusal read two
// ways depending on which tool produced it.
func (c *Client) exchangeClient(
	ctx context.Context, domain, op string,
) (rampv1connect.ExchangeServiceClient, error) {
	if domain == "" {
		return nil, &rampsdkconnect.CallError{
			Kind: rampsdkconnect.CallNotSent, Op: op, Err: errors.New(
				"request names no Exchange; an account call is addressed to one Exchange by domain"),
		}
	}
	endpoint, err := c.endpoints.ResolveEndpoint(ctx, domain)
	if err != nil {
		kind := rampsdkconnect.CallUnreachable
		if ramproute.IsVerdict(err) {
			kind = rampsdkconnect.CallNotSent
		}
		return nil, &rampsdkconnect.CallError{
			Kind: kind, Op: op, Err: fmt.Errorf("resolve %s: %w", domain, err),
		}
	}
	if client, ok := c.pool.Get(endpoint); ok {
		return client, nil
	}
	client := rampv1connect.NewExchangeServiceClient(c.exchangeHTTP, endpoint, connectReadCap)
	c.pool.Add(endpoint, client)
	return client, nil
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

// connectReadCap bounds every Connect response this package reads. Applied at
// construction so no call site can forget it.
var connectReadCap = connect.WithReadMaxBytes(MaxRPCReadBytes)

// withDefaults resolves every optional field once, so the rest of the package
// reads settled values and the defaulting is not restated per consumer.
func (c Config) withDefaults() Config {
	if c.SignatureTTL <= 0 {
		c.SignatureTTL = DefaultSignatureTTL
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Clock == nil {
		c.Clock = clock.System{}
	}
	return c
}

// signingClient builds an http.Client whose transport signs each RAMP request
// with the key the KeySource resolves for that request, so one client speaks for
// every agent without ever binding one agent's key.
//
// base is the underlying round-tripper and it is what the two callers differ by:
// the relay leg passes the default transport, because the Broker is an
// operator-configured origin, and the account leg passes the SSRF-guarded one,
// because an Exchange is whatever domain an agent named. The guard goes UNDER
// the signer rather than around it — a finished http.Client cannot wrap a
// transport, so a guarded client could not have been used here at all.
//
// Redirects are refused outright: a RAMP RPC has no legitimate reason to be
// redirected, and following one would re-sign the caller's request for a target
// the peer chose. That covers both destinations, because a redirect on either
// moves where a signed request lands after the signature was made.
func signingClient(cfg Config, base http.RoundTripper, relayURL string) (*http.Client, error) {
	// directory and priv are zero: WithKeySource supplies both per request, and
	// New skips the static-key path entirely when a KeySource is present.
	// WithRAMPTargets adds two path shapes to the RAMP-signed set that the
	// transport's own "/ramp." prefix rule does not claim: the execute relay
	// route, whose body the Broker verifies under the RAMP covered set
	// (relay_core.go) despite the path, and an account RPC reached through an
	// endpoint carrying a path prefix. See rampTargetsOf.
	//
	// Both clients get it, though each dials only its own half. Passing it to
	// both keeps the two transports identical apart from the base, which is the
	// ONE difference worth being able to see, and each half matches nothing on
	// the client that does not send it.
	//
	// MonotonicWindow, not ClockWindow, and for the same reason
	// src/broker/internal/xclient/signing_transport.go uses it: the signature
	// window has one-second resolution, so two identical requests inside one
	// second would produce byte-identical signatures and the second would be
	// refused by the peer's replay store, which keys on (keyid, signature). A
	// status call carries no identifying field at all, so its body is constant —
	// exactly the shape that collides.
	transport, err := ramphttpsig.New(
		correlationTransport{base: base}, "", nil,
		ramphttpsig.MonotonicWindow(cfg.Clock, cfg.SignatureTTL),
		ramphttpsig.WithKeySource(cfg.Keys),
		ramphttpsig.WithRAMPTargets(rampTargetsOf(relayURL)),
	)
	if err != nil {
		return nil, fmt.Errorf("rampclient: build signing transport: %w", err)
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       cfg.Timeout,
		CheckRedirect: refuseRedirects,
	}, nil
}

// refuseRedirects stops the client following any 3xx.
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	// Query stripped, not url.URL.Redacted(): Redacted masks userinfo passwords
	// only, and a RAMP target's query is not something to render into a log on the
	// assumption that it holds nothing worth hiding.
	target := *req.URL
	target.RawQuery, target.Fragment, target.User = "", "", nil
	return fmt.Errorf("rampclient: refusing redirect to %s: a RAMP call is never redirected",
		target.String())
}

// Register creates (or idempotently re-reads) the calling agent's account at the
// Exchange the request names. The Exchange derives WHO is registering from the
// request signature alone, so req carries the business payload and no identity.
//
// The destination is read off req.exchange rather than taken as an argument, the
// way the SDK's report leg reads it off the report. That is not a style choice:
// a parameter is something a configured origin could arrive as, and reading the
// destination off the message the signature covers leaves no such seam. It also
// means the value that decides where the call goes is the same value the
// receiving Exchange checks it against.
//
// req is sent as the caller built it. This client no longer stamps the recipient
// — that field is now the agent's own statement of which Exchange it means, and
// overwriting it would send the request somewhere other than the caller asked.
func (c *Client) Register(
	ctx context.Context, req *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	const op = "register"
	client, err := c.exchangeClient(ctx, req.GetExchange(), op)
	if err != nil {
		return nil, err
	}
	return unary(ctx, client.Register, req)
}

// AccountStatus reports the calling agent's account state at the Exchange the
// request names. GetAccountStatusRequest carries no identifying field beyond
// that — the Exchange resolves the account from the verified signature.
func (c *Client) AccountStatus(
	ctx context.Context, req *rampv1.GetAccountStatusRequest,
) (*rampv1.GetAccountStatusResponse, error) {
	// A verb phrase, like every other op on this surface. It names the failing
	// call inside the error text — CallError renders it, so it arrives on the err
	// field of identity.mcp.call_failed, beside op=ramp_status. The op field
	// itself carries the tool name and never this value, so an operator reads the
	// verb as part of the cause rather than as the thing they filter on.
	const op = "read account status"
	client, err := c.exchangeClient(ctx, req.GetExchange(), op)
	if err != nil {
		return nil, err
	}
	resp, err := unary(ctx, client.GetAccountStatus, req)
	if err != nil {
		return nil, noAccount(req.GetExchange(), err)
	}
	return resp, nil
}

// Execute buys the offers in req through the Broker's execute relay and returns
// the Exchange's TransactionResponse — one result item per offer, each carrying
// a signed delivery URL or a typed denial. A batch of one is not special-cased:
// a single offer is the degenerate 1-element items[].
//
// req carries ver, idempotency_key, requester, and each item's offer; this
// method fills in each item's detached AgentAcceptance, signed with the caller's
// own key over that offer + the shared requester + the shared idempotency_key.
// The acceptance is the agent's binding the Exchange verifies (topology-
// independent, unlike the transport signature), which is why it is signed here
// and not left to the transport.
func (c *Client) Execute(
	ctx context.Context, req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	key, err := c.keys(ctx)
	if err != nil {
		// The SDK's class, not this package's, and deliberately. A custody failure
		// is one condition, and the service's other three outbound legs already
		// report it as not-signable — so an operator alert keyed on that token was
		// silent on exactly the leg where money moves. This package's own Kind set
		// has no member for it, and adding one would be a second vocabulary that
		// has to keep agreeing with the first by spelling.
		//
		// The cause stays wrapped so errors.Is still reaches the custody sentinel
		// underneath: "no authenticated agent" and "custody is down" are different
		// conditions with different answers.
		return nil, &rampsdkconnect.CallError{
			Kind: rampsdkconnect.CallNotSignable, Op: "execute",
			Err: fmt.Errorf("resolve signing key: %w", err),
		}
	}
	signed, err := signAcceptances(req, key.Private)
	if err != nil {
		return nil, err
	}
	return c.postRelay(ctx, signed)
}
