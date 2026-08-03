// Package rampclient is the Identity Service's outbound RAMP leg: the Connect
// clients the MCP tools reach the Broker and the Exchanges through.
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
// # Why there is no hand-rolled HTTP here
//
// All four surfaces are Connect unary RPCs on /ramp.* paths, which the canonical
// outbound signer (internal/ramphttpsig) already covers unchanged. The one RAMP
// call that is NOT a Connect route — the Broker's execute relay at
// /broker/v1/exchange/execute — is deliberately out of scope; it needs a raw
// protojson POST and a signer that applies the RAMP covered set to a
// non-/ramp.* target, and it arrives with ramp_execute.
//
// The claim above is about RAMP traffic and stays true of it. The content leg is
// a different protocol and lives in internal/delivery: fetching a delivery URL
// means a plain GET signed under the agent-binding profile, whose covered set and
// parameter order the RAMP signer does not emit.
//
// # Two kinds of Exchange
//
// Register and GetAccountStatus go to the service's OWN configured Exchange: the
// account is per-Exchange and its endpoint is known up front. ReportUsage goes to
// whichever Exchange issued the offer being reported, resolved per call from that
// Exchange's own /.well-known/ramp.json (see endpoints.go). The registry never
// supplies a report endpoint from configuration — that is the Offer.exchange
// routing invariant.
package rampclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// DefaultTimeout bounds one outbound RAMP call. RAMP RPCs are interactive — an
// agent is waiting on the other end of a tool call — so a request that has not
// answered within this is more useful as an error than as a hang.
const DefaultTimeout = 30 * time.Second

// DefaultSignatureTTL is how long an outbound RFC 9421 signature stays valid.
// Short enough that a captured request is not replayable for long, long enough to
// absorb ordinary clock skew between us and the verifier.
const DefaultSignatureTTL = 30 * time.Second

// Config wires a Client. Signer, BrokerURL, and ExchangeURL are required; the
// rest take defaults.
type Config struct {
	// Signer resolves the key each outbound request is signed with, per request,
	// from the authenticated identity on the context. Pass
	// agentsign.Resolver.Source().
	Signer ramphttpsig.KeySource

	// BrokerURL is the Broker's Connect origin (discovery).
	BrokerURL string

	// ExchangeURL is the service's own Exchange origin, where the agents'
	// accounts live (register, status).
	ExchangeURL string

	// Fetch is the HTTP client used to read other Exchanges' well-known
	// manifests when resolving a report endpoint. It fetches attacker-influenced
	// hosts, so it should be SSRF-guarded
	// (resolvers.NewGuardedClientFromEnv). Defaults to that.
	//
	// The SSRF policy itself is not configured here: the SDK owns the guard and
	// reads its two flags (SKIP_SSRF, ALLOW_INSECURE) from the environment, so
	// every hop that talks to an offer-derived Exchange shares one policy rather
	// than a per-caller copy that can drift from it.
	Fetch *http.Client

	// Scheme is the URL scheme used to fetch those manifests ("https" in
	// production, "http" for a local stack). Defaults to https.
	Scheme string

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

// Client is the outbound RAMP leg. Construct it with New; it is safe for
// concurrent use.
type Client struct {
	broker    rampv1connect.BrokerServiceClient
	home      rampv1connect.ExchangeServiceClient
	exchanges *exchangePool
	endpoints endpointResolver

	// signer resolves the current caller's key. Execute needs it directly — not
	// just through the transport — because it detached-signs each offer
	// acceptance with the agent's own key before the body is serialized.
	signer ramphttpsig.KeySource
	// http is the one signing client every call shares; Execute uses it for the
	// raw relay POST (the only call that is not a generated Connect client).
	http *http.Client
	// relayURL is the Broker's execute-relay endpoint, the one RAMP call that is
	// not a Connect route.
	relayURL string
}

// New builds a Client from cfg. It fails on missing required configuration
// rather than nil-panicking on the first tool call.
func New(cfg Config) (*Client, error) {
	if cfg.Signer == nil {
		return nil, errors.New("rampclient: Config.Signer is required")
	}
	if cfg.BrokerURL == "" {
		return nil, errors.New("rampclient: Config.BrokerURL is required")
	}
	if cfg.ExchangeURL == "" {
		return nil, errors.New("rampclient: Config.ExchangeURL is required")
	}
	cfg = cfg.withDefaults()
	relayURL := strings.TrimRight(cfg.BrokerURL, "/") + relayExecutePath
	// The configured Broker and home Exchange are operator-supplied origins, so
	// they dial over the default transport. Offer-derived Exchanges are not, and
	// get the guarded one below.
	httpClient, err := signingClient(cfg, http.DefaultTransport, relayURL)
	if err != nil {
		return nil, err
	}
	// A SECOND signing client for the offer-derived leg. Its base transport is
	// the SDK's guarded one, so the dial-time public-IP check that already
	// protects the manifest fetch also covers the signed RPC that follows it.
	// Without this the guard stops one hop short: the caller names a domain, the
	// manifest it serves names any endpoint, and the RAMP-signed report goes
	// there — a signed request aimed at an arbitrary internal address.
	guarded := resolvers.NewGuardedClientFromEnv()
	reportClient, err := signingClient(cfg, guarded.Transport, relayURL)
	if err != nil {
		return nil, err
	}
	pool := newExchangePool(reportClient)
	home := rampv1connect.NewExchangeServiceClient(httpClient, cfg.ExchangeURL, connectReadCap)
	return &Client{
		broker:    rampv1connect.NewBrokerServiceClient(httpClient, cfg.BrokerURL, connectReadCap),
		home:      home,
		exchanges: pool,
		endpoints: newEndpointResolver(cfg),
		signer:    cfg.Signer,
		http:      httpClient,
		relayURL:  relayURL,
	}, nil
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
// every agent without ever binding one agent's key. base is the underlying
// round-tripper — the default one for operator-configured origins, the
// SSRF-guarded one for origins an offer named.
//
// Redirects are refused outright: a RAMP RPC has no legitimate reason to be
// redirected, and following one would re-sign the caller's request for a target
// the peer chose. That also keeps the endpoint check in ReportUsage meaningful,
// since a redirect would otherwise move the destination after the check ran.
func signingClient(cfg Config, base http.RoundTripper, relayURL string) (*http.Client, error) {
	// directory and priv are zero: WithKeySource supplies both per request, and
	// New skips the static-key path entirely when a KeySource is present.
	// WithRAMPTargets adds the execute relay route to the RAMP-signed set — it is
	// not a /ramp.* path but the Broker verifies its body under the RAMP covered
	// set (relay_core.go), so it must be signed as RAMP, not WBA.
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
		ramphttpsig.WithKeySource(cfg.Signer),
		ramphttpsig.WithRAMPTargets(relayTargetOf(relayURL)),
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

// Register creates (or idempotently re-reads) the calling agent's account on the
// service's own Exchange. The Exchange derives WHO is registering from the
// request signature alone, so req carries the business payload and no identity.
func (c *Client) Register(
	ctx context.Context, req *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	return unary(ctx, c.home.Register, req)
}

// AccountStatus reports the calling agent's account state on the service's own
// Exchange. GetAccountStatusRequest deliberately carries no identifying field —
// the Exchange resolves the account from the verified signature.
func (c *Client) AccountStatus(
	ctx context.Context, req *rampv1.GetAccountStatusRequest,
) (*rampv1.GetAccountStatusResponse, error) {
	return unary(ctx, c.home.GetAccountStatus, req)
}

// Resolve runs discovery through the Broker, which fans out to the Exchanges and
// returns one OfferGroup per requested URI.
func (c *Client) Resolve(
	ctx context.Context, req *rampv1.DiscoveryRequest,
) (*rampv1.DiscoveryResponse, error) {
	return unary(ctx, c.broker.Resolve, req)
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
	key, err := c.signer(ctx)
	if err != nil {
		// A resolution failure here is the custody sentinel (down, no active key,
		// unauthenticated) wrapped through unchanged — the same class the transport
		// would surface, caught earlier because the acceptance needs the key too.
		return nil, &Error{
			Kind: KindUnreachable, Op: "execute",
			Err: fmt.Errorf("resolve signing key: %w", err),
		}
	}
	signed, err := signAcceptances(req, key.Private)
	if err != nil {
		return nil, err
	}
	return c.postRelay(ctx, signed)
}

// ReportUsage reports usage DIRECTLY to the Exchange that issued the offer —
// never via the Broker. exchangeDomain is the signed Offer.exchange; it is
// resolved to that Exchange's self-advertised endpoint through its own
// well-known manifest, so the report always lands where the offer came from.
func (c *Client) ReportUsage(
	ctx context.Context, exchangeDomain string, req *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	endpoint, err := reportEndpoint(ctx, c.endpoints, exchangeDomain)
	if err != nil {
		return nil, err
	}
	return unary(ctx, c.exchanges.clientFor(endpoint).ReportUsage, req)
}

// reportEndpoint resolves exchangeDomain to the origin a report may be sent to,
// or refuses. Every refusal here is a *Error carrying a Kind, because the tool
// layer renders "the Exchange said no", "we could not reach it" and "we refused
// to dial it" differently and can only tell them apart from the Kind.
//
// Split out of ReportUsage so the send is one line: the vetting is the part that
// grows, and reading it in one place is what makes it obvious that no branch
// falls through to the send.
func reportEndpoint(
	ctx context.Context, resolver endpointResolver, exchangeDomain string,
) (string, error) {
	// A bare host, checked again here even though the tool layer already checked
	// it. The resolver builds its URL by concatenating this value, so a path or
	// query smuggled through would choose what gets fetched; this package owns the
	// call and cannot rely on every present and future caller to have vetted it.
	bare, err := rampwellknown.IsBareHost(exchangeDomain)
	if err != nil {
		return "", &Error{
			Kind: KindUnreachable, Op: "report usage",
			Err: fmt.Errorf("exchange %q is not a usable domain: %w", exchangeDomain, err),
		}
	}
	if !bare {
		return "", &Error{
			Kind: KindUnreachable, Op: "report usage",
			Err: fmt.Errorf("exchange %q is not a bare domain, refusing to resolve it", exchangeDomain),
		}
	}
	endpoint, err := resolver.ResolveEndpoint(ctx, exchangeDomain)
	if err != nil {
		return "", &Error{
			Kind: KindUnreachable, Op: "report usage",
			Err: fmt.Errorf("resolve exchange %q: %w", exchangeDomain, err),
		}
	}
	// The manifest that named this endpoint is served by the very host the caller
	// asked us to report to, so the endpoint is only as trustworthy as that host.
	// Anchoring it to the domain it was resolved from keeps a manifest from
	// redirecting a signed report to an unrelated host: an Exchange may advertise
	// itself or a subdomain of itself, and nothing else. The dial-time guard
	// behind this client refuses private addresses independently; this is the
	// second half, and it is what stops delivery to an unrelated PUBLIC host.
	anchored, err := rampwellknown.HostAnchored(exchangeDomain, endpoint)
	if err != nil {
		return "", &Error{
			Kind: KindUnreachable, Op: "report usage",
			Err: fmt.Errorf("check exchange %q endpoint %q: %w", exchangeDomain, endpoint, err),
		}
	}
	if !anchored {
		return "", &Error{
			Kind: KindUnreachable, Op: "report usage",
			Err: fmt.Errorf(
				"exchange %q advertises endpoint %q on a different host — refusing to send a signed report there",
				exchangeDomain, endpoint,
			),
		}
	}
	return endpoint, nil
}
