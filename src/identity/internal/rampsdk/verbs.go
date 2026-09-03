package rampsdk

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// Resolve runs discovery through the Broker, which fans the query out to the
// Exchanges it knows and returns one group per requested URI.
//
// Every returned offer is verified. That is the point of routing this through
// the SDK rather than reading the response as it arrives: the Broker forwards
// offers it did not mint, and an agent reached through the MCP surface runs no
// verifier of its own, so this is the only place the check can happen on its
// behalf. A doctored offer would otherwise steer the agent's choice and fail
// much later, at the purchase, pointing at the agent rather than at the relay.
//
// Verification is fail-closed and there is no opt-out here. An offer that cannot
// be verified is returned as rejected with its reason, never as an offer.
func (c *Client) Resolve(ctx context.Context, req *rampv1.DiscoveryRequest) (core.DiscoveryResult, error) {
	opts, err := c.callOptions(ctx, "resolve offers")
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	broker := connect.NewBrokerClient(c.brokerURL, append(
		opts,
		// Keyed per exchange DOMAIN, because broker fan-out returns offers minted
		// by different Exchanges — a single pinned key would reject every offer
		// but one issuer's.
		connect.WithKeyResolver(c.offerKeys),
	)...)
	return broker.Resolve(ctx, req)
}

// ReportUsage files a usage report with the Exchange that ISSUED the offer.
//
// The destination is read off the report's own exchange field and resolved
// through that Exchange's well-known manifest. It is not an argument, and there
// is no configuration slot for it: a signature covers the domain but says
// nothing about where that domain's endpoint lives, so the endpoint always comes
// from the Exchange itself. Leaving nowhere for a configured origin to be passed
// is what keeps that structural rather than conventional.
func (c *Client) ReportUsage(
	ctx context.Context, report *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	opts, err := c.callOptions(ctx, "report usage")
	if err != nil {
		return nil, err
	}
	return connect.NewClient(homeExchangePlaceholder, opts...).ReportUsage(ctx, report)
}

// ContentFetch retrieves the content one signed delivery URL names, presenting
// proof of possession of the agent key that URL is bound to.
//
// The registry fetches rather than the agent because the key the Exchange bound
// the URL to is custodied here and never reaches the agent, so an agent-side
// fetch could only ever be refused by an edge that enforces the binding.
type ContentFetch = func(ctx context.Context, signedURL string) (resolvers.Content, error)

// ContentSession resolves the calling agent's key once and returns a fetch bound
// to it, for every item of one purchase.
//
// A session rather than a plain Fetch, because the alternative is a client per
// ITEM and that costs a connection pool per item. The SDK composes its SSRF guard
// by cloning the transport it is handed, and a clone carries the settings and not
// the idle connections — so N items means N TLS handshakes against the same edge
// and N abandoned transports holding sockets and goroutines until they idle out.
// The batch size is the authenticated caller's choice.
//
// One purchase is one agent, so one client covers the batch. What stays per-call
// is the identity, which is the whole reason a client is built per call rather
// than once per process.
func (c *Client) ContentSession(ctx context.Context) (ContentFetch, error) {
	opts, err := c.callOptions(ctx, "fetch content")
	if err != nil {
		return nil, err
	}
	// A method value, so the client it is bound to lives exactly as long as the
	// fetches that use it and there is no handle type whose only job is to hold
	// one field.
	return connect.NewClient(homeExchangePlaceholder, opts...).Fetch, nil
}

// notSignable classifies a local failure to produce the credentials a call is
// signed with. Nothing has left the process when one of these is returned.
//
// It is the SDK's own error type rather than one of ours, and deliberately: the
// SDK classifies the same condition as CallNotSignable when custody declines a
// step later, and both readers downstream — the tool error and the delivery
// failure — branch on that type. A bare error here would be the only outbound
// failure in this service carrying no class, and it renders as "unknown", which
// is the token reserved for a cause nobody could name. An operator alert keyed on
// a custody outage would then see nothing at all.
func notSignable(op string, err error) error {
	return &connect.CallError{Kind: connect.CallNotSignable, Op: op, Err: err}
}

// callOptions resolves the calling agent's key and assembles the options one
// client is built from. op names the verb, so a failure says which call could
// not be signed.
//
// The three identity-bearing options travel together and must agree. The signer
// holds the private half; the agent key presents the public half on a delivery
// fetch, which a Signer cannot yield because custody keeps the private half; and
// the directory names where a peer fetches that public half to verify the
// request signature. A client with any one of them missing fails in a way that
// names something other than the cause — an empty directory in particular
// surfaces as a 401 from a healthy Exchange, after the call was routed, signed
// and sent.
func (c *Client) callOptions(ctx context.Context, op string) ([]connect.ClientOption, error) {
	key, err := c.keys(ctx)
	if err != nil {
		// Wrapped, not replaced: a caller must still reach the custody sentinel
		// underneath through errors.Is — "no authenticated agent" and "custody is
		// down" are different conditions with different answers.
		return nil, notSignable(op, fmt.Errorf("rampsdk: resolve signing key: %w", err))
	}
	// The keyid custody hands back is READ FROM THE STORE, not recomputed from the
	// key it ships with, so a rotation bug or a partial write there puts a keyid on
	// the wire that resolves at the peer to a different public key. Every signature
	// is then rejected and nothing on this side names why.
	//
	// The rule that a keyid must identify its key belongs to whoever owns outbound
	// signing keys, and asking it here rather than restating it is what stops this
	// service's two outbound paths answering differently — the legs rampclient
	// still carries have run this check all along.
	//
	// Not reachable through the MCP surface: arranging it needs a key-store record
	// whose thumbprint disagrees with its key, which only a test writing past the
	// repository layer could produce. The rule keeps its own test where it is
	// defined; what this line buys is that both paths ask the same question.
	key, err = ramphttpsig.CompleteKey(key)
	if err != nil {
		return nil, notSignable(op, err)
	}
	signer, err := helpers.NewEd25519Signer(key.KeyID, key.Private)
	if err != nil {
		return nil, notSignable(op, fmt.Errorf("rampsdk: build signer: %w", err))
	}
	pub, ok := key.Private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, notSignable(op, fmt.Errorf("rampsdk: custody returned a non-Ed25519 key for %q", key.KeyID))
	}
	return []connect.ClientOption{
		connect.WithSigner(signer),
		connect.WithAgentKey(pub),
		connect.WithSignatureAgent(key.Directory),
		connect.WithSignWindow(c.signWindow),
		connect.WithProofWindow(c.proofWindow),
		connect.WithEndpointResolver(c.endpoints),
		// The Broker's own leg. Its timeout is the operator's to set; the
		// offer-derived leg carries its own deadline inside the SDK.
		connect.WithHTTPClient(&http.Client{Transport: c.homeBase, Timeout: c.timeout}),
		// Settings UNDER the SSRF guard, never instead of it — and settings ONLY.
		// The SDK composes the guard by cloning this transport, and a clone carries
		// the exported configuration without the idle-connection pool, so what is
		// shared here is the tuning and never a socket. Reuse on this leg comes
		// from holding one client for a batch, not from holding one transport.
		connect.WithGuardedBaseTransport(c.guardedBase),
		connect.WithContentTimeout(c.fetchTimeout),
		connect.WithMaxContentBytes(c.maxBytes),
		// Correlation from the inbound request, resolved per call. The SDK mints
		// one when the context carries none, which keeps a log line correlatable
		// even on a path that lost the header.
		//
		// It reaches all THREE legs, including the delivery fetch — which is worth
		// saying because that one is not an RPC and does not correlate the way the
		// other two do. The RPC legs stamp the header from an interceptor; a plain
		// GET never traverses one, so the fetcher takes this same mint through its
		// own hook. Dropping this option does not leave the fetch bare: the SDK
		// falls back to its own mint, so the edge records the delivery under an id
		// nothing on this side has ever seen, which is worse than an absent header
		// because it looks correlated.
		connect.WithRequestIDFunc(func() string { return reqctx.IDOrNew(ctx) }),
	}, nil
}
