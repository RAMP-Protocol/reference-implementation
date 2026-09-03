// Package mcp is the Identity Service's RAMP adapter: the MCP endpoint an
// SDK-less agent drives, and the tools that turn each call into a key-signed RAMP
// request to the Broker or an Exchange.
//
// # Two hops, never bridged
//
// Inbound, the caller authenticates to US with an OAuth 2.1 bearer token minted by
// developer sign-in. Outbound, the RAMP request is signed with THAT caller's own
// custodied Ed25519 key, so the Broker and the Exchange see the individual agent,
// not the registry. The two are deliberately separate mechanisms: the bearer never
// travels outbound, and a RAMP signature never authenticates anyone to this
// endpoint. Bridging them — signing outbound on the strength of a bearer alone
// without resolving that user's key, or accepting a RAMP signature as a login —
// would collapse every MCP user into one RAMP identity.
//
// The join between the hops is auth.go: the verified token's subject (the
// developer's subdomain) goes onto the request context, and the outbound signer
// reads it from there. Each tool additionally re-reads that identity from the
// SDK's per-request TokenInfo and fails closed if the two disagree (see
// callerFrom in caller.go) — because the context a tool handler receives belongs
// to the session, not to the request being served, so the context alone would
// answer "whoever opened the session". No tool takes an agent argument, so a
// caller cannot ask to be someone else.
//
// # Tool shapes follow the protocol
//
// Each tool's input and output is a projection of the RAMP protocol message it
// carries, not a convenience shape of our own. An Offer travels back to the caller
// as the JSON object the Broker returned, because its signature covers those
// bytes: re-modelling it here would risk dropping a field and invalidating the
// signature when the agent hands it back.
//
// That fidelity has one limit worth naming, because it is not obvious and the
// obvious reading is wrong: the object is re-encoded from a message decoded
// against the protocol version this service pins, and protojson does not emit
// fields that version does not declare. A peer running a NEWER protocol would
// therefore have fields silently dropped. protoToMap refuses that case outright
// rather than handing over an offer whose signature can no longer verify.
//
// # Scope
//
// Five tools, all named ramp_*: ramp_register, ramp_status, ramp_discover,
// ramp_execute, ramp_report.
//
// ramp_execute returns the signed delivery URL per item AND the content itself,
// fetched here rather than by the agent (ADR-023). The Exchange binds each
// delivery URL to the key that signed the offer acceptance, and a capable edge
// makes the fetcher prove possession of it; in the custodial flow that key lives
// in Vault and never reaches the agent, so an agent-side fetch could only ever
// be refused. Fetching from here — where the key is — is what lets the edge keep
// enforcing rather than having to be switched off.
//
// The bytes come back as MCP embedded resources on the tool result, and nothing
// is stored: the fetch happens inside the call that pays for it, so there is no
// state to keep between calls and no second delivery for the edge's log to
// record. A fetch that fails does NOT fail the call — the transaction is already
// paid for, so the failure is reported alongside the URL, which the agent can
// still use itself.
package mcp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// EndpointPath is where the MCP endpoint is mounted. Clients speak Streamable
// HTTP against it.
const EndpointPath = "/mcp"

// serverName and serverVersion identify this implementation to MCP clients during
// initialize.
const (
	serverName    = "ramp-registry"
	serverVersion = "1.0"
)

// SessionTimeout closes a session that has gone this long without a request.
//
// Sized for an agent workload rather than a human one: a tool call and the RAMP
// legs behind it complete in seconds, and an agent that has more to do sends the
// next call promptly. Ten minutes is generous for that and still bounds how long
// an abandoned session holds its goroutines. A client that is merely slow
// reconnects; nothing but the session's own liveness depends on it.
const SessionTimeout = 10 * time.Minute

// Config wires the MCP adapter. Every collaborator is required, and validate()
// below is the enumeration: an adapter with no token issuer cannot
// authenticate, with no account service cannot register, with no RAMP client
// cannot buy, and with no issuer URL cannot tell a client where to sign in.
//
// Two kinds of field are exempt, and both mean something when left unset.
// ExchangeAllowed is nil for a deployment that reaches every Exchange, which is
// what an unset allowlist says. The three size and time bounds default, so a
// caller states only the ones it wants moved.
type Config struct {
	// Tokens verifies the inbound bearer. It is the same issuer the sign-in flow
	// mints with, so a token is accepted here exactly when it was issued by us,
	// for us, and is still live.
	Tokens *token.Issuer

	// RAMP is the relay purchase, and only that: it goes to the Broker's relay
	// route rather than to the ExchangeService RPC the SDK's Execute calls, which
	// is why this package still sends it itself. Signed per request as the
	// authenticated agent. Typed as the narrow port this package actually calls
	// (see ports.go for why the seam is declared here); *rampclient.Client
	// satisfies it.
	//
	// Registration and account status are NOT on this port. They travel through
	// Accounts below, which owns the workflow they belong to. This is the field a
	// reader opens Config to see what the adapter is wired with, so it says where
	// the other two went rather than leaving a reader to find out from ports.go.
	RAMP rampCaller

	// Discovery resolves offers through the Broker and returns them already
	// verified. Separate from RAMP because the SDK serves it (see ports.go).
	Discovery discoverer

	// Reports files a usage report with the Exchange that issued the offer.
	// Separate from RAMP for the same reason as Discovery.
	Reports reporter

	// Accounts opens and reports the caller's Exchange accounts. It owns the
	// requirements read, the pre-check, the send and the local note; the two
	// account tools are decode-call-render over it.
	Accounts *exchacct.Service

	// ExchangeAllowed is the deployment's Exchange policy. Optional: nil permits
	// every Exchange, which is the same answer an unset allowlist gives.
	ExchangeAllowed exchangeAllowed

	// Content fetches licensed bytes from the delivery edge, signed as the calling
	// agent. Typed as the narrow port this package calls (see ports.go).
	//
	// Required, like everything else here. ramp_execute promises the content, so
	// an adapter wired without a fetcher cannot honour its own contract — and
	// discovering that per call would surface as a delivery failure on every
	// purchase rather than as the wiring mistake it is.
	Content contentFetcher

	// CallTimeout bounds one ramp_execute's whole content leg, and
	// MaxCallContentBytes what it may accumulate. Both default; both are
	// CALL-scoped, which is why they live here and not on the fetcher.
	//
	// MaxItemContentBytes must be the SAME value the fetcher was built with —
	// app.Build passes one resolved number to both. It is not a second cap; it is
	// how the budget check knows what a single fetch could still cost.
	CallTimeout         time.Duration
	MaxCallContentBytes int64
	MaxItemContentBytes int64

	// IssuerURL is this service's public origin, which is both the OAuth issuer
	// identifier and the base the endpoint's resource identifier is derived from.
	IssuerURL string

	// AgentDirectory builds a caller's directory origin — the value a tool puts in
	// requester.id. Pass (*agentsign.Resolver).DirectoryOrigin: that is the same
	// function the outbound signer publishes in Signature-Agent, and the
	// Broker/Exchange authorize a call by comparing the two. Taking the function
	// rather than a scheme is what makes the two impossible to spell differently;
	// a scheme here would be a second setting that could drift from the signer's.
	AgentDirectory func(subdomain string) string

	// Logger receives endpoint-level events.
	Logger *slog.Logger
}

// Server mounts the MCP endpoint and its OAuth discovery document on the identity
// service's mux. It satisfies transport.RouteRegistrar.
type Server struct {
	handler     http.Handler
	metadata    http.Handler
	metadataURL string
}

// New assembles the MCP adapter: one MCP server carrying the five tools, wrapped
// in the bearer gate, plus the RFC 9728 metadata document that tells a client
// where to get a token.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	metadataURL, err := metadataIdentifier(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	// The advertised resource identifier is read off the issuer rather than
	// derived from the endpoint's URL: it must be exactly what tokens are
	// audience-bound to, and taking it from anywhere else lets the two drift into
	// a state where correctly-issued tokens are refused for the wrong resource.
	resourceURL := cfg.Tokens.Audience()

	srv := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)
	cfg = cfg.withDefaults()
	tools := &toolset{
		ramp:                cfg.RAMP,
		discovery:           cfg.Discovery,
		reports:             cfg.Reports,
		accounts:            cfg.Accounts,
		exchangeAllowed:     cfg.ExchangeAllowed,
		content:             cfg.Content,
		callTimeout:         cfg.CallTimeout,
		maxCallContentBytes: cfg.MaxCallContentBytes,
		maxItemContentBytes: cfg.MaxItemContentBytes,
		log:                 cfg.Logger,
		directory:           cfg.AgentDirectory,
	}
	tools.register(srv)

	// One server instance serves every connection: the tools hold no per-caller
	// state, and everything caller-specific already rides on the request context.
	//
	// SessionTimeout is set explicitly because the SDK's zero value means idle
	// sessions are NEVER closed: a session leaves the handler's map only on an
	// explicit DELETE, so a client that opens sessions and does not delete them —
	// self-service sign-up makes that one account's choice, and a crash-looping
	// client does it by accident — leaks a live ServerSession, its connection, and
	// its goroutines per initialize.
	streamable := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return srv },
		&mcpsdk.StreamableHTTPOptions{SessionTimeout: SessionTimeout},
	)
	return &Server{
		handler:     requireBearer(streamable, cfg.Tokens, metadataURL),
		metadata:    metadataHandler(protectedResourceMetadata(resourceURL, cfg.IssuerURL)),
		metadataURL: metadataURL,
	}, nil
}

func (c Config) validate() error {
	switch {
	case c.Tokens == nil:
		return errors.New("mcp: Config.Tokens is required")
	case c.RAMP == nil:
		return errors.New("mcp: Config.RAMP is required")
	case c.Discovery == nil:
		return errors.New("mcp: Config.Discovery is required")
	case c.Reports == nil:
		return errors.New("mcp: Config.Reports is required")
	case c.Accounts == nil:
		return errors.New("mcp: Config.Accounts is required")
	case c.Content == nil:
		return errors.New("mcp: Config.Content is required")
	case c.IssuerURL == "":
		return errors.New("mcp: Config.IssuerURL is required")
	case c.AgentDirectory == nil:
		return errors.New("mcp: Config.AgentDirectory is required")
	case c.Logger == nil:
		return errors.New("mcp: Config.Logger is required")
	}
	// A per-item cap above the call budget is not a large batch — it is a batch
	// that silently collapses to one item, with every remaining licensed-and-CHARGED
	// item reported as budget-exhausted. Refusing at startup names the
	// misconfiguration; discovering it per call surfaces as paid-for content the
	// agent never receives.
	if c.MaxItemContentBytes > 0 && c.MaxCallContentBytes > 0 &&
		c.MaxItemContentBytes > c.MaxCallContentBytes {
		return fmt.Errorf(
			"mcp: Config.MaxItemContentBytes (%d) exceeds Config.MaxCallContentBytes (%d): "+
				"a call could then admit at most one item",
			c.MaxItemContentBytes, c.MaxCallContentBytes,
		)
	}
	return nil
}

// withDefaults resolves the optional bounds once, so the toolset reads settled
// values and no handler has to re-ask what "unset" meant.
func (c Config) withDefaults() Config {
	if c.CallTimeout <= 0 {
		c.CallTimeout = DefaultCallTimeout
	}
	if c.MaxCallContentBytes <= 0 {
		c.MaxCallContentBytes = DefaultMaxCallContentBytes
	}
	if c.MaxItemContentBytes <= 0 {
		c.MaxItemContentBytes = resolvers.DefaultMaxContentBytes
	}
	return c
}

// RegisterRoutes mounts the endpoint and its discovery document. The metadata
// route is deliberately OUTSIDE the bearer gate: a client fetches it precisely
// because it does not yet have a token.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(EndpointPath, s.handler)
	mux.Handle(EndpointPath+"/", s.handler)
	mux.Handle("GET "+ProtectedResourceMetadataPath, s.metadata)
}

// metadataIdentifier is the absolute URL of the protected-resource metadata
// document, which the 401 challenge points clients at.
func metadataIdentifier(issuerURL string) (string, error) {
	base, err := parseOrigin(issuerURL)
	if err != nil {
		return "", err
	}
	return base.JoinPath(ProtectedResourceMetadataPath).String(), nil
}
