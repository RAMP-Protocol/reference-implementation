// Package app is the Identity Service's composition root. It wires the persistence
// repos, the Vault key custody, the publisher service, the well-known transport, and
// (optionally) the OAuth developer sign-up server into one http.Handler. Both the
// production binary (cmd/server) and the integration tests build the server through
// Build, so a test drives the same wiring that ships — closing the gap where the
// binary and the test fixture assembled the server differently.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/offerkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchpolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/mcp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampclient"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampsdk"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/transport"

	"github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config wires the identity server. Pool, Keys, BaseDomain, Logger, and Auth are
// required; the rest take defaults. Developer sign-up is mandatory, so Auth must be
// set — Build rejects a nil Auth rather than serving a well-known-only server.
type Config struct {
	Pool            *pgxpool.Pool
	Keys            *keystore.VaultStore
	Logger          *slog.Logger
	BaseDomain      string
	DirectoryTTL    time.Duration
	WellKnownScheme string // scheme for the per-subdomain revocation_url; defaults to https
	Health          func(context.Context) error
	Clock           clock.Clock // defaults to the system clock

	Auth *AuthConfig
	MCP  *MCPConfig
}

// MCPConfig wires the RAMP adapter — the MCP endpoint and its tools. It is
// MANDATORY: the RAMP adapter is the identity service's agent-facing surface, so
// Build fails closed when it is absent rather than serving a directory-and-sign-up
// server that no agent can act through. BrokerURL is required; the rest take
// defaults.
//
// There is no Exchange origin here. An account is per-Exchange, the agent names
// which one per call, and the endpoint comes from that Exchange's own manifest —
// so a configured origin would be a second answer to a question the protocol
// already answers, and there is nowhere for one to be passed in.
type MCPConfig struct {
	// BrokerURL is the Broker's Connect origin, where discovery goes.
	BrokerURL string
	// ExchangeAllowlist confines this deployment to a set of Exchanges: a
	// comma-separated list of bare domains. Empty permits every Exchange, which
	// is how this service behaved before the lever existed.
	//
	// See exchpolicy for why the lever exists, which outbound legs it governs and
	// which two it cannot. That rationale is stated there and not restated here:
	// this copy had already drifted from it inside one commit, disagreeing about
	// what the SSRF guard stops.
	ExchangeAllowlist string

	// WellKnownScheme is the scheme for /.well-known/ramp.json fetches. A usage
	// report goes to the Exchange that issued the offer — identified in the offer
	// by domain only — so the client fetches that domain's manifest to discover
	// its endpoint. "https" unless overridden for local development.
	WellKnownScheme string
	// CallTimeout bounds one outbound RAMP call; SignatureTTL caps the lifetime
	// of the RFC 9421 signature on it. Both default inside the RAMP client.
	CallTimeout  time.Duration
	SignatureTTL time.Duration
	// PoPTTL caps the proof of possession on a content fetch.
	//
	// It is SEPARATE from SignatureTTL even though both are short-lived assertions
	// about the same key, because they carry different risk. A RAMP signature is
	// replay-protected server-side; the delivery edge deliberately keeps no replay
	// store (ADR-013 D2) and the proof covers only the method and the URL, so its
	// lifetime IS a replay window. Sharing one knob meant raising the RAMP TTL for
	// a slow peer silently widened that window.
	PoPTTL time.Duration
	// FetchTimeout bounds one content fetch from a delivery edge, and
	// MaxContentBytes caps one fetched body. Both default inside the fetcher.
	// They are separate from CallTimeout because a publisher's edge is not a RAMP
	// peer: it serves whole documents rather than small protocol messages, and it
	// is reached over the open internet rather than an operator-configured origin.
	FetchTimeout    time.Duration
	MaxContentBytes int64
	// CallContentTimeout bounds one ramp_execute's WHOLE content leg and
	// MaxCallContentBytes what it may accumulate. FetchTimeout and MaxContentBytes
	// above bound a single item; these bound the batch, whose size is the caller's
	// choice. Both default inside the MCP adapter.
	CallContentTimeout  time.Duration
	MaxCallContentBytes int64
}

// AuthConfig wires the OAuth developer sign-up server, which is always mounted.
// Issuer, Upstream, SessionKey, and Tokens are required; Slugs defaults to a random
// generator and the TTLs default inside the auth server.
type AuthConfig struct {
	Issuer        string
	Upstream      oidcup.Authenticator
	SessionKey    []byte
	Tokens        *token.Issuer
	Slugs         signup.SlugGen
	SecureCookies bool
	CodeTTL       time.Duration
	TokenTTL      time.Duration
	KeyLifetime   time.Duration
}

// Build assembles the identity service's HTTP handler from cfg. It also returns the
// publisher service so the caller can wire background work (the rotation scheduler)
// onto the same instance a rotation must be visible through. It returns an error
// rather than panicking so a misconfiguration fails startup cleanly.
func Build(cfg Config) (http.Handler, *publisher.Service, error) {
	if cfg.Auth == nil {
		return nil, nil, errors.New("app: Auth is required — developer sign-up is mandatory")
	}
	// The RAMP adapter is a mandatory part of the identity service: without it the
	// server has no agent-facing surface. Checked up front, before any DB or
	// keystore work, so a misconfiguration fails startup cleanly and cheaply.
	if cfg.MCP == nil {
		return nil, nil, errors.New("app: MCP is required — the RAMP adapter is a mandatory part of the identity service")
	}
	// Checked here rather than left to the first user. Build reads the Exchange
	// policy onto a log line while assembling the adapter, which is reached before
	// mcp.New validates its own config — so without this check a nil Logger is a
	// nil-pointer panic at that line instead of the error this function promises.
	if cfg.Logger == nil {
		return nil, nil, errors.New(
			"app: Logger is required — the boot lines are written before anything is served")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	svc, err := publisher.New(publisher.Config{
		Keys:            cfg.Keys,
		Cards:           repo.NewCardRepo(cfg.Pool),
		Revocations:     repo.NewRevocationRepo(cfg.Pool),
		Registrations:   repo.NewDeveloperRepo(cfg.Pool),
		WellKnownScheme: cfg.WellKnownScheme,
		TTL:             cfg.DirectoryTTL,
		Clock:           clk,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("app: publisher: %w", err)
	}
	ttl := cfg.DirectoryTTL
	if ttl <= 0 {
		ttl = publisher.DefaultTTL
	}
	handler := transport.NewHandler(cfg.BaseDomain, svc, ttl)

	// Developer sign-up and the RAMP adapter are both mandatory routers, so both
	// are built up front and either failing fails the whole build.
	oauthSrv, err := buildAuthServer(cfg, svc, clk)
	if err != nil {
		return nil, nil, err
	}
	mcpSrv, err := buildMCPServer(cfg, clk)
	if err != nil {
		return nil, nil, err
	}
	opts := []transport.ServerOption{
		transport.WithRoutes(oauthSrv),
		transport.WithRoutes(mcpSrv),
	}
	return transport.NewServer(cfg.Logger, handler, cfg.Health, opts...), svc, nil
}

// outboundPosture is what every leg this service dials shares: the one guarded
// client, the one endpoint resolver, and the deployment's Exchange policy.
//
// Grouped rather than passed as three arguments because they are one decision.
// Each is deliberately built ONCE and handed to several consumers, and the
// reason is the same each time — a second construction is a second answer, and
// on the account leg a second answer to "where does this Exchange live" sends a
// signed registration somewhere the operator never chose.
type outboundPosture struct {
	guarded   *http.Client
	endpoints connect.EndpointResolver
	allow     *exchpolicy.Allowlist
}

// buildOutboundPosture assembles what this service's outbound legs share, and
// fails the boot on a policy it cannot parse.
func buildOutboundPosture(cfg Config, clk clock.Clock) (outboundPosture, error) {
	// ONE guarded client for the three outbound hops that FETCH from a host an
	// offer or an agent named: the offer-key directory lookup, the endpoint
	// resolver's manifest read, and the registration-requirements read. Built here
	// rather than defaulted inside each package because this is the only place
	// that can show the service's outbound posture at all — three constructions
	// would be three connection pools to the same hosts and three reads of the
	// SSRF environment, with no file naming the set.
	//
	// It is not every hop that reaches such a host. The usage report, the account
	// RPCs and the delivery fetch go to addresses those lookups return, and they
	// dial under the SDK's guard too — composed by cloning a base transport, so
	// they carry their own pools. The POLICY is what is shared: the SDK reads
	// SKIP_SSRF and ALLOW_INSECURE from the environment, once per construction, in
	// this process, so the guard cannot mean one thing on one leg and another on
	// the next.
	guarded := resolvers.NewGuardedClientFromEnv()

	// The deployment's Exchange policy. Parsed here so a malformed entry stops the
	// boot, and read back on one log line so an operator checks what was PARSED
	// rather than what they believe they set.
	allow, err := exchpolicy.New(cfg.MCP.ExchangeAllowlist)
	if err != nil {
		return outboundPosture{}, fmt.Errorf("app: %w", err)
	}
	cfg.Logger.Info("identity.mcp.exchange_policy",
		"allowlist", allow.Domains(), "permits_any", allow.Empty())

	// The ONE endpoint resolver every Exchange-facing leg shares. A usage report
	// and an account call resolve through the same manifest cache and the same
	// same-host rule, so the two cannot come to disagree about where an Exchange
	// lives.
	//
	// Allow is the policy overlay, and it sits here because the SDK consults it
	// BEFORE any fetch — so no leg that routes through a resolver can be sent to a
	// domain the deployment excluded, whatever its own call site checks.
	endpoints := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		HTTP: guarded,
		// Now comes from the injected clock so the manifest cache's freshness
		// window reads the same time source as the signature window, rather than
		// reading the wall clock behind the port's back.
		Now:    clk.Now,
		Scheme: cfg.MCP.WellKnownScheme,
		Allow:  allow.Permits,
	})
	return outboundPosture{guarded: guarded, endpoints: endpoints, allow: allow}, nil
}

// buildAccountService composes the Exchange-account workflow: what a target
// Exchange asks of a registration, the signed call that opens or reports one,
// and the local note behind the no-argument status.
//
// The requirements reader is built here rather than inside the service because
// it needs the ONE guarded client the outbound posture carries — the manifest
// host comes from an authenticated agent's tool argument, so that read is a
// request-derived address and has to dial under the same guard as every other
// leg that fetches from a host somebody named.
func buildAccountService(
	cfg Config, clk clock.Clock, posture outboundPosture, ramp exchacct.Caller,
) (*exchacct.Service, error) {
	requirements, err := exchreg.New(exchreg.Config{
		Fetch:   posture.guarded,
		Scheme:  cfg.MCP.WellKnownScheme,
		Timeout: cfg.MCP.CallTimeout,
		Allow:   posture.allow.Permits,
	})
	if err != nil {
		return nil, fmt.Errorf("app: exchange registration requirements: %w", err)
	}
	accounts, err := exchacct.New(exchacct.Config{
		Requirements: requirements,
		Caller:       ramp,
		// The service gets the narrow note log, never a handle that could reach a
		// developer's own record.
		Notes: repo.NewExchangeRegistrationRepo(cfg.Pool),
		Clock: clk,
	})
	if err != nil {
		return nil, fmt.Errorf("app: exchange accounts: %w", err)
	}
	return accounts, nil
}

// buildMCPServer composes the RAMP adapter: key custody is reached through the
// same VaultStore the rest of the service uses, wrapped in the agentsign resolver
// that turns an authenticated caller into the key its outbound requests are signed
// with.
//
// The scheme the resolver publishes in Signature-Agent must be the one the agent's
// directory is actually served on, so it comes from the same WellKnownScheme the
// publisher builds documents with rather than a second setting that could drift
// from it. The adapter then takes the resolver's DirectoryOrigin function itself
// rather than that scheme, so requester.id and Signature-Agent cannot disagree
// even if a future change gives them separate settings.
func buildMCPServer(cfg Config, clk clock.Clock) (*mcp.Server, error) {
	signer, err := agentsign.New(agentsign.Config{
		Keys:   cfg.Keys,
		Scheme: cfg.WellKnownScheme,
	})
	if err != nil {
		return nil, fmt.Errorf("app: agentsign: %w", err)
	}
	// Resolved once, here, because TWO consumers need the same number: the fetcher
	// enforces it per body, and the MCP layer's call budget subtracts it to decide
	// whether the next item could still fit. Letting each side default
	// independently is how they would come to disagree.
	maxItemBytes := cfg.MCP.MaxContentBytes
	if maxItemBytes <= 0 {
		maxItemBytes = resolvers.DefaultMaxContentBytes
	}
	posture, err := buildOutboundPosture(cfg, clk)
	if err != nil {
		return nil, err
	}

	ramp, err := rampclient.New(rampclient.Config{
		Keys:      signer.Source(),
		BrokerURL: cfg.MCP.BrokerURL,
		Endpoints: posture.endpoints,
		// The account RPCs dial a host the CALLER named, so they dial guarded —
		// and the guard goes UNDER the RFC 9421 signer, which is why this is a
		// transport rather than the finished client two lines up. Same policy as
		// that client: the SDK reads the SSRF environment on each construction, in
		// this process, so the two cannot mean different things.
		ExchangeBase: resolvers.NewGuardedTransport(nil),
		Timeout:      cfg.MCP.CallTimeout,
		SignatureTTL: cfg.MCP.SignatureTTL,
		Clock:        clk,
	})
	if err != nil {
		return nil, fmt.Errorf("app: ramp client: %w", err)
	}

	// The SDK legs take the SAME key source the RAMP client signs offer
	// acceptances with. That is the whole security argument for fetching content
	// here: the Exchange binds each delivery URL to the key that signed the
	// acceptance, so presenting a key resolved any other way would be presenting a
	// different key, and the edge would refuse it. This is the one place the two
	// could be made to disagree.
	sdk, err := rampsdk.New(rampsdk.Config{
		Keys:      signer.Source(),
		BrokerURL: cfg.MCP.BrokerURL,
		Endpoints: posture.endpoints,
		// Offers arrive from a Broker that did not mint them, and the agent on the
		// other end of a tool call runs no verifier of its own. Resolving each
		// issuing Exchange's key is what lets discovery check them on its behalf.
		OfferKeys: offerkeys.New(offerkeys.Config{
			Client: posture.guarded,
			Scheme: cfg.MCP.WellKnownScheme,
			Clk:    clk,
		}),
		Timeout:      cfg.MCP.CallTimeout,
		SignatureTTL: cfg.MCP.SignatureTTL,
		PoPTTL:       cfg.MCP.PoPTTL,
		FetchTimeout: cfg.MCP.FetchTimeout,
		MaxBytes:     maxItemBytes,
		Clock:        clk,
	})
	if err != nil {
		return nil, fmt.Errorf("app: ramp sdk: %w", err)
	}
	accounts, err := buildAccountService(cfg, clk, posture, ramp)
	if err != nil {
		return nil, err
	}

	srv, err := mcp.New(mcp.Config{
		Tokens:          cfg.Auth.Tokens,
		RAMP:            ramp,
		Discovery:       sdk,
		Reports:         sdk,
		Content:         sdk,
		Accounts:        accounts,
		ExchangeAllowed: posture.allow.Permits,
		// The call-scoped bounds. MaxItemContentBytes is the SAME resolved number
		// the fetcher got, so mcp.Config.validate can refuse a per-item cap that
		// exceeds the batch budget at startup instead of collapsing every batch to
		// one item at run time.
		CallTimeout:         cfg.MCP.CallContentTimeout,
		MaxCallContentBytes: cfg.MCP.MaxCallContentBytes,
		MaxItemContentBytes: maxItemBytes,
		IssuerURL:           cfg.Auth.Issuer,
		// The signer's OWN directory construction, so a tool's requester.id is
		// byte-identical to the Signature-Agent origin the Broker/Exchange verify
		// it against — one function, not two settings that happen to match.
		AgentDirectory: signer.DirectoryOrigin,
		Logger:         cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("app: mcp: %w", err)
	}
	return srv, nil
}

// buildAuthServer composes the developer sign-up server from cfg.Auth, reusing the
// publisher as the sign-up cache invalidator so a freshly-minted key or card shows up
// at once.
func buildAuthServer(cfg Config, svc *publisher.Service, clk clock.Clock) (*oauthserver.Server, error) {
	a := cfg.Auth
	codec, err := session.NewCodec(a.SessionKey, clk)
	if err != nil {
		return nil, fmt.Errorf("app: session codec: %w", err)
	}
	slugs := a.Slugs
	if slugs == nil {
		slugs = signup.RandomSlugGen{}
	}
	signUp, err := signup.New(signup.Config{
		Keys:        cfg.Keys,
		Cards:       repo.NewCardRepo(cfg.Pool),
		Developers:  repo.NewDeveloperRepo(cfg.Pool),
		Slugs:       slugs,
		Invalidator: svc,
		Clock:       clk,
		BaseDomain:  cfg.BaseDomain,
		KeyLifetime: a.KeyLifetime,
	})
	if err != nil {
		return nil, fmt.Errorf("app: signup: %w", err)
	}
	oauthSrv, err := oauthserver.New(oauthserver.Config{
		Issuer:        a.Issuer,
		Codec:         codec,
		Upstream:      a.Upstream,
		Clients:       repo.NewOAuthRepo(cfg.Pool),
		SignUp:        signUp,
		Tokens:        a.Tokens,
		Clock:         clk,
		SecureCookies: a.SecureCookies,
		CodeTTL:       a.CodeTTL,
		TokenTTL:      a.TokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("app: oauth server: %w", err)
	}
	return oauthSrv, nil
}
