// Package rampsdk is the identity service's outbound RAMP legs that the
// protocol SDK now owns: discovery through the Broker, the usage report to the
// Exchange that issued the offer, and the content fetch against a signed
// delivery URL.
//
// # Why a client per call
//
// This service signs as whichever agent the inbound bearer authenticated, and
// resolves that agent's key per request from custody. The SDK client binds ONE
// signer, one public key and one directory origin for its lifetime — deliberately,
// because one client speaks for one agent — so a long-lived client cannot serve a
// registry that speaks for many. A client is therefore built per call, from the
// key the context resolves to.
//
// What that costs is bounded, because the expensive parts are injected rather
// than rebuilt: the endpoint resolver holds the manifest cache and is shared
// with the account leg so both resolve an Exchange the same way, the home
// transport holds its connection pool, and the signature window holds the
// running maximum that keeps repeat signatures apart. What is per-call is a
// handful of small values over those.
//
// The GUARDED leg is the exception, and it is worth naming because the obvious
// reading is wrong. The SDK composes its SSRF guard by cloning the transport it
// is given, and a clone carries the exported settings without the idle
// connections, so that leg gets a fresh pool per client.
//
// Reuse there comes from holding one client across a batch — see ContentSession,
// where the batch size is the caller's choice and the cost would otherwise scale
// with it. ReportUsage holds no client across anything: one report is one call,
// so it pays a handshake and abandons a transport whose idle connection stays
// open until it times out. That is bounded by how often an agent reports rather
// than by anything a caller can inflate, which is why it is stated here and not
// fixed — closing it means either caching clients across calls, or an SDK seam
// that takes an already-guarded transport instead of cloning one.
//
// # Two transports, and why the guard sits on only one
//
// The Broker is an operator-configured origin and is trusted as far as that
// configuration is, so it dials over the ordinary transport. An Exchange named
// inside an offer is not: the caller supplies a domain, the manifest that domain
// serves names an endpoint, and a signed call then goes there. That leg dials
// under the SDK's SSRF guard, so the dial-time address check that already covers
// the manifest fetch also covers the RPC that follows it. Without that the guard
// would stop one hop short of the request that matters.
//
// # What is NOT here
//
// Register, account status and the purchase itself stay in rampclient. The first
// two have no SDK verb yet; the purchase goes to the Broker's relay route, which
// is a raw HTTP POST rather than the ExchangeService RPC the SDK's Execute calls.
package rampsdk

import (
	"errors"
	"net/http"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
)

// DefaultTimeout bounds one outbound RAMP call. RAMP RPCs are interactive — an
// agent is waiting on the other end of a tool call — so a request that has not
// answered within this is more useful as an error than as a hang.
const DefaultTimeout = 30 * time.Second

// DefaultSignatureTTL is how long an outbound RFC 9421 signature stays valid.
// Short enough that a captured request is not replayable for long, long enough
// to absorb ordinary clock skew between us and the verifier.
const DefaultSignatureTTL = 30 * time.Second

// DefaultPoPTTL is how long a proof of possession minted for a content fetch
// stays valid.
//
// The same number as the signature TTL today and a separate constant on
// purpose, because the two bound different risks and there is no reason they
// must move together. A proof covers only the method and the URL, and the
// delivery edge keeps no replay store, so this value IS the window in which an
// observed fetch can be repeated. Sharing one constant would make shortening
// that window silently lengthen every RPC's tolerance for clock skew, or the
// reverse.
const DefaultPoPTTL = 30 * time.Second

// homeExchangePlaceholder is the base URL the exchange-facing client is built
// with, and it is never dialled.
//
// The SDK's NewClient takes the agent's HOME Exchange, which Discover and
// Execute go to. This package calls neither: its report leg routes to the
// Exchange the offer names, resolved per call from that Exchange's own manifest,
// and its fetch leg speaks to a delivery edge. A reserved-invalid host is what
// makes that structural — should a home-Exchange call ever be added here by
// mistake, it fails loudly at the first dial instead of quietly reaching
// whatever a plausible-looking default pointed at.
const homeExchangePlaceholder = "https://home.invalid"

// Config wires a Client. Keys, BrokerURL and OfferKeys are required; the rest
// take defaults.
type Config struct {
	// Keys resolves the key each outbound request is signed with, per request,
	// from the authenticated identity on the context. Pass
	// agentsign.Resolver.Source().
	Keys ramphttpsig.KeySource

	// BrokerURL is the Broker's Connect origin, where discovery goes.
	BrokerURL string

	// OfferKeys resolves an exchange domain to that exchange's offer-signing key.
	// It is REQUIRED, and it is what makes discovery fail closed: the SDK verifies
	// every relayed offer under Strict by default, so without a resolver every
	// offer would be unverifiable and rejected. Pass offerkeys.New(...).
	OfferKeys helpers.KeyResolver

	// Endpoints resolves an Exchange domain to the origin that Exchange
	// advertises for itself, and refuses an endpoint on a host unrelated to the
	// one that served the manifest. It reads each manifest through an
	// SSRF-guarded client, because the domain comes off an offer rather than out
	// of configuration.
	//
	// REQUIRED, and INJECTED rather than built here, which is the change worth
	// naming: the account leg needs the SAME instance. Two resolvers would be two
	// manifest caches and two chances for one leg to apply the same-host rule
	// while the other did not — and the account leg is where a wrong answer sends
	// a signed registration somewhere the operator never chose. Building it at the
	// composition root is also what lets a deployment's Exchange policy sit on it,
	// where no leg can be routed around it.
	Endpoints connect.EndpointResolver

	// Timeout bounds a single outbound RPC. Defaults to DefaultTimeout.
	Timeout time.Duration

	// SignatureTTL caps an outbound signature's lifetime. Defaults to
	// DefaultSignatureTTL.
	SignatureTTL time.Duration

	// PoPTTL caps the proof of possession minted for a content fetch. It is a
	// separate knob from SignatureTTL deliberately: the two are short-lived
	// assertions about the same key but not the same risk, because the proof
	// covers only the method and the URL, so within its window anyone who
	// observes the request can repeat it. Zero uses DefaultPoPTTL.
	//
	// Not the SDK's default: this package always passes a proof window, so the
	// SDK's own is never reached and naming it here would send a reader looking
	// for a value that comes from the constant above.
	PoPTTL time.Duration

	// FetchTimeout bounds one content fetch, proof minting included. Zero uses
	// the SDK default.
	FetchTimeout time.Duration

	// MaxBytes caps one fetched body. Zero uses the SDK default.
	MaxBytes int64

	// Clock is the time source both signature windows read. Defaults to the
	// system clock.
	Clock clock.Clock
}

// Client is the outbound RAMP leg the SDK owns. Construct it with New; it is
// safe for concurrent use.
type Client struct {
	keys      ramphttpsig.KeySource
	brokerURL string
	offerKeys helpers.KeyResolver

	// endpoints resolves an offer's exchange domain to that Exchange's own
	// advertised origin, and caches per host. Shared across calls so a burst of
	// reports to one Exchange fetches its manifest once — a per-call resolver
	// would fetch it every time.
	endpoints connect.EndpointResolver

	// signWindow is ONE window for the whole process. It has to be: the monotonic
	// variant keeps a running maximum so two identical requests inside one second
	// cannot produce byte-identical signatures, which the peers' replay stores
	// reject as a duplicate. A per-call window starts from zero and never sees the
	// previous call, so the property it exists for would not hold.
	signWindow core.Window
	// proofWindow is a plain clock window rather than the monotonic one. The
	// delivery edge keeps no replay store to collide in, so the drift buys
	// nothing there and a proof whose expiry ran ahead of the clock would only
	// widen the window in which an observed request can be repeated.
	proofWindow core.Window

	// homeBase and guardedBase are shared so every call dials on one set of
	// settings. homeBase carries its pool too — the SDK wraps it directly.
	// guardedBase does not: the guard is composed by cloning, so each client gets
	// its own pool underneath it, and only the tuning is common.
	homeBase    *http.Transport
	guardedBase *http.Transport

	timeout      time.Duration
	fetchTimeout time.Duration
	maxBytes     int64
}

// New builds a Client from cfg. It fails on missing required configuration
// rather than nil-panicking on the first tool call.
func New(cfg Config) (*Client, error) {
	if cfg.Keys == nil {
		return nil, errors.New("rampsdk: Config.Keys is required")
	}
	if cfg.BrokerURL == "" {
		return nil, errors.New("rampsdk: Config.BrokerURL is required")
	}
	if cfg.OfferKeys == nil {
		// Fail loud rather than fail closed-and-silent. A nil resolver still
		// produces a working client, but one under which every offer is
		// unverifiable and discovery answers "nothing on offer" for reasons no log
		// line explains.
		return nil, errors.New("rampsdk: Config.OfferKeys is required to verify relayed offers")
	}
	if cfg.Endpoints == nil {
		return nil, errors.New(
			"rampsdk: Config.Endpoints is required; build the resolver once at the " +
				"composition root and inject it, so this leg and the account leg share one")
	}
	cfg = cfg.withDefaults()
	return &Client{
		keys:         cfg.Keys,
		brokerURL:    cfg.BrokerURL,
		offerKeys:    cfg.OfferKeys,
		endpoints:    cfg.Endpoints,
		signWindow:   core.Window(ramphttpsig.MonotonicWindow(cfg.Clock, cfg.SignatureTTL)),
		proofWindow:  core.Window(ramphttpsig.ClockWindow(cfg.Clock, cfg.PoPTTL)),
		homeBase:     clonedTransport(),
		guardedBase:  clonedTransport(),
		timeout:      cfg.Timeout,
		fetchTimeout: cfg.FetchTimeout,
		maxBytes:     cfg.MaxBytes,
	}, nil
}

// withDefaults settles the fields this package must read a value for, so the
// rest of it does not restate the defaulting per consumer.
//
// It is not every optional field, and the ones it leaves alone are left alone on
// purpose. Endpoints has no default to settle: New requires it, because the
// resolver belongs to the composition root that can show the whole outbound
// posture and hand the same instance to both legs. FetchTimeout and MaxBytes are
// passed on as given, because their defaults belong to the code that consumes
// them — the SDK's own, in both cases — and a second default here would be a copy
// that can disagree.
func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.SignatureTTL <= 0 {
		c.SignatureTTL = DefaultSignatureTTL
	}
	if c.PoPTTL <= 0 {
		c.PoPTTL = DefaultPoPTTL
	}
	if c.Clock == nil {
		c.Clock = clock.System{}
	}
	return c
}

// clonedTransport returns a transport carrying the standard library's tuned
// pool settings. Cloned rather than shared with http.DefaultTransport so this
// package's connection reuse is its own, and so the guarded leg's transport can
// never be the one an unrelated caller reconfigured.
func clonedTransport() *http.Transport {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return &http.Transport{}
}
