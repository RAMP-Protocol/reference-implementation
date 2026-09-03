// Package relay owns the security pipeline shared by the broker's agent-signed
// relay routes: SSRF admission against the Exchange
// registry, the SDK sig1 boundary verify, the relay-scoped replay guard, and
// the structured relay audit. It mirrors the Exchange's thin-adapter→service
// exemplar (and the broker's own internal/resolve): the transport layer keeps
// only ServeHTTP adapters, per-route routing input, and every write sink; this
// package receives NO http.ResponseWriter and reports rejections as typed
// *broker.Error values the adapter maps to the wire.
//
// Both relay routes — POST /broker/v1/exchange/execute (ExecuteTransaction)
// and POST /broker/v1/exchange/discover (known-URL DiscoverResources) —
// authenticate an agent-signed request (sig1) at the broker boundary as an
// open-proxy guard, SSRF-gate the target to a registered Exchange, and reject
// sig1 replays before the per-route forward. The Exchange remains the sole
// authoritative verifier of the agent binding. The routes differ in how the
// target Exchange is chosen and in the @target-uri the agent signed; a
// Boundary supplies those per-route specifics.
package relay

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// Boundary is the per-route behavior the shared pipeline composes around: the
// @target-uri the agent signed sig1 against and the audit message key. The
// transport adapters implement it.
type Boundary interface {
	// BoundaryTargetURL returns the absolute @target-uri the agent signed sig1
	// against, used to reconstruct the exact signature base for the boundary
	// verify. Execute returns the broker's OWN relay route (the request as
	// received — the agent signs the broker route, not the Exchange, so it
	// stays topology-decoupled); discover returns the resolved Exchange
	// endpoint + its known-URL procedure path. The resolved endpoint is
	// supplied for routes that reconstruct against it (discover); routes that
	// verify as-received (execute) ignore it.
	BoundaryTargetURL(r *http.Request, endpoint string) (*url.URL, error)
	// AuditMessage is the broker-namespaced structured-log message key for
	// this route's relay outcomes.
	AuditMessage() string
}

// Core owns the security pipeline shared by every agent-signed relay route.
// resolver verifies the agent's sig1 (the SDK KeyResolver built from the
// broker's agent-key snapshot — boundary verify uses the same SDK verifier as
// the Exchange); exchanges is the SSRF allowlist (only registered Exchanges
// may be relayed to); clk feeds the RFC 9421 created/expires window; replay
// rejects a sig1 reused within its window. The relay routes are excluded from
// the httpsig middleware, so the per-signature replay check the signed
// surfaces get for free is applied here.
type Core struct {
	resolver  helpers.KeyResolver
	exchanges repo.ExchangeRepo
	clk       clock.Clock
	replay    replay.Store
}

// NewCore wires the shared pipeline; clk nil → system, replayStore nil →
// in-memory store.
func NewCore(
	resolver helpers.KeyResolver,
	exchanges repo.ExchangeRepo,
	clk clock.Clock,
	replayStore replay.Store,
) Core {
	if clk == nil {
		clk = clock.System{}
	}
	if replayStore == nil {
		replayStore = replay.NewMemoryStore(nil)
	}
	return Core{resolver: resolver, exchanges: exchanges, clk: clk, replay: replayStore}
}

// AdmitEndpoint enforces the SSRF allowlist for an already-resolved relay
// target: only relay to an Exchange the broker already trusts via its
// registry, so a caller cannot steer the broker's signed POST onto an
// arbitrary internal target (e.g. cloud metadata). Returns the typed rejection
// (auditing it) for the adapter to write.
func (c Core) AdmitEndpoint(ctx context.Context, b Boundary, endpoint string) *broker.Error {
	admission, err := c.EndpointAllowed(ctx, endpoint)
	if err != nil {
		// Audited like every other refusal. A registry read that failed is the
		// same class of fault the execute route records, and leaving it silent
		// here meant one fault had a trail on one route and none on the other.
		rerr := broker.Wrapf(broker.KindInternal, err, "exchange registry")
		c.Audit(ctx, b, AuditAction(rerr), endpoint, err)
		return rerr
	}
	return c.RefuseAdmission(ctx, b, admission, endpoint)
}

// Audit actions for a relay refusal. Every one begins with REJECTED_ so an
// operator filtering that prefix sees every refusal, and each stays searchable
// on its own.
const (
	// ActionRejectedEndpoint records an address the operator never authorized —
	// the shape an SSRF attempt takes. Reserved for exactly that.
	ActionRejectedEndpoint = "REJECTED_ENDPOINT"
	// ActionRejectedEndpointDown records a registered, trusted exchange whose
	// last probe failed. Kept apart from ActionRejectedEndpoint because filing a
	// routine outage there makes every restart read like an attack.
	ActionRejectedEndpointDown = "REJECTED_ENDPOINT_DOWN"
	// ActionRejectedUpstream records a fault reaching an exchange that the
	// registry is happy with — a DNS failure, a refused connection, a 500 from
	// its well-known. Nothing about it is a refusal by the broker.
	ActionRejectedUpstream = "REJECTED_UPSTREAM"
	// ActionRejectedInternal records a fault on the BROKER's side, such as a
	// registry read that failed. It says nothing about the exchange, and filing
	// it against the exchange would blame the wrong party.
	ActionRejectedInternal = "REJECTED_INTERNAL"
)

// AuditAction is the ONE place a refusal becomes an audit action. Every relay
// audit of a refusal routes through it, so a single state cannot be recorded as
// an outage on one route and as a rejection on the other.
//
// Deriving it from the error's Kind is what keeps that true. The Kind is already
// decided wherever the refusal is built, and the alternative — each call site
// naming an action by hand — is exactly how every routine outage on the execute
// route came to be filed under the attack-shaped record: one function turned a
// refusal into an action, and the audit calls beside it picked their own.
func AuditAction(err *broker.Error) string {
	if err == nil {
		return ActionRejectedEndpoint
	}
	switch err.Kind {
	case broker.KindUpstreamUnavailable:
		return ActionRejectedEndpointDown
	case broker.KindInternal:
		return ActionRejectedInternal
	case broker.KindUpstreamRejected:
		return ActionRejectedUpstream
	default:
		return ActionRejectedEndpoint
	}
}

// RefuseAdmission writes the audit record an admission owes and returns the
// typed rejection with it, or nil when the endpoint is live. Both relay routes
// classify here, and both route their action through AuditAction, so one state
// cannot audit as an outage on one route and as a rejection on the other.
func (c Core) RefuseAdmission(
	ctx context.Context, b Boundary, admission EndpointAdmission, endpoint string,
) *broker.Error {
	if admission == EndpointLive {
		return nil
	}
	rerr := UnregisteredEndpointError(endpoint)
	if admission == EndpointDown {
		rerr = DownEndpointError(endpoint)
	}
	c.Audit(ctx, b, AuditAction(rerr), endpoint, nil)
	return rerr
}

// UnregisteredEndpointError is the single source of the SSRF-gate
// registry-reject fault: a RESOLVED endpoint that is not in the broker's
// Exchange registry. It is shared by the discover admission and the batch
// per-group resolution so the two byte-identical rejects cannot drift (one
// message literal, jscpd-zero), and it rides the rejected endpoint as typed
// metadata under "resolved_endpoint" so the boundary stamps it onto
// ErrorDetail.metadata (ADR-019) rather than leaving it only in the
// non-authoritative Message string.
func UnregisteredEndpointError(endpoint string) *broker.Error {
	return broker.Newf(broker.KindInvalidArgument,
		"resolved endpoint %q is not a registered exchange", endpoint).
		WithMeta("resolved_endpoint", endpoint)
}

// DownEndpointError refuses a relay to an Exchange the registry knows and the
// operator still trusts, but whose last health probe failed. Separate from
// UnregisteredEndpointError because the two differ in what an agent should do
// next: an unregistered endpoint is refused identically on every retry, so it
// arrives as invalid-argument, while a down Exchange clears itself within one
// refresher interval. Saying invalid-argument here would tell an agent holding
// a valid signed offer that the offer is bad, and "not a registered exchange"
// would be false about an Exchange the registry lists. It rides the endpoint
// under "resolved_endpoint", the same field the unregistered refusal uses.
func DownEndpointError(endpoint string) *broker.Error {
	return broker.Newf(broker.KindUpstreamUnavailable,
		"exchange at %q is registered but its last health check failed", endpoint).
		WithMeta("resolved_endpoint", endpoint)
}

// EndpointAdmission is what EndpointAllowed learned about a resolved endpoint.
// Three states, because the caller owes a different answer to each.
type EndpointAdmission int

const (
	// EndpointUnregistered means no non-BLOCKED registry row carries this
	// endpoint — never registered, or trust withdrawn. Both settled, so the
	// refusal is final.
	EndpointUnregistered EndpointAdmission = iota
	// EndpointDown means a registry row carries this endpoint and the operator
	// still trusts it, but its last health probe failed. Transient.
	EndpointDown
	// EndpointLive means registered, trusted, and answering health probes.
	EndpointLive
)

// EndpointAllowed classifies a CALLER-SUPPLIED endpoint against the registry.
// The discover route is its caller: a known-URL query carries no signed
// Offer.exchange, so the target arrives in a header and the registry is the
// only thing bounding where the broker sends a signed POST.
//
// One ListUnblocked read answers both questions. The SSRF question is "is this
// an address a registered Exchange advertises" — a down Exchange still
// advertises the address it always did, so health is a separate answer, and
// keeping it separate is what lets the caller refuse a down Exchange retryably.
// BLOCKED rows never appear in the list, so a withdrawn Exchange is refused as
// unregistered, the correct final verdict for it.
//
// The comparison is exact and stays exact: an anchored-host match would admit
// every subdomain of a registered Exchange without it ever advertising one.
// What keeps that from stranding an Exchange that moved is the refresher
// writing each pass's resolved address back to the column. Both sides are
// canonical (repo.CanonicalEndpoint).
func (c Core) EndpointAllowed(ctx context.Context, endpoint string) (EndpointAdmission, error) {
	exchanges, err := c.exchanges.ListUnblocked(ctx)
	if err != nil {
		return EndpointUnregistered, err
	}
	// The BEST admission across every matching row, not the first match. Nothing
	// makes the endpoint column unique — only the domain is — and two registered
	// domains whose well-knowns advertise the same origin both carry it, which
	// the refresher actively brings about by converging each row's column on what
	// its well-known says. The list's ORDER BY does not break the tie between
	// them, so reading the first match let the same request be admitted on one
	// call and refused on the next with nothing in the registry having changed.
	//
	// Best-wins is also the older, correct rule: the question is whether ANY
	// registered exchange advertises this address, and one row being down says
	// nothing about another that is up. The constants are ordered
	// Unregistered < Down < Live, so max reads as "the most permissive answer any
	// matching row supports".
	best := EndpointUnregistered
	for _, ex := range exchanges {
		if ex.Endpoint == endpoint {
			best = max(best, admissionOf(ex))
		}
	}
	return best, nil
}

// admissionOf projects the registry's routability verdict onto what a relay
// caller is told — the ONE place the relay turns a row into an answer, so the
// two routes cannot answer differently about the same row.
//
// The projection is not the identity: a blocked row reaches the caller as
// UNREGISTERED. Both are settled refusals and an agent owes no distinction
// between them, and telling them apart would report whether an endpoint is in
// the registry at all — more than an unauthenticated caller needs to know.
func admissionOf(ex repo.Exchange) EndpointAdmission {
	switch ex.Admission() {
	case repo.AdmissionLive:
		return EndpointLive
	case repo.AdmissionDown:
		return EndpointDown
	default:
		return EndpointUnregistered
	}
}

// VerifyAndGuardReplay runs the ONE whole-body sig1 boundary verify + the ONE
// relay-scoped replay add shared by every relay route. endpoint is the
// resolved target for the discover path; for the batch execute branch (which
// verifies sig1 as-received and resolves no single endpoint) it is "" and
// serves only the audit context. Returns the typed rejection (auditing it) for
// the adapter to write.
func (c Core) VerifyAndGuardReplay(
	b Boundary, r *http.Request, endpoint string, body []byte,
) *broker.Error {
	ctx := r.Context()
	// Auth (open-proxy guard): verify the agent's sig1 at the broker boundary
	// before relaying. Defense-in-depth — the broker must not act as an open
	// signing proxy that stamps sig2 onto unauthenticated requests. Uses the
	// SDK verifier so the boundary check matches the Exchange's authoritative
	// verify.
	verified, err := c.verifyAgentSignature(b, r, endpoint, body)
	if err != nil {
		c.Audit(ctx, b, "REJECTED_AUTHZ", endpoint, err)
		return broker.Wrapf(broker.KindUnauthenticated, err,
			"agent signature verification failed")
	}

	// Replay guard: recorded only after sig1 verifies, so an unverified caller
	// cannot poison the store.
	seen, rerr := c.replay.SeenOrAdd(ctx, verified.KeyID, verified.Signature, replay.ReplayTTL)
	if rerr != nil {
		return broker.Wrapf(broker.KindInternal, rerr, "replay store")
	}
	if seen {
		c.Audit(ctx, b, "REJECTED_REPLAY", endpoint, nil)
		return broker.Newf(broker.KindUnauthenticated,
			"agent signature already used (replay)")
	}
	return nil
}

// verifyAgentSignature rebuilds the @target-uri the agent signed sig1 against
// (per-route, via b.BoundaryTargetURL) and verifies sig1 against the broker's
// agent-key resolver using the SDK verifier — the same rules the Exchange
// applies. Execute's agent signs the broker relay route (verified as
// received); discover's agent signs the Exchange URL (reconstructed). Either
// way the broker produces a byte-identical signature base.
func (c Core) verifyAgentSignature(
	b Boundary, r *http.Request, endpoint string, body []byte,
) (*helpers.VerifiedRequest, error) {
	target, err := b.BoundaryTargetURL(r, endpoint)
	if err != nil {
		return nil, err
	}
	clone := r.Clone(r.Context())
	clone.URL = target
	clone.Host = target.Host
	clone.Body = io.NopCloser(bytes.NewReader(body))
	// The resolver needs the signed Signature-Agent directory: after the WBA split
	// the RFC 9421 keyid is only a thumbprint, so a never-seen agent's key is
	// fetched from the directory named in its (covered) header. Nothing is seeded
	// here — VerifyRequestResolved reads that header off the request itself and
	// puts it in the context before calling the resolver, including unwrapping the
	// quoted structured-field form a conformant signer sends. A value seeded here
	// would be overwritten on every path. Use the returned
	// VerifiedRequest.SignatureAgent if the directory is wanted after the fact.
	return helpers.VerifyRequestResolved(
		clone.Context(), clone, body, c.resolver,
		helpers.VerifyOptions{Now: c.clk.Now()},
	)
}

// Audit emits a structured relay outcome to the request-scoped logger so the
// security-critical relay path is observable on both accept and rejection. The
// agent's verified key id is intentionally not logged; outcome + endpoint are
// sufficient to trace a rejection without recording caller material.
func (c Core) Audit(ctx context.Context, b Boundary, outcome, endpoint string, err error) {
	logger := reqctx.FromContext(ctx)
	if err != nil {
		logger.WarnContext(ctx, b.AuditMessage(),
			"outcome", outcome, "endpoint", endpoint, "err", err.Error())
		return
	}
	logger.InfoContext(ctx, b.AuditMessage(), "outcome", outcome, "endpoint", endpoint)
}
