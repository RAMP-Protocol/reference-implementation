// Package transport — known-URL discover relay adapter for agent-originated
// DiscoverResources. The discovery counterpart of the execute relay:
// the agent signs a DiscoverResources request (sig1) and the broker relays it
// VERBATIM to the agent-chosen Exchange, chaining its sig2 — so the Exchange
// can attribute a known-URL lookup to the agent (per-agent rate-limit / audit /
// entitlement at discovery), consistent with the execute relay.
//
// The discover-route wire specifics (routing header, write sinks) live here;
// the shared security pipeline (SSRF admission, SDK sig1 boundary verify,
// relay-scoped replay guard, audit) lives in the relay service layer
// (src/broker/internal/relay).
package transport

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	relaysvc "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/relay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// auditMessageDiscover is the structured-log message key for discover-relay
// outcomes, broker-namespaced and distinct from the execute relay's so the two
// routes' lines don't collide in a shared aggregator.
const auditMessageDiscover = "broker.discover_relay"

// DiscoverRelayHandler relays agent-originated DiscoverResources (known-URL)
// requests to the Exchange. The relay service verifies the agent's sig1 at the
// broker boundary (with the SAME SDK verifier the Exchange uses) and restricts
// the relay target to a registered Exchange; this adapter preserves sig1 and
// lets the broker's signing transport append sig2 (multi-label signing). The
// Exchange verifies both signatures and attributes the lookup to the agent's
// proven key.
//
// Routing differs from the execute relay: a DiscoverResources query carries no
// Offer, so there is no signed Offer.exchange to route from. The agent chooses
// which Exchange to query for the known URL and names it via the
// X-RAMP-Exchange-Endpoint header (SSRF-gated against the registry); the agent
// signs sig1's @target-uri against that Exchange's discover URL.
type DiscoverRelayHandler struct {
	core     relaysvc.Core
	exchange xclient.ExchangeCaller
}

// NewDiscoverRelayHandler wires the discover relay adapter. Parameters mirror
// NewExchangeRelayHandler: resolver verifies the agent's sig1; exchanges is the
// SSRF allowlist; clk feeds the RFC 9421 window (nil → system); replay rejects
// a reused sig1 (nil → in-memory store). The route is excluded from the httpsig
// middleware, so the per-signature replay check is applied by the relay
// service.
func NewDiscoverRelayHandler(
	exchange xclient.ExchangeCaller,
	resolver helpers.KeyResolver,
	exchanges repo.ExchangeRepo,
	clk clock.Clock,
	replay replay.Store,
) *DiscoverRelayHandler {
	return &DiscoverRelayHandler{
		core:     relaysvc.NewCore(resolver, exchanges, clk, replay),
		exchange: exchange,
	}
}

// ServeHTTP handles POST /broker/v1/exchange/discover: bounded pre-auth read,
// per-route endpoint derivation, SSRF admission, sig1 boundary verify + replay
// guard, then the verbatim forward. The adapter owns every write; the relay
// service reports rejections as typed errors.
func (h *DiscoverRelayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := reqctx.RequestID(ctx)

	body, ok := readAgentBody(w, r, requestID)
	if !ok {
		return
	}
	endpoint, berr := h.resolveEndpoint(r)
	if berr != nil {
		writeBrokerError(w, requestID, berr)
		return
	}
	// Verify BEFORE admitting, so no caller learns anything about the registry
	// without first proving who it is. The admission answer distinguishes an
	// endpoint nobody registered from one that is registered and failing its
	// health check, and it says which in words. Answered pre-verification, that
	// lets anyone sort address guesses into registered and unregistered, and poll
	// a registered one for its outage windows. The projection onto the caller
	// hides the blocked-versus-unregistered split for exactly this reason; health
	// reports the same fact on a different axis.
	//
	// The swap costs nothing. The endpoint comes from the header and is already
	// resolved above, and BoundaryTargetURL rebuilds the signature base from that
	// same value, so verification never depended on the admission result. A
	// verified agent still gets the retryable-versus-settled distinction.
	if verr := h.core.VerifyAndGuardReplay(h, r, endpoint, body); verr != nil {
		writeBrokerError(w, requestID, verr)
		return
	}
	if aerr := h.core.AdmitEndpoint(ctx, h, endpoint); aerr != nil {
		writeBrokerError(w, requestID, aerr)
		return
	}
	h.forward(w, r, endpoint, body, requestID)
}

// BoundaryTargetURL reconstructs the Exchange known-URL discover procedure URL
// the agent signed sig1's @target-uri against. Unlike execute (where the agent
// signs the broker route), a known-URL discovery names a specific Exchange and
// the agent signs against that Exchange's discover URL, so the relay service
// rebuilds it from the resolved endpoint to produce a byte-identical signature
// base.
func (h *DiscoverRelayHandler) BoundaryTargetURL(_ *http.Request, endpoint string) (*url.URL, error) {
	return url.Parse(endpoint + rampv1connect.ExchangeServiceDiscoverResourcesProcedure)
}

// AuditMessage implements relay.Boundary.
func (h *DiscoverRelayHandler) AuditMessage() string { return auditMessageDiscover }

// resolveEndpoint derives the canonical Exchange discover endpoint from the
// X-RAMP-Exchange-Endpoint header — the agent's chosen target for the known-URL
// lookup. A DiscoverResources query has no Offer (and thus no signed
// Offer.exchange), so unlike the execute relay the header is the PRIMARY
// routing input, not a fallback. The resolved value is then SSRF-gated against
// the registry (Core.AdmitEndpoint), so an arbitrary header value cannot steer
// the broker's signed POST off-allowlist. A bare "/" trims to "" (rejected).
// The body is not parsed for routing; it is relayed verbatim.
func (h *DiscoverRelayHandler) resolveEndpoint(r *http.Request) (string, *broker.Error) {
	endpoint := strings.TrimRight(r.Header.Get(headerExchangeEndpoint), "/")
	if endpoint == "" {
		return "", broker.Newf(broker.KindInvalidArgument,
			headerExchangeEndpoint+" header required to route a known-URL discovery relay").
			WithMeta("field", headerExchangeEndpoint)
	}
	return endpoint, nil
}

// forward seats the agent's incoming signature headers for sig2 chaining,
// relays the verbatim bytes to the Exchange discover RPC, and writes the
// ResourceResponse. The EXACT signed bytes — not a re-marshal — are relayed.
func (h *DiscoverRelayHandler) forward(
	w http.ResponseWriter, r *http.Request, endpoint string, body []byte, requestID string,
) {
	ctx := seatRelayContext(r)
	resp, err := h.exchange.DiscoverResourcesRaw(ctx, endpoint, body)
	if err != nil {
		h.core.Audit(ctx, h, "RELAY_UPSTREAM_ERROR", endpoint, err)
		writeBrokerError(w, requestID, err)
		return
	}
	h.core.Audit(ctx, h, "VALIDATED", endpoint, nil)
	writeResourceResponse(w, requestID, resp)
}
