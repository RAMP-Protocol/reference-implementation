// Package transport — Exchange relay adapter for agent-originated
// ExecuteTransaction (re-package model). The execute-route wire
// specifics (routing input, write sinks) live here; the shared security
// pipeline and the batch fan-out live in the broker's relay service layer
// (src/broker/internal/relay), mirroring the thin-adapter→service exemplar.
package transport

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	relaysvc "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/relay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// auditMessageExecute is the structured-log message key for execute-relay
// outcomes. It mirrors the Exchange's "exchange.<op>" convention but is
// broker-namespaced so relay lines don't collide with the Exchange's own
// "exchange.*" entries in a shared aggregator.
const auditMessageExecute = "broker.exchange_relay"

// headerExchangeEndpoint names the caller-supplied header carrying the target
// Exchange endpoint. Every other X-RAMP-* header in the codebase is a named
// constant; this keeps the relay's producer/consumer in sync. For execute it is
// a one-release fallback (DEC#1) behind the signed Offer.exchange; for discover
// it is the primary routing input (no offer exists on a discovery query).
const headerExchangeEndpoint = "X-RAMP-Exchange-Endpoint"

// ExchangeRelayHandler relays agent-originated ExecuteTransaction requests to
// the Exchange under the RE-PACKAGE model. The agent transport-signs
// sig1 over the broker relay route (NOT the Exchange URL) and detached-signs
// the offer (body AgentAcceptance). The relay service verifies that sig1 as an
// open-proxy guard, resolves the Exchange endpoint from the signed
// Offer.exchange via well-known (registry = trust allowlist only), then
// RE-PACKAGES a fresh broker→Exchange ExecuteTransaction signed with the
// broker key alone. The Exchange binds the agent SOLELY via the body
// AgentAcceptance against the agent's registered key — so the agent never
// needs to know the Exchange's topology. This adapter owns the wire only: the
// bounded body read, the load-bearing admission ordering, and every write.
type ExchangeRelayHandler struct {
	core  relaysvc.Core
	batch relaysvc.Batch
}

// NewExchangeRelayHandler wires the relay adapter over the relay service.
// resolver verifies the agent's sig1 over the broker route (the SDK
// KeyResolver built from the broker's agent-key snapshot); endpoints resolves
// the signed Offer.exchange to the Exchange's self-advertised endpoint via
// /.well-known/ramp.json; exchanges is the trust allowlist (the resolved
// endpoint must match a registered Exchange — SSRF gate); clk feeds the RFC
// 9421 created/expires window (nil → system); replay rejects a sig1 reused
// within its window (nil → in-memory store). The relay route is excluded from
// the httpsig middleware, so the per-signature replay check the signed
// surfaces get for free is applied by the relay service.
func NewExchangeRelayHandler(
	exchange xclient.ExchangeCaller,
	resolver helpers.KeyResolver,
	endpoints relaysvc.EndpointResolver,
	exchanges repo.ExchangeRepo,
	clk clock.Clock,
	replay replay.Store,
) *ExchangeRelayHandler {
	core := relaysvc.NewCore(resolver, exchanges, clk, replay)
	return &ExchangeRelayHandler{
		core:  core,
		batch: relaysvc.NewBatch(core, endpoints, exchange),
	}
}

// ServeHTTP handles POST /broker/v1/exchange/execute.
//
// Execute is ALWAYS batch: a single offer is the degenerate 1-element items[]
// request. There is no single-offer dispatch path — the body is read once
// under the pre-auth bound and handed to the batch fan-out (per-group trust +
// well-known + SSRF, ONE whole-body sig1 verify, fan out, merge; N=1 handled).
// serveBatch rejects an empty items[] (min 1).
func (h *ExchangeRelayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := readAgentBody(w, r, reqctx.RequestID(r.Context()))
	if !ok {
		return
	}
	h.serveBatch(w, r, body)
}

// AuditMessage implements relay.Boundary.
func (h *ExchangeRelayHandler) AuditMessage() string { return auditMessageExecute }

// BoundaryTargetURL returns the broker relay route URL the agent signed sig1
// against — reconstructed from the request as received. Unlike the discover
// relay (where the agent signs the Exchange's known-URL procedure), the
// execute agent is topology-decoupled: it signs only the broker route it posts
// to, so the relay service verifies the signature as received, with no
// Exchange-URL reconstruction.
func (h *ExchangeRelayHandler) BoundaryTargetURL(r *http.Request, _ string) (*url.URL, error) {
	return requestTargetURL(r), nil
}

// requestTargetURL reconstructs the absolute @target-uri of an inbound request
// (scheme://host/path?query). Scheme prefers URL.Scheme when set — populated by
// runhttp.TrustProxyHeaders from X-Forwarded-Proto, wired only under the
// deployment's explicit proxy-trust opt-in — then TLS, else http. The header is
// deliberately NOT read here: on a directly-exposed broker a caller-supplied
// X-Forwarded-Proto must not pick the scheme its signature is verified against.
func requestTargetURL(r *http.Request) *url.URL {
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	return &url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
}

// readAgentBody reads the raw body exactly as the agent signed it, under the
// pre-auth size bound (DoS — see maxAgentBodyBytes). We MUST NOT unmarshal and
// re-marshal: that would change the bytes and invalidate the agent's
// Content-Digest binding (and sig1). Shared by both relay adapters so they
// honour the identical bound. Returns ok=false (having written the error) on a
// read error.
func readAgentBody(w http.ResponseWriter, r *http.Request, requestID string) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBodyBytes))
	_ = r.Body.Close()
	if err != nil {
		writeBrokerError(w, requestID, broker.Wrapf(broker.KindInvalidArgument, err, "read body"))
		return nil, false
	}
	return body, true
}

// seatRelayContext returns a ctx carrying the agent's sig1 + Content-Digest (so
// the signing transport can append sig2 on the same body) and, when present, the
// agent's Authorization (bearer/entitlement-biscuit) so sig2 covers identical
// bytes. Used by the verbatim discover relay; the execute relay
// re-packages and does not seat the agent's signature.
func seatRelayContext(r *http.Request) context.Context {
	ctx := xclient.WithIncomingSignatures(
		r.Context(),
		r.Header.Get("Signature-Input"),
		r.Header.Get("Signature"),
		r.Header.Get("Content-Digest"),
		// The agent's Signature-Agent is a covered component of sig1 after the WBA
		// split; forward it verbatim so sig1 still verifies at the Exchange.
		r.Header.Get(helpers.SignatureAgentHeader),
	)
	if authz := r.Header.Get("Authorization"); authz != "" {
		ctx = xclient.WithIncomingAuthorization(ctx, authz)
	}
	return ctx
}
