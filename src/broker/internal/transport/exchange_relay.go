// Package transport — Exchange relay handler for agent-originated ExecuteTransaction.
//
// Per RAMP-56, the broker relays (does not author) agent-signed ExecuteTransaction
// requests. The agent originates and signs the request; the broker preserves sig1
// and appends its relay signature (sig2) via multi-label RFC 9421 signing; the
// Exchange verifies both signatures and binds the delivery URL to the agent's key.
package transport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// headerExchangeEndpoint names the caller-supplied header carrying the target
// Exchange endpoint. Every other X-RAMP-* header in the codebase is a named
// constant; this keeps the relay's producer/consumer in sync.
const headerExchangeEndpoint = "X-RAMP-Exchange-Endpoint"

// ExchangeRelayHandler relays agent-originated ExecuteTransaction requests to
// the Exchange. It verifies the agent's sig1 at the broker boundary, restricts
// the relay target to a registered Exchange, preserves sig1, and lets the
// broker's signing transport append sig2 (multi-label signing). The Exchange
// verifies both signatures and binds the response to the agent's proven key.
type ExchangeRelayHandler struct {
	exchange  xclient.ExchangeCaller
	resolver  httpsig.KeyResolver
	exchanges repo.ExchangeRepo
	clk       clock.Clock
	replay    httpsig.ReplayStore
}

// NewExchangeRelayHandler wires the relay handler. resolver verifies the agent's
// sig1; exchanges is the SSRF allowlist (only registered Exchanges may be
// relayed to); clk feeds the RFC 9421 created/expires window (nil → system);
// replay rejects a sig1 reused within its window (nil → in-memory store). The
// relay endpoint is excluded from the httpsig middleware, so the per-signature
// replay check the signed surfaces get for free must be applied here (SEC-01).
func NewExchangeRelayHandler(
	exchange xclient.ExchangeCaller,
	resolver httpsig.KeyResolver,
	exchanges repo.ExchangeRepo,
	clk clock.Clock,
	replay httpsig.ReplayStore,
) *ExchangeRelayHandler {
	if clk == nil {
		clk = clock.System{}
	}
	if replay == nil {
		replay = httpsig.NewMemoryReplayStore(nil)
	}
	return &ExchangeRelayHandler{
		exchange:  exchange,
		resolver:  resolver,
		exchanges: exchanges,
		clk:       clk,
		replay:    replay,
	}
}

// ServeHTTP handles POST /broker/v1/exchange/execute.
//
// The agent includes the target Exchange endpoint in the X-RAMP-Exchange-Endpoint
// header and signs the TransactionRequest (sig1). The broker authenticates sig1,
// confirms the endpoint is a registered Exchange, then forwards the agent-signed
// request verbatim, appending its relay signature via the signing transport.
func (h *ExchangeRelayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestIDFrom(ctx)

	// Canonicalize the agent-supplied endpoint exactly once (MED-01). Every
	// downstream consumer — the SSRF allowlist, the sig1 @target-uri base, and
	// the forwarded URL — uses this single normalized value, so they are
	// byte-identical by construction. Registered endpoints are normalized the
	// same way on store (repo.UpsertFromBootstrap), so discovery hands the agent
	// the already-clean form it signs against. A bare "/" trims to "" → rejected.
	endpoint := strings.TrimRight(r.Header.Get(headerExchangeEndpoint), "/")
	if endpoint == "" {
		writeProtoError(w, requestID, broker.Newf(broker.KindInvalidArgument,
			headerExchangeEndpoint+" header required"))
		return
	}

	// SSRF guard (RAMP-56 / HIGH-02): only relay to an Exchange the broker
	// already trusts via its registry, so a caller cannot steer the broker's
	// signed POST onto an arbitrary internal target (e.g. cloud metadata).
	allowed, err := h.endpointAllowed(ctx, endpoint)
	if err != nil {
		writeProtoError(w, requestID, broker.Wrapf(broker.KindInternal, err, "exchange registry"))
		return
	}
	if !allowed {
		h.audit(ctx, "REJECTED_ENDPOINT", endpoint, nil)
		writeProtoError(w, requestID, broker.Newf(broker.KindInvalidArgument,
			"%s %q is not a registered exchange", headerExchangeEndpoint, endpoint))
		return
	}

	// Read the raw body bytes exactly as the agent signed them. We MUST NOT
	// unmarshal and re-marshal because that would change the bytes and invalidate
	// the agent's signature (Content-Digest binding). The read is bounded by
	// maxAgentBodyBytes: this endpoint is pre-auth by design (sig1 is verified
	// below, not at the middleware gate), so without the limit an unauthenticated
	// caller could force the broker to buffer an arbitrarily large body (DoS).
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBodyBytes))
	_ = r.Body.Close()
	if err != nil {
		writeProtoError(w, requestID, broker.Wrapf(broker.KindInvalidArgument, err, "read body"))
		return
	}

	// Auth (RAMP-56 / CRIT-01): verify the agent's sig1 at the broker boundary
	// before relaying. Defense-in-depth — the broker must not act as an open
	// signing proxy that stamps sig2 onto unauthenticated requests.
	verified, err := h.verifyAgentSignature(r, endpoint, body)
	if err != nil {
		h.audit(ctx, "REJECTED_AUTHZ", endpoint, err)
		writeProtoError(w, requestID, broker.Wrapf(broker.KindUnauthenticated, err,
			"agent signature verification failed"))
		return
	}

	// Replay guard (SEC-01): this endpoint is excluded from the httpsig
	// middleware, so the (keyid, signature) uniqueness check the signed surfaces
	// enforce must be applied here. A captured valid relay request would
	// otherwise be replayable within the sig1 expires window. Recorded only
	// after sig1 verifies, so an unverified caller cannot poison the store.
	if seen, rerr := h.replay.SeenOrAdd(ctx, verified.KeyID, verified.Signature, httpsig.ReplayTTL); rerr != nil {
		writeProtoError(w, requestID, broker.Wrapf(broker.KindInternal, rerr, "replay store"))
		return
	} else if seen {
		h.audit(ctx, "REJECTED_REPLAY", endpoint, nil)
		writeProtoError(w, requestID, broker.Newf(broker.KindUnauthenticated,
			"agent signature already used (replay)"))
		return
	}

	// Validate it's a well-formed TransactionRequest (but don't re-marshal it).
	var txReq rampv1.TransactionRequest
	if err := protojson.Unmarshal(body, &txReq); err != nil {
		writeProtoError(w, requestID, broker.Wrapf(broker.KindInvalidArgument, err,
			"parse TransactionRequest"))
		return
	}

	// Preserve the agent's sig1 + Content-Digest so the signing transport can
	// append sig2 (multi-label signing on the same body).
	ctx = xclient.WithIncomingSignatures(
		ctx,
		r.Header.Get("Signature-Input"),
		r.Header.Get("Signature"),
		r.Header.Get("Content-Digest"),
	)

	resp, err := h.exchange.ExecuteTransactionRaw(ctx, endpoint, body)
	if err != nil {
		h.audit(ctx, "RELAY_UPSTREAM_ERROR", endpoint, err)
		writeProtoError(w, requestID, err)
		return
	}
	h.audit(ctx, "VALIDATED", endpoint, nil)
	writeProtoJSON(w, http.StatusOK, resp)
}

// auditMessage is the structured-log message key for relay outcomes. It mirrors
// the Exchange's "exchange.<op>" convention (MED-04) — dotted, but broker-
// namespaced so relay lines don't collide with the Exchange's own "exchange.*"
// entries in a shared aggregator. The success token "VALIDATED" and the
// REJECTED_* tokens match the Exchange vocabulary so accept/reject can be
// grep-correlated across the two audit surfaces.
const auditMessage = "broker.exchange_relay"

// audit emits a structured relay outcome to the request-scoped logger so the
// security-critical relay path is observable on both accept and rejection. The
// agent's verified key id is intentionally not logged here; outcome + endpoint
// are sufficient to trace a rejection without recording caller material.
func (h *ExchangeRelayHandler) audit(ctx context.Context, outcome, endpoint string, err error) {
	logger := reqctx.FromContext(ctx)
	if err != nil {
		logger.WarnContext(ctx, auditMessage,
			"outcome", outcome, "endpoint", endpoint, "err", err.Error())
		return
	}
	logger.InfoContext(ctx, auditMessage, "outcome", outcome, "endpoint", endpoint)
}

// endpointAllowed reports whether endpoint matches a healthy, registered
// Exchange. Matching against the same registry discovery uses (repo.List)
// guarantees the guard never rejects an endpoint the broker itself advertised.
func (h *ExchangeRelayHandler) endpointAllowed(ctx context.Context, endpoint string) (bool, error) {
	exchanges, err := h.exchanges.List(ctx)
	if err != nil {
		return false, err
	}
	// Both sides are already canonical — endpoint is normalized once in
	// ServeHTTP, stored endpoints on store (repo.UpsertFromBootstrap) — so a
	// direct comparison suffices (MED-01).
	for _, ex := range exchanges {
		if ex.Endpoint == endpoint {
			return true, nil
		}
	}
	return false, nil
}

// verifyAgentSignature rebuilds the agent's intended @target-uri (the Exchange
// execute endpoint) and verifies sig1 against the broker's key registry using
// the same RFC 9421 rules the Exchange applies. The agent signs against the
// Exchange URL, not this relay path, so the broker reconstructs that target to
// produce a byte-identical signature base.
func (h *ExchangeRelayHandler) verifyAgentSignature(
	r *http.Request, endpoint string, body []byte,
) (*httpsig.VerifiedRequest, error) {
	// endpoint is already canonical (normalized once in ServeHTTP), so this
	// reconstructs the exact @target-uri the agent signed (MED-01).
	target, err := url.Parse(endpoint + rampv1connect.ExchangeServiceExecuteTransactionProcedure)
	if err != nil {
		return nil, err
	}
	clone := r.Clone(r.Context())
	clone.URL = target
	clone.Host = target.Host
	clone.Body = io.NopCloser(bytes.NewReader(body))
	return httpsig.VerifyRequest(clone, h.resolver, httpsig.VerifyRequestOptions{Clk: h.clk})
}
