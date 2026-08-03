package transport

import (
	"context"
	"errors"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
)

// brokerServiceDomain stamps the ErrorDetail.Domain on every broker resolve
// fault so a client can attribute the failure to this service.
const brokerServiceDomain = "ramp.v1.BrokerService"

// BrokerConnectHandler adapts the resolve business core to the generated
// rampconnect.BrokerServiceHandler interface. It is the SOLE transport over the
// resolve.Service business core (ADR-019 — the bespoke POST
// /broker/v1/resolve route was removed): it decodes via Connect, runs the
// validate → authorize → resolve pipeline, and renders toDiscoveryResponse. Domain
// faults map to connect.Code via broker.ToConnect and carry a typed ErrorDetail
// (resolveFaultError).
type BrokerConnectHandler struct {
	rampconnect.UnimplementedBrokerServiceHandler
	h *resolve.Service
}

// NewBrokerConnectHandler wires the Connect adapter over the shared resolver.
func NewBrokerConnectHandler(h *resolve.Service) *BrokerConnectHandler {
	return &BrokerConnectHandler{h: h}
}

// Resolve handles ramp.v1.BrokerService/Resolve. A licensed result returns OK
// with the delivery fields populated on DiscoveryResponse (retrieval_endpoint
// present); a request that ran but yielded nothing licensable returns OK with
// the typed absence_reason set (ADR-019 §2 — "no result is a successful
// answer"). Malformed requests, auth failures, and internal faults are non-OK
// transport errors carrying a typed ErrorDetail (resolveFaultError).
func (b *BrokerConnectHandler) Resolve(
	ctx context.Context,
	creq *connect.Request[rampv1.DiscoveryRequest],
) (*connect.Response[rampv1.DiscoveryResponse], error) {
	req := rampRequestToInput(creq.Msg)
	// The name says it mutates: it rewrites req.AgentID to the canonical host, so
	// the identity the authorization gate compares is the same string the core
	// keys its budget, audit row and forwarded requester.id on.
	if verr := validateAndCanonicalizeRequest(&req); verr != nil {
		return nil, resolveFaultError(verr)
	}
	if aerr := authorizeAgentSelfAct(ctx, req.AgentID); aerr != nil {
		return nil, resolveFaultError(aerr)
	}
	resp, rerr := b.h.Resolve(ctx, reqctx.RequestID(ctx), req)
	if rerr != nil {
		return nil, resolveFaultError(rerr)
	}
	return connect.NewResponse(toDiscoveryResponse(resp)), nil
}

// resolveFaultError maps a resolve fault to its Connect transport error and
// attaches a typed proto ErrorDetail. Broker resolve faults are the generic
// transport class (INVALID_ARGUMENT / UNAUTHENTICATED / PERMISSION_DENIED /
// UNAVAILABLE / INTERNAL), so the detail carries Message + Domain with NO reason
// oneof — per the proto ErrorDetail comment, the typed reason is absent for
// generic transport-class failures that carry no domain-specific reason. Mirrors
// the Exchange's executeTxError (exchange_error_detail.go), the canonical
// ADR-019 pattern: the machine-readable fault travels as a typed detail, never
// as a server-side string the client must parse. Message is non-authoritative
// developer text.
func resolveFaultError(err error) error {
	cerr := broker.ToConnect(err)
	var ce *connect.Error
	if !errors.As(cerr, &ce) {
		return cerr
	}
	return connectserver.AttachDetail(ce, brokerDetail(err))
}
