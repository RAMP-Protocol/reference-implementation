package transport

import (
	"context"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// MaxRPCReadBytes caps what a single request can make an Exchange mount read.
// It is a coarse backstop against pathologically large bodies on ANY RPC: a
// valid request signature authenticates a caller, it does not license them to
// stream an unbounded body into the service. 1 MiB comfortably fits a real
// registration and normal RPC traffic (signed offers, transactions) while
// bounding the worst case. The Register RPC additionally applies a tighter,
// semantic bound on registration_data itself at the service layer — this is the
// outer wall, that is the inner one.
//
// It bounds two quantities on each mount, because a caller can exhaust the
// server through either: the raw HTTP body a verifier buffers before it knows
// who is calling, and the decompressed Connect message the handler decodes. On
// the ExchangeService mount both come from connectserver.WithMaxRequestBytes in
// ExchangeMountOptions; on the raw catalog mount the body bound is the capture
// in CatalogSignatureMiddleware and the message bound is connect.WithReadMaxBytes
// in CatalogMountOptions. The production server and the integration harness
// call the same two providers, so the two never drift.
const MaxRPCReadBytes = 1 << 20 // 1 MiB

// ExchangeHandler adapts ExchangeService to the generated
// rampconnect.ExchangeServiceHandler interface.
type ExchangeHandler struct {
	rampconnect.UnimplementedExchangeServiceHandler
	svc *service.ExchangeService
}

// NewExchangeHandler wires the handler.
func NewExchangeHandler(svc *service.ExchangeService) *ExchangeHandler {
	return &ExchangeHandler{svc: svc}
}

// DiscoverResources handles ramp.v1.ExchangeService/DiscoverResources.
func (h *ExchangeHandler) DiscoverResources(
	ctx context.Context,
	req *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error) {
	out, err := h.svc.DiscoverResources(ctx, req.Msg)
	if err != nil {
		return nil, genericFaultError(err)
	}
	return connect.NewResponse(out), nil
}

// ExecuteTransaction handles ramp.v1.ExchangeService/ExecuteTransaction.
func (h *ExchangeHandler) ExecuteTransaction(
	ctx context.Context,
	req *connect.Request[rampv1.TransactionRequest],
) (*connect.Response[rampv1.TransactionResponse], error) {
	out, err := h.svc.ExecuteTransaction(ctx, req.Msg)
	if err != nil {
		return nil, executeTxError(err, h.svc.ExchangeDomain())
	}
	return connect.NewResponse(out), nil
}

// Register handles ramp.v1.ExchangeService/Register, replacing the embedded
// Unimplemented default.
func (h *ExchangeHandler) Register(
	ctx context.Context,
	req *connect.Request[rampv1.RegisterRequest],
) (*connect.Response[rampv1.RegisterResponse], error) {
	// The peer address is passed explicitly because audit_log.source_addr is NOT
	// NULL and only the transport can see it — the same shape the admin RPCs use.
	out, err := h.svc.Register(ctx, req.Msg, req.Peer().Addr)
	if err != nil {
		return nil, registerError(err)
	}
	return connect.NewResponse(out), nil
}

// GetAccountStatus handles ramp.v1.ExchangeService/GetAccountStatus, replacing
// the embedded Unimplemented default.
func (h *ExchangeHandler) GetAccountStatus(
	ctx context.Context,
	req *connect.Request[rampv1.GetAccountStatusRequest],
) (*connect.Response[rampv1.GetAccountStatusResponse], error) {
	out, err := h.svc.GetAccountStatus(ctx, req.Msg)
	if err != nil {
		return nil, accountStatusError(err)
	}
	return connect.NewResponse(out), nil
}

// ReportUsage handles ramp.v1.ExchangeService/ReportUsage.
func (h *ExchangeHandler) ReportUsage(
	ctx context.Context,
	req *connect.Request[rampv1.UsageReport],
) (*connect.Response[rampv1.UsageReportResponse], error) {
	out, err := h.svc.ReportUsage(ctx, req.Msg)
	if err != nil {
		return nil, reportUsageError(err)
	}
	return connect.NewResponse(out), nil
}
