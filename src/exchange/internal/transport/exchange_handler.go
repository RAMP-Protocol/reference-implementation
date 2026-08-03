package transport

import (
	"context"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// MaxRPCReadBytes caps the size of a single request message the Exchange's
// Connect handlers will read from a caller (wired via connect.WithReadMaxBytes).
// It is a coarse backstop against pathologically large bodies on ANY RPC: a
// valid request signature authenticates a caller, it does not license them to
// stream an unbounded body into the service. 1 MiB comfortably fits a real
// registration and normal RPC traffic (signed offers, transactions) while
// bounding the worst case. The Register RPC additionally applies a tighter,
// semantic bound on registration_data itself at the service layer — this is the
// outer wall, that is the inner one. Wired identically in the production server
// (cmd/server/main.go) and the integration harness so the two never drift.
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
		return nil, executeTxError(err)
	}
	return connect.NewResponse(out), nil
}

// Register handles ramp.v1.ExchangeService/Register, replacing the embedded
// Unimplemented default.
func (h *ExchangeHandler) Register(
	ctx context.Context,
	req *connect.Request[rampv1.RegisterRequest],
) (*connect.Response[rampv1.RegisterResponse], error) {
	out, err := h.svc.Register(ctx, req.Msg)
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
