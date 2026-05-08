package transport

import (
	"context"

	connect "connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// ExchangeHandler adapts MarketplaceService to the generated
// rampconnect.ExchangeServiceHandler interface.
type ExchangeHandler struct {
	rampconnect.UnimplementedExchangeServiceHandler
	svc *service.MarketplaceService
}

// NewExchangeHandler wires the handler.
func NewExchangeHandler(svc *service.MarketplaceService) *ExchangeHandler {
	return &ExchangeHandler{svc: svc}
}

// DiscoverResources handles ramp.v1.ExchangeService/DiscoverResources.
func (h *ExchangeHandler) DiscoverResources(
	ctx context.Context,
	req *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error) {
	out, err := h.svc.DiscoverResources(ctx, req.Msg)
	if err != nil {
		return nil, exchange.ToConnect(err)
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
		return nil, exchange.ToConnect(err)
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
		return nil, exchange.ToConnect(err)
	}
	return connect.NewResponse(out), nil
}
