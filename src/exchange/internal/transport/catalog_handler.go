package transport

import (
	"context"

	connect "connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// CatalogHandler adapts CatalogService to the generated connect interface.
type CatalogHandler struct {
	rampconnect.UnimplementedCatalogServiceHandler
	svc *service.CatalogService
}

// NewCatalogHandler wires the handler.
func NewCatalogHandler(svc *service.CatalogService) *CatalogHandler {
	return &CatalogHandler{svc: svc}
}

// PushResources handles ramp.v1.CatalogService/PushResources.
func (h *CatalogHandler) PushResources(
	ctx context.Context,
	req *connect.Request[rampv1.PushResourcesRequest],
) (*connect.Response[rampv1.PushResourcesResponse], error) {
	out, err := h.svc.PushResources(ctx, req.Msg)
	if err != nil {
		return nil, exchange.ToConnect(err)
	}
	return connect.NewResponse(out), nil
}
