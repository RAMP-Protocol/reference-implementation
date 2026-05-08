package transport

import (
	"context"
	"log/slog"
	"sync"

	"connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// TransactionRouteStore maps transaction_id → marketplace endpoint so the
// Broker can relay UsageReport calls back to the owning Exchange.
type TransactionRouteStore struct {
	mu        sync.RWMutex
	endpoints map[string]string
}

// NewTransactionRouteStore constructs an empty store.
func NewTransactionRouteStore() *TransactionRouteStore {
	return &TransactionRouteStore{endpoints: make(map[string]string)}
}

// Put records a transaction → endpoint mapping.
func (s *TransactionRouteStore) Put(transactionID, endpoint string) {
	s.mu.Lock()
	s.endpoints[transactionID] = endpoint
	s.mu.Unlock()
}

// Get returns the endpoint for a transaction_id or ("", false).
func (s *TransactionRouteStore) Get(transactionID string) (string, bool) {
	s.mu.RLock()
	e, ok := s.endpoints[transactionID]
	s.mu.RUnlock()
	return e, ok
}

// ReportUsageHandler implements rampv1connect.ExchangeServiceHandler for
// ReportUsage only. Other RPCs are rejected with Unimplemented — the Broker
// is a relay, not a full Exchange.
type ReportUsageHandler struct {
	// Unimplemented satisfies the full handler interface; we override ReportUsage.
	fallback unimplementedExchange

	routes      *TransactionRouteStore
	marketplace repo.MarketplaceRepo
	exchange    xclient.ExchangeCaller
	logger      *slog.Logger
}

// NewReportUsageHandler constructs the relay handler.
func NewReportUsageHandler(
	routes *TransactionRouteStore,
	marketplaces repo.MarketplaceRepo,
	exchange xclient.ExchangeCaller,
	logger *slog.Logger,
) *ReportUsageHandler {
	return &ReportUsageHandler{
		routes:      routes,
		marketplace: marketplaces,
		exchange:    exchange,
		logger:      logger,
	}
}

// ReportUsage routes the incoming report to the Exchange that owns the tx.
func (h *ReportUsageHandler) ReportUsage(
	ctx context.Context, req *connect.Request[rampv1.UsageReport],
) (*connect.Response[rampv1.UsageReportResponse], error) {
	txID := req.Msg.GetTransactionId()
	if txID == "" {
		return nil, broker.ToConnect(broker.Newf(broker.KindInvalidArgument, "transaction_id is required"))
	}
	endpoint, ok := h.routes.Get(txID)
	if !ok {
		endpoint = h.lookupByMarketplaceField(ctx, req.Msg.GetMarketplace())
	}
	if endpoint == "" {
		return nil, broker.ToConnect(broker.Newf(broker.KindNotFound,
			"no route for transaction %s", txID))
	}
	resp, err := h.exchange.ReportUsage(ctx, endpoint, req.Msg)
	if err != nil {
		return nil, broker.ToConnect(err)
	}
	return connect.NewResponse(resp), nil
}

func (h *ReportUsageHandler) lookupByMarketplaceField(ctx context.Context, marketplace string) string {
	if marketplace == "" {
		return ""
	}
	m, err := h.marketplace.GetByDomain(ctx, marketplace)
	if err != nil {
		h.logger.WarnContext(ctx, "route lookup failed", "marketplace", marketplace, "err", err)
		return ""
	}
	return m.Endpoint
}

// DiscoverResources is rejected — Broker does not expose Exchange discovery.
func (h *ReportUsageHandler) DiscoverResources(
	ctx context.Context, req *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error) {
	return h.fallback.DiscoverResources(ctx, req)
}

// ExecuteTransaction is rejected on the Broker.
func (h *ReportUsageHandler) ExecuteTransaction(
	ctx context.Context, req *connect.Request[rampv1.TransactionRequest],
) (*connect.Response[rampv1.TransactionResponse], error) {
	return h.fallback.ExecuteTransaction(ctx, req)
}

// DisputeTransaction is rejected on the Broker.
func (h *ReportUsageHandler) DisputeTransaction(
	ctx context.Context, req *connect.Request[rampv1.DisputeRequest],
) (*connect.Response[rampv1.DisputeResponse], error) {
	return h.fallback.DisputeTransaction(ctx, req)
}

// RequestDomainVerification is rejected on the Broker.
func (h *ReportUsageHandler) RequestDomainVerification(
	ctx context.Context, req *connect.Request[rampv1.DomainVerificationRequest],
) (*connect.Response[rampv1.DomainVerificationChallenge], error) {
	return h.fallback.RequestDomainVerification(ctx, req)
}

// ConfirmDomainVerification is rejected on the Broker.
func (h *ReportUsageHandler) ConfirmDomainVerification(
	ctx context.Context, req *connect.Request[rampv1.DomainVerificationConfirmation],
) (*connect.Response[rampv1.DomainVerificationResult], error) {
	return h.fallback.ConfirmDomainVerification(ctx, req)
}

// unimplementedExchange reuses generated "not implemented" errors.
type unimplementedExchange struct{}

func relayOnlyError() error {
	return connect.NewError(
		connect.CodeUnimplemented,
		broker.Newf(broker.KindInvalidArgument, "broker only relays ReportUsage"),
	)
}

func (unimplementedExchange) DiscoverResources(
	_ context.Context, _ *connect.Request[rampv1.ResourceQuery],
) (*connect.Response[rampv1.ResourceResponse], error) {
	return nil, relayOnlyError()
}

func (unimplementedExchange) ExecuteTransaction(
	_ context.Context, _ *connect.Request[rampv1.TransactionRequest],
) (*connect.Response[rampv1.TransactionResponse], error) {
	return nil, relayOnlyError()
}

func (unimplementedExchange) DisputeTransaction(
	_ context.Context, _ *connect.Request[rampv1.DisputeRequest],
) (*connect.Response[rampv1.DisputeResponse], error) {
	return nil, relayOnlyError()
}

func (unimplementedExchange) RequestDomainVerification(
	_ context.Context, _ *connect.Request[rampv1.DomainVerificationRequest],
) (*connect.Response[rampv1.DomainVerificationChallenge], error) {
	return nil, relayOnlyError()
}

func (unimplementedExchange) ConfirmDomainVerification(
	_ context.Context, _ *connect.Request[rampv1.DomainVerificationConfirmation],
) (*connect.Response[rampv1.DomainVerificationResult], error) {
	return nil, relayOnlyError()
}
