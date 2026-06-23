package service

import (
	"context"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// denyIfReportingOverdue refuses an ExecuteTransaction when the calling agent
// has any PENDING reporting obligation whose deadline has already elapsed for
// this tenant. ListOutstanding filters state='PENDING' AND deadline<NOW()
// server-side, so a non-empty result means the agent is behind on usage
// reports and is blocked until it catches up. This binary "any overdue" rule
// is stricter than — and conformant with — the protocol's optional
// (>20% overdue-rate) threshold. Runs after authorization and before fund
// reservation so a blocked agent reserves no funds.
func (s *ExchangeService) denyIfReportingOverdue(
	ctx context.Context, caller Caller, tenant *repo.Tenant, agentID string,
) *exchange.Error {
	outstanding, err := s.obligations.ListOutstanding(ctx, tenant.ID, agentID)
	if err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "list outstanding obligations")
	}
	if len(outstanding) == 0 {
		return nil
	}
	oerr := exchange.Newf(exchange.KindFailedPrecondition,
		"reporting overdue: %d obligation(s) past deadline", len(outstanding))
	s.logOutcome(ctx, "execute_transaction", "REJECTED_REPORTING_OVERDUE", caller, tenant, agentID, "", oerr)
	return oerr
}
