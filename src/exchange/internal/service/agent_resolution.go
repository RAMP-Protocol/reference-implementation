// Agent-id resolution for ExecuteTransaction.
//
// Pre-MR behavior lazy-registered unknown ids with a placeholder public_key so
// any wire-claimed requester.id could be persisted to transaction_log.agent_id.
// The caller-identity authz layer (resolveCaller / authorizeForAgent) now
// requires every accepted caller to be a registered agent or broker, so the
// lazy-upsert path is gone — an unknown requester.id is a hard NotFound. For
// the broker-relay flow the on-the-wire requester.id MUST already correspond
// to a registered AGENT (the broker cannot mint identities on the fly).

package service

import (
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// resolveAgentID returns the agent_id to attribute the transaction to. The
// id MUST exist in ramp.agents — unknown ids are rejected with NotFound so
// transaction_log.agent_id (FK to agents) is always satisfied. requester.id
// is guaranteed non-empty by validateTxRequest.
func (s *ExchangeService) resolveAgentID(
	ctx context.Context, req *rampv1.TransactionRequest,
) (string, error) {
	requesterID := req.GetRequester().GetId()
	if s.agents == nil {
		return requesterID, nil
	}
	if _, err := s.agents.ByID(ctx, requesterID); err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return "", exchange.Newf(exchange.KindNotFound,
				"agent %q not registered", requesterID)
		}
		return "", exchange.Wrap(exchange.KindInternal, err, "lookup agent")
	}
	return requesterID, nil
}
