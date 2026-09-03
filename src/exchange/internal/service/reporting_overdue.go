package service

import (
	"context"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// overdueRule is the Exchange's reporting-compliance policy: how far behind on
// usage reports an agent may fall before its next transaction is refused.
//
// It is a value rather than two constants read inline because per-provider
// thresholds are anticipated — a tenant-scoped rule sourced from
// tenants.reporting_policy would be a different value here and nothing else
// would move. For the same reason the rule reads repo.ObligationCounts, which
// reports every bucket and classifies none of them, rather than a query that
// has already decided what "overdue" means.
//
// Product policy, not protocol. Only the rate comes from the protocol, and only
// as a MAY: the wire reason DENIAL_REASON_REPORTING_OVERDUE is documented as
// "Requester has >20% overdue reports (MAY threshold)". The absolute cap, the
// denominator and the absence of an evaluation period are ours. The rate alone
// is unbounded in absolute terms — a high-volume agent could sit on hundreds of
// unreported obligations at 5% — and the cap is what stops that.
type overdueRule struct {
	// MaxOverdue refuses above this many unreported past-deadline obligations,
	// whatever the rate.
	MaxOverdue int64
	// RateDivisor states the rate ceiling as a reciprocal so the comparison is
	// integer arithmetic with no float rounding: 5 means "refuse above one in
	// five", which is the protocol's 20%.
	RateDivisor int64
}

// defaultOverdueRule holds the thresholds the type comment above describes: the
// protocol's 20% rate ceiling, and this Exchange's own absolute cap.
var defaultOverdueRule = overdueRule{MaxOverdue: 10, RateDivisor: 5}

// blocks reports whether an agent carrying this many unreported obligations out
// of this many due ones is refused its next transaction.
//
// Pure arithmetic over the two numbers the caller picked out of the counts, so
// the thresholds can be exercised without a database. overdue is a subset of
// due, so overdue > 0 implies due > 0 and there is no zero case to guard.
func (r overdueRule) blocks(overdue, due int64) bool {
	return overdue > r.MaxOverdue || overdue*r.RateDivisor > due
}

// denyIfReportingOverdue refuses an ExecuteTransaction when the calling agent is
// far enough behind on usage reports for this tenant, per overdueRule. Runs
// after authorization and before fund reservation, so a refused transaction
// reserves nothing.
//
// The refusal carries KindReportingOverdue, which maps to the wire reason
// DENIAL_REASON_REPORTING_OVERDUE. That is what keeps a multi-item request
// alive: the batch loop denies the affected items in-body and returns the rest,
// instead of aborting on an error it cannot classify.
//
// A counts read that fails returns KindInternal, which carries no wire reason
// and so still aborts the whole batch. The gate fails closed: an agent is never
// let through because the compliance read broke.
func (s *ExchangeService) denyIfReportingOverdue(
	ctx context.Context, caller Caller, tenant *repo.Tenant, agentID string,
) *exchange.Error {
	counts, err := s.obligations.CountByStateAndDueness(ctx, tenant.ID, agentID, s.clk.Now())
	if err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "count reporting obligations")
	}
	// Overdue is an obligation still PENDING whose deadline has passed, so one
	// that was reported never counts again — however late the report was. The
	// denominator is every obligation whose deadline has passed, over the whole
	// history, with no evaluation period and no minimum sample size. One overdue
	// out of one due is therefore 100% and blocks; the agent clears it by filing
	// the report, which is accepted whatever the time.
	overdue := counts.In(repo.ObligationStatePending, true)
	due := counts.PastDeadline()
	if !defaultOverdueRule.blocks(overdue, due) {
		return nil
	}
	// The message names the remedy, not just the condition, the way the two
	// account denials this kind is modelled on do.
	//
	// It reaches the operator's audit log, not the agent. Every error this
	// function returns is classified by batchDenialResult, which builds a
	// result item carrying offer_id and denial_reason and no free text, and
	// TransactionResultItem has no field a message could travel in. An agent
	// sees DENIAL_REASON_REPORTING_OVERDUE and nothing more. The text is here
	// for whoever reads the line below while an agent asks why its purchases
	// stopped, and it says what to tell them: a late report is accepted now, so
	// filing the missing reports clears the refusal.
	oerr := exchange.Newf(exchange.KindReportingOverdue,
		"reporting overdue: %d unreported, out of %d past their deadline: "+
			"file the missing usage reports, they are accepted however late they are",
		overdue, due)
	s.logOutcome(ctx, "execute_transaction", "REJECTED_REPORTING_OVERDUE", caller, tenant, agentID, "", oerr)
	return oerr
}
