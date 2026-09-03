// ReportUsage and its helpers. Extracted from exchange.go to keep the
// service files under the 500-line per-file cap and to give the
// idempotency / authz / validation choreography a single home.

package service

import (
	"context"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// ReportUsage validates and records a usage report against the obligation
// created at ExecuteTransaction time. The four RAMP §3.2 #4 checks (required
// fields, quantity tolerance, billing_id, timestamp) run inside the same
// transaction as the persist so audit and state stay consistent. A report filed
// after its deadline is accepted like any other — see ValidateUsageReport for
// why the window is not a check. Whether the report is addressed to this
// Exchange is decided earlier and elsewhere, by the recipient interceptor on the
// Connect surface, so a report meant for somebody else never opens a transaction
// at all.
//
// Idempotency: UsageReport.id is the caller-supplied idempotency anchor. A
// replay of an ACCEPTED report returns the original
// UsageReportResponse.report_id without re-running validation. A retry under a
// key that was only ever rejected is validated afresh, because there is no
// accepted result to return and the caller is correcting its report rather than
// replaying one. Two different UsageReport.id values against the same obligation
// are rejected on the second call (the state guard on MarkValidationValidated
// fires).
//
// Authz: the verified httpsig keyID must equal the obligation's agent_id
// (or be a registered BROKER caller against a tenant with allow_broker_relay
// set). Mismatch → PermissionDenied without writing an audit row.
func (s *ExchangeService) ReportUsage(
	ctx context.Context,
	req *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	if req == nil {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "report required")
	}
	if req.GetTransactionId() == "" {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "transaction_id required")
	}
	if req.GetIdempotencyKey() == "" {
		// UsageReport.id is the dispute-chain anchor and the idempotency key;
		// reject empty at the boundary rather than silently treating it as
		// "no idempotency".
		return nil, exchange.Newf(exchange.KindInvalidRequest, "report id required")
	}

	caller, err := s.resolveCaller(ctx)
	if err != nil {
		return nil, err
	}

	// Idempotent-retry probe outside any transaction — cheap point lookup.
	// A hit means we already ACCEPTED this exact UsageReport.id and must return
	// the same response without writing again. The probe keys on a prior
	// accepted result, not on a bare key match: our own MCP tool tells agents to
	// reuse the key when retrying, so a retry correcting a rejected report
	// arrives under the original key and has to be re-validated.
	if existing, lookupErr := s.obligations.FindAcceptedBySourceReportID(
		ctx, req.GetTransactionId(), req.GetIdempotencyKey(),
	); lookupErr == nil {
		return s.buildReplayResponse(ctx, caller, existing), nil
	} else if !errors.Is(lookupErr, repo.ErrObligationNotFound) {
		return nil, exchange.Wrap(exchange.KindInternal, lookupErr,
			"idempotent retry probe")
	}

	// validationErr survives the tx so the audit-row commit can flush
	// before we return the validation failure to the caller. Without this,
	// returning the error from BeginFunc rolls back the row
	// MarkValidationRejected just wrote, and the rejection becomes invisible
	// to everything that reads it: the operator evidence route renders
	// validation_outcome and validated_at from that row, and it is the only
	// record of which check refused the report.
	var (
		out           *rampv1.UsageReportResponse
		validationErr *exchange.Error
	)
	txErr := s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		return s.runReportUsageTx(ctx, tx, caller, req, &out, &validationErr)
	})
	if txErr != nil {
		return nil, txErr
	}
	if validationErr != nil {
		return nil, validationErr
	}
	return out, nil
}

// runReportUsageTx executes the load/authz/validate/persist sequence inside
// the caller's transaction. Extracted from ReportUsage so the cognitive
// complexity budget stays under the per-function cap; out and validationErr
// are filled in by the success / rejection paths and consumed once the tx
// commits in ReportUsage.
func (s *ExchangeService) runReportUsageTx(
	ctx context.Context, tx pgx.Tx, caller Caller, req *rampv1.UsageReport,
	out **rampv1.UsageReportResponse, validationErr **exchange.Error,
) error {
	rc, loadErr := s.obligations.LoadForReportTx(ctx, tx, req.GetTransactionId())
	if loadErr != nil {
		if errors.Is(loadErr, repo.ErrObligationNotFound) {
			return exchange.Newf(exchange.KindNotFound, "no obligation for transaction")
		}
		return exchange.Wrap(exchange.KindInternal, loadErr, "load obligation with transaction")
	}
	if authzErr := authorizeForAgent(caller, rc.AgentID, rc.AllowBrokerRelay); authzErr != nil {
		// No audit row — authz failures must not allow attackers to pollute
		// the audit trail. Rollback (returning err from BeginFunc) is wanted.
		s.logOutcome(ctx, "report_usage", "REJECTED_AUTHZ", caller,
			&repo.Tenant{ID: rc.TenantID}, rc.AgentID, rc.TransactionID, authzErr)
		return authzErr
	}
	outcome, vErr := ValidateUsageReport(ReportInput{
		Obligation:    rc.Obligation,
		TransactionID: rc.TransactionID,
		BillingID:     rc.BillingID,
		CreatedAt:     rc.CreatedAt,
		Report:        req,
		Now:           s.clk.Now(),
	})
	if vErr != nil {
		return s.persistRejection(ctx, tx, caller, req, rc, outcome, vErr, validationErr)
	}
	return s.persistValidation(ctx, tx, caller, req, rc, out)
}

// refuseAlreadyReported answers a report filed against an obligation that has
// already settled. Both persist paths reach it, because the accept statement
// and the reject statement carry the same AND state = 'PENDING' predicate and
// so match zero rows for the same reason.
//
// The line is logged before returning. Returning the error rolls the
// transaction back, so nothing is written to the obligation row, and without
// the line the attempt would leave no trace at all — on the one request shape
// worth an operator's attention, an agent filing a second report over a settled
// one to move validation_outcome and source_report_id off the accepted key, on
// the surface a dispute would be settled from. The authorization refusal takes
// the same shape: it deliberately writes no row and still logs first.
func (s *ExchangeService) refuseAlreadyReported(
	ctx context.Context, caller Caller, rc repo.ReportValidationContext,
) *exchange.Error {
	rerr := exchange.Newf(exchange.KindFailedPrecondition, "obligation already reported")
	s.logOutcome(ctx, "report_usage", "REJECTED_ALREADY_REPORTED", caller,
		&repo.Tenant{ID: rc.TenantID}, rc.AgentID, rc.TransactionID, rerr)
	return rerr
}

func (s *ExchangeService) persistRejection(
	ctx context.Context, tx pgx.Tx, caller Caller, req *rampv1.UsageReport,
	rc repo.ReportValidationContext, outcome repo.ValidationOutcome,
	vErr *exchange.Error, validationErr **exchange.Error,
) error {
	if _, mErr := s.obligations.MarkValidationRejected(ctx, tx, repo.RejectReport{
		ObligationID:   rc.Obligation.ID,
		Outcome:        outcome,
		SourceReportID: req.GetIdempotencyKey(),
		Now:            s.clk.Now(),
	}); mErr != nil {
		if errors.Is(mErr, repo.ErrObligationAlreadyReported) {
			// The obligation was already settled, so this rejection has nothing
			// to record against it. Returning the error rolls the transaction
			// back, which is wanted: writing the outcome here would walk a
			// VALIDATED row back to a rejection and move source_report_id off
			// the accepted key, breaking the replay of that key. Same answer the
			// accept path gives for a second report against a settled
			// obligation.
			return s.refuseAlreadyReported(ctx, caller, rc)
		}
		return exchange.Wrap(exchange.KindInternal, mErr, "persist validation rejection")
	}
	s.logOutcome(ctx, "report_usage", string(outcome), caller,
		&repo.Tenant{ID: rc.TenantID}, rc.AgentID, rc.TransactionID, vErr)
	// Returning nil commits the audit row; the caller-facing error is
	// surfaced from validationErr after the tx flushes.
	*validationErr = vErr
	return nil
}

func (s *ExchangeService) persistValidation(
	ctx context.Context, tx pgx.Tx, caller Caller, req *rampv1.UsageReport,
	rc repo.ReportValidationContext, out **rampv1.UsageReportResponse,
) error {
	consumed, err := consumedNumeric(req)
	if err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "encode consumed quantity")
	}
	issuedReportID := uuid.NewString()
	updated, mErr := s.obligations.MarkValidationValidated(ctx, tx, repo.AcceptReport{
		ObligationID:   rc.Obligation.ID,
		SourceReportID: req.GetIdempotencyKey(),
		IssuedReportID: issuedReportID,
		Consumed:       consumed,
		Now:            s.clk.Now(),
	})
	if mErr != nil {
		if errors.Is(mErr, repo.ErrObligationAlreadyReported) {
			return s.refuseAlreadyReported(ctx, caller, rc)
		}
		return exchange.Wrap(exchange.KindInternal, mErr, "persist validation outcome")
	}
	*out = &rampv1.UsageReportResponse{
		Ver:      helpers.ProtocolVersion,
		ReportId: updated.IssuedReportID,
	}
	s.logOutcome(ctx, "report_usage", "VALIDATED", caller,
		&repo.Tenant{ID: rc.TenantID}, rc.AgentID, rc.TransactionID, nil)
	return nil
}

// buildReplayResponse mirrors the response we returned when this
// UsageReport.idempotency_key was ACCEPTED. The replay path does not re-run
// validation; the idempotent contract is "same input → same output." Acceptance
// and rejection are not an in-body flag (ADR-019 §2: a rejected report is a
// transport error), so a replay reaching here always has an issued report id to
// return — the probe that selected this row required one.
func (s *ExchangeService) buildReplayResponse(
	ctx context.Context, caller Caller, existing repo.Obligation,
) *rampv1.UsageReportResponse {
	s.logOutcome(ctx, "report_usage", "REPLAY", caller, nil, "", existing.TransactionID, nil)
	return &rampv1.UsageReportResponse{
		Ver:      helpers.ProtocolVersion,
		ReportId: existing.IssuedReportID,
	}
}

// consumedNumeric turns the report's int32 consumed_quantity into the
// pgtype.Numeric the consumed_quantity NUMERIC(20,8) column expects. The
// formatter uses Sprintf with %d because the wire type is int and the
// repo's numericFromDecimal already canonicalises through pgx.
func consumedNumeric(req *rampv1.UsageReport) (pgtype.Numeric, error) {
	consumed := int64(req.GetUsage().GetConsumedQuantity())
	var n pgtype.Numeric
	if err := n.Scan(fmt.Sprintf("%d", consumed)); err != nil {
		return pgtype.Numeric{}, err
	}
	return n, nil
}
