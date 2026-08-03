// ReportUsage and its helpers. Extracted from exchange.go to keep the
// service files under the 500-line per-file cap and to give the
// idempotency / authz / validation choreography a single home.

package service

import (
	"context"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// ReportUsage validates and records a usage report against the obligation
// created at ExecuteTransaction time. The five RAMP §3.2 #4 + L6-remainder
// checks (required fields, window, quantity tolerance, billing_id,
// timestamp, exchange) run inside the same transaction as the persist so
// audit and state stay consistent.
//
// Idempotency: UsageReport.id is the caller-supplied idempotency anchor.
// Replays with the same id return the original UsageReportResponse.report_id
// without re-running validation. Two different UsageReport.id values against
// the same obligation are rejected on the second call (the state guard on
// MarkValidationValidated fires).
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
	// A hit means we already processed this exact UsageReport.id and must
	// return the same response without writing again.
	if existing, lookupErr := s.obligations.FindBySourceReportID(
		ctx, req.GetTransactionId(), req.GetIdempotencyKey(),
	); lookupErr == nil {
		return s.buildReplayResponse(ctx, caller, existing), nil
	} else if !errors.Is(lookupErr, repo.ErrObligationNotFound) {
		return nil, exchange.Wrap(exchange.KindInternal, lookupErr,
			"idempotent retry probe")
	}

	// validationErr survives the tx so the audit-row commit can flush
	// before we return the validation failure to the caller. Without this
	// dance, returning the error from BeginFunc rolls back the audit row
	// MarkValidationRejected just wrote — the rejection becomes invisible
	// to operators and to /list-outstanding queries.
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
		Exchange:      s.cfg.Exchange,
	})
	if vErr != nil {
		return s.persistRejection(ctx, tx, caller, req, rc, outcome, vErr, validationErr)
	}
	return s.persistValidation(ctx, tx, caller, req, rc, out)
}

func (s *ExchangeService) persistRejection(
	ctx context.Context, tx pgx.Tx, caller Caller, req *rampv1.UsageReport,
	rc repo.ReportValidationContext, outcome repo.ValidationOutcome,
	vErr *exchange.Error, validationErr **exchange.Error,
) error {
	if _, mErr := s.obligations.MarkValidationRejected(
		ctx, tx, rc.Obligation.ID, outcome, req.GetIdempotencyKey(),
	); mErr != nil {
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
	updated, mErr := s.obligations.MarkValidationValidated(
		ctx, tx, rc.Obligation.ID, req.GetIdempotencyKey(), issuedReportID, consumed,
	)
	if mErr != nil {
		if errors.Is(mErr, repo.ErrObligationAlreadyReported) {
			return exchange.Newf(exchange.KindFailedPrecondition,
				"obligation already reported")
		}
		return exchange.Wrap(exchange.KindInternal, mErr, "persist validation outcome")
	}
	*out = &rampv1.UsageReportResponse{
		ReportId: updated.IssuedReportID,
	}
	s.logOutcome(ctx, "report_usage", "VALIDATED", caller,
		&repo.Tenant{ID: rc.TenantID}, rc.AgentID, rc.TransactionID, nil)
	return nil
}

// buildReplayResponse mirrors the response we returned on the first call for
// this UsageReport.idempotency_key. The replay path does not re-run validation;
// the idempotent contract is "same input → same output." Acceptance/rejection
// is no longer an in-body flag (ADR-019 §2: a rejected report is a transport
// error); the success replay returns the issued report id. Precise error-replay
// semantics for a non-received obligation are wired under the idempotency work.
func (s *ExchangeService) buildReplayResponse(
	ctx context.Context, caller Caller, existing repo.Obligation,
) *rampv1.UsageReportResponse {
	s.logOutcome(ctx, "report_usage", "REPLAY", caller, nil, "", existing.TransactionID, nil)
	return &rampv1.UsageReportResponse{
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
