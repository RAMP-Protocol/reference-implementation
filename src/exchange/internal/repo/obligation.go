package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// Obligation is the domain view of a reporting_obligations row.
type Obligation struct {
	ID                string
	TransactionID     string
	State             ObligationState
	WindowSeconds     int32
	Deadline          time.Time
	ConsumedQuantity  string // decimal canonical representation (empty until report)
	ReceivedAt        time.Time
	CreatedAt         time.Time
	RequiredFields    []string
	EstimatedQuantity int64
	QuantityTolerance float64
	ValidationOutcome ValidationOutcome // empty when never attempted
	ValidatedAt       time.Time
	SourceReportID    string // UsageReport.id the caller presented (idempotency anchor)
	IssuedReportID    string // UsageReportResponse.report_id we returned (dispute-chain anchor)
}

// ReportValidationContext carries every input the protocol-validation pass for
// ReportUsage needs in a single value. Returned by LoadForReport /
// LoadForReportTx so the service does not juggle three separate returns and
// future fields (tenant policy, agent metadata) land in one place.
type ReportValidationContext struct {
	Obligation       Obligation
	TransactionID    string
	BillingID        string
	CreatedAt        time.Time
	TenantID         string
	AgentID          string
	AllowBrokerRelay bool
}

// ObligationRepo is the contract the service needs for usage reports.
type ObligationRepo interface {
	// Create inserts a new obligation row inside the caller's transaction.
	Create(ctx context.Context, tx pgx.Tx, o Obligation) (Obligation, error)
	// CreateForOffer mints an obligation row from a PersistTxIntent.
	// Companion of TransactionRepo.CreateForOffer; each repo owns the
	// column-shape for its own table.
	CreateForOffer(ctx context.Context, tx pgx.Tx, intent PersistTxIntent) (Obligation, error)
	// ByTransaction returns the most-recent obligation for a transaction; used
	// by audit-style reads outside ReportUsage's hot path.
	ByTransaction(ctx context.Context, transactionID string) (Obligation, error)
	// LoadForReport loads the obligation, transaction, and tenant fields the
	// validator needs in one round-trip. Used by the idempotent-retry probe
	// outside any transaction.
	LoadForReport(ctx context.Context, transactionID string) (ReportValidationContext, error)
	// LoadForReportTx is LoadForReport with SELECT … FOR UPDATE on the
	// obligation row. Used inside ReportUsage's pgx.BeginFunc so load,
	// validate, and write run atomically against a held row.
	LoadForReportTx(ctx context.Context, tx pgx.Tx, transactionID string) (ReportValidationContext, error)
	// FindAcceptedBySourceReportID returns the obligation whose
	// (transaction_id, source_report_id) pair was already recorded AND
	// ACCEPTED. A hit means the caller is replaying a report this Exchange
	// already validated, so the service returns the original IssuedReportID
	// without re-running validation. A key that was only ever REJECTED does
	// not match: there is no accepted result to replay, and the retry must be
	// validated afresh.
	FindAcceptedBySourceReportID(ctx context.Context, transactionID, sourceReportID string) (Obligation, error)
	// MarkValidationValidated transitions the obligation PENDING→RECEIVED and
	// writes consumed_quantity + the source/issued report-id idempotency
	// anchors. The query carries an AND state = 'PENDING' predicate; zero
	// rows updated → ErrObligationAlreadyReported.
	MarkValidationValidated(ctx context.Context, tx pgx.Tx, in AcceptReport) (Obligation, error)
	// MarkValidationRejected records the rejection outcome without changing
	// obligation state, so the obligation stays PENDING and the caller may
	// retry with a corrected report — including under the same source report
	// id, which FindAcceptedBySourceReportID deliberately does not treat as a
	// replay.
	// The query carries an AND state = 'PENDING' predicate; zero rows updated
	// → ErrObligationAlreadyReported. So an audit row is written for every
	// rejection against a PENDING obligation, and none against a settled one.
	MarkValidationRejected(ctx context.Context, tx pgx.Tx, in RejectReport) (Obligation, error)
	// CountByStateAndDueness returns the reporting-compliance fact table for a
	// (tenant_id, agent_id): how many obligations sit in each state, split by
	// whether their deadline had passed at asOf. It classifies nothing —
	// naming a bucket "overdue" is the service's policy decision.
	CountByStateAndDueness(
		ctx context.Context, tenantID, agentID string, asOf time.Time,
	) (ObligationCounts, error)
}

// AcceptReport carries everything MarkValidationValidated writes. A struct
// rather than a longer parameter list: the fields are one decision — this report
// was accepted — so they travel together, and naming them at the call site is
// what keeps the two report ids from being passed in the wrong order.
type AcceptReport struct {
	ObligationID   string
	SourceReportID string
	IssuedReportID string
	Consumed       pgtype.Numeric
	// Now is the service clock's instant, written to received_at and
	// validated_at. The database clock is deliberately not consulted: the
	// deadline these are compared against was written from the service clock,
	// and comparing two clocks would make received_at > deadline unsound as a
	// lateness check. created_at is the one column on this row that still takes
	// the database default.
	Now time.Time
}

// RejectReport carries everything MarkValidationRejected writes. Mirrors
// AcceptReport so the two audit writes read the same way at their call sites.
type RejectReport struct {
	ObligationID   string
	Outcome        ValidationOutcome
	SourceReportID string
	// Now is the service clock's instant, written to validated_at. The
	// obligation's deadline, received_at and validated_at all come from this
	// clock, which is what makes received_at > deadline a sound lateness check.
	// It is not a claim about every timestamp on the row: created_at still takes
	// the column's database default.
	Now time.Time
}

// NewObligationRepo composes an ObligationRepo over a sqlc.Querier.
func NewObligationRepo(q sqlc.Querier) ObligationRepo { return &obligationRepo{q: q} }

type obligationRepo struct{ q sqlc.Querier }

// Sentinel errors.
var (
	// ErrObligationNotFound signals a lookup miss on the requested transaction.
	ErrObligationNotFound = errors.New("repo: obligation not found")
	// ErrObligationAlreadyReported signals that the AND state = 'PENDING' guard
	// matched zero rows on either MarkValidationValidated or
	// MarkValidationRejected — the obligation has already transitioned out of
	// PENDING and the caller is filing a second, distinct report.
	ErrObligationAlreadyReported = errors.New("repo: obligation already reported")
)

func (r *obligationRepo) Create(ctx context.Context, tx pgx.Tx, o Obligation) (Obligation, error) {
	qtx := sqlc.New(tx)
	tol, err := numericFromFloat(o.QuantityTolerance)
	if err != nil {
		return Obligation{}, fmt.Errorf("encode quantity_tolerance: %w", err)
	}
	row, err := qtx.CreateObligation(ctx, sqlc.CreateObligationParams{
		ObligationID:      o.ID,
		TransactionID:     o.TransactionID,
		State:             sqlcObligationState(stateOrDefault(o.State)),
		WindowSeconds:     pgtype.Int4{Int32: o.WindowSeconds, Valid: o.WindowSeconds > 0},
		Deadline:          pgtype.Timestamptz{Time: o.Deadline, Valid: true},
		RequiredFields:    o.RequiredFields,
		EstimatedQuantity: o.EstimatedQuantity,
		QuantityTolerance: tol,
	})
	if err != nil {
		return Obligation{}, fmt.Errorf("create obligation: %w", err)
	}
	return obligationFromRow(row)
}

// CreateForOffer projects a PersistTxIntent onto an Obligation and delegates
// to Create. The repo owns the field-mapping so the service no longer
// constructs Obligation literals at the call site.
func (r *obligationRepo) CreateForOffer(ctx context.Context, tx pgx.Tx, intent PersistTxIntent) (Obligation, error) {
	return r.Create(ctx, tx, Obligation{
		ID:                intent.ObligationID,
		TransactionID:     intent.TransactionID,
		State:             intent.State,
		WindowSeconds:     intent.WindowSeconds,
		Deadline:          intent.Deadline,
		RequiredFields:    intent.RequiredFields,
		EstimatedQuantity: intent.EstimatedQuantity,
		QuantityTolerance: intent.QuantityTolerance,
	})
}

func (r *obligationRepo) ByTransaction(ctx context.Context, transactionID string) (Obligation, error) {
	row, err := r.q.GetObligationByTransaction(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Obligation{}, ErrObligationNotFound
		}
		return Obligation{}, fmt.Errorf("get obligation by transaction: %w", err)
	}
	return obligationFromRow(row)
}

func (r *obligationRepo) LoadForReport(
	ctx context.Context, transactionID string,
) (ReportValidationContext, error) {
	row, err := r.q.GetObligationWithTransaction(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ReportValidationContext{}, ErrObligationNotFound
		}
		return ReportValidationContext{}, fmt.Errorf("load obligation with transaction: %w", err)
	}
	return reportContextFromJoinRow(joinRowFromGetObligation(row))
}

func (r *obligationRepo) LoadForReportTx(
	ctx context.Context, tx pgx.Tx, transactionID string,
) (ReportValidationContext, error) {
	qtx := sqlc.New(tx)
	row, err := qtx.GetObligationWithTransactionForUpdate(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ReportValidationContext{}, ErrObligationNotFound
		}
		return ReportValidationContext{}, fmt.Errorf("load obligation with transaction for update: %w", err)
	}
	return reportContextFromJoinRow(joinRowFromGetObligationForUpdate(row))
}

func (r *obligationRepo) FindAcceptedBySourceReportID(
	ctx context.Context, transactionID, sourceReportID string,
) (Obligation, error) {
	row, err := r.q.FindAcceptedObligationBySourceReportID(ctx, sqlc.FindAcceptedObligationBySourceReportIDParams{
		TransactionID:  transactionID,
		SourceReportID: pgtype.Text{String: sourceReportID, Valid: sourceReportID != ""},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Obligation{}, ErrObligationNotFound
		}
		return Obligation{}, fmt.Errorf("find obligation by source_report_id: %w", err)
	}
	return obligationFromRow(row)
}

func (r *obligationRepo) MarkValidationValidated(
	ctx context.Context, tx pgx.Tx, in AcceptReport,
) (Obligation, error) {
	qtx := sqlc.New(tx)
	row, err := qtx.MarkValidationValidated(ctx, sqlc.MarkValidationValidatedParams{
		ObligationID:     in.ObligationID,
		ConsumedQuantity: in.Consumed,
		SourceReportID:   pgtype.Text{String: in.SourceReportID, Valid: in.SourceReportID != ""},
		IssuedReportID:   pgtype.Text{String: in.IssuedReportID, Valid: in.IssuedReportID != ""},
		Now:              pgtype.Timestamptz{Time: in.Now, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Zero rows updated — the state guard (AND state = 'PENDING')
			// matched nothing. The obligation has already transitioned.
			return Obligation{}, ErrObligationAlreadyReported
		}
		return Obligation{}, fmt.Errorf("mark validation validated: %w", err)
	}
	return obligationFromRow(row)
}

func (r *obligationRepo) MarkValidationRejected(
	ctx context.Context, tx pgx.Tx, in RejectReport,
) (Obligation, error) {
	qtx := sqlc.New(tx)
	row, err := qtx.MarkValidationRejected(ctx, sqlc.MarkValidationRejectedParams{
		ObligationID: in.ObligationID,
		ValidationOutcome: sqlc.NullRampValidationOutcome{
			RampValidationOutcome: sqlcValidationOutcome(in.Outcome),
			Valid:                 true,
		},
		SourceReportID: pgtype.Text{String: in.SourceReportID, Valid: in.SourceReportID != ""},
		Now:            pgtype.Timestamptz{Time: in.Now, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The statement's state predicate did not match, so the obligation
			// was not PENDING. Same mapping as the accept path: a report against
			// a settled obligation is refused rather than written over it.
			return Obligation{}, ErrObligationAlreadyReported
		}
		return Obligation{}, fmt.Errorf("mark validation rejected: %w", err)
	}
	return obligationFromRow(row)
}

func (r *obligationRepo) CountByStateAndDueness(
	ctx context.Context, tenantID, agentID string, asOf time.Time,
) (ObligationCounts, error) {
	rows, err := r.q.CountObligationsByStateAndDueness(ctx, sqlc.CountObligationsByStateAndDuenessParams{
		TenantID: tenantID,
		AgentID:  agentID,
		AsOf:     pgtype.Timestamptz{Time: asOf, Valid: true},
	})
	if err != nil {
		return ObligationCounts{}, fmt.Errorf("count obligations by state and dueness: %w", err)
	}
	// At most four rows: two states times two dueness values.
	buckets := make(map[obligationBucket]int64, len(rows))
	for _, row := range rows {
		buckets[obligationBucket{
			state:        domainObligationState(row.State),
			pastDeadline: row.PastDeadline,
		}] = row.N
	}
	return ObligationCounts{buckets: buckets}, nil
}

// obligationFromRow is the single owner of RampReportingObligation → Obligation
// mapping. Both join-row paths (LoadForReport / LoadForReportTx) synthesise a
// RampReportingObligation via joinRowFromGetObligation* and route through here,
// so the ~16-field mapping lives in exactly one place.
func obligationFromRow(row sqlc.RampReportingObligation) (Obligation, error) {
	o := Obligation{
		ID:                row.ObligationID,
		TransactionID:     row.TransactionID,
		State:             domainObligationState(row.State),
		RequiredFields:    row.RequiredFields,
		EstimatedQuantity: row.EstimatedQuantity,
	}
	if row.WindowSeconds.Valid {
		o.WindowSeconds = row.WindowSeconds.Int32
	}
	if row.Deadline.Valid {
		o.Deadline = row.Deadline.Time
	}
	if row.ReceivedAt.Valid {
		o.ReceivedAt = row.ReceivedAt.Time
	}
	if row.CreatedAt.Valid {
		o.CreatedAt = row.CreatedAt.Time
	}
	if row.ValidationOutcome.Valid {
		o.ValidationOutcome = domainValidationOutcome(row.ValidationOutcome.RampValidationOutcome)
	}
	if row.ValidatedAt.Valid {
		o.ValidatedAt = row.ValidatedAt.Time
	}
	// Propagate NUMERIC decode errors rather than swallowing them: a consumed-
	// quantity or tolerance must never be silently zeroed by a decode failure.
	dec, err := decimalFromNumeric(row.ConsumedQuantity)
	if err != nil {
		return Obligation{}, fmt.Errorf("decode consumed_quantity for obligation %q: %w", row.ObligationID, err)
	}
	o.ConsumedQuantity = dec
	tol, err := floatFromNumeric(row.QuantityTolerance)
	if err != nil {
		return Obligation{}, fmt.Errorf("decode quantity_tolerance for obligation %q: %w", row.ObligationID, err)
	}
	o.QuantityTolerance = tol
	o.SourceReportID = textOrEmpty(row.SourceReportID)
	o.IssuedReportID = textOrEmpty(row.IssuedReportID)
	return o, nil
}

// obligationJoinRow is the narrow shape obligationFromRow consumes when called
// from the join paths: it carries every RampReportingObligation field plus the
// joined tenant/transaction fields. Defined here (not in sqlc) so the two
// generated join-row types can both feed obligationFromRow without duplicating
// the 16-field mapping.
type obligationJoinRow struct {
	core             sqlc.RampReportingObligation
	txCreatedAt      pgtype.Timestamptz
	txBillingID      pgtype.Text
	txTenantID       string
	txAgentID        string
	allowBrokerRelay bool
}

func joinRowFromGetObligation(r sqlc.GetObligationWithTransactionRow) obligationJoinRow {
	return obligationJoinRow{
		core: sqlc.RampReportingObligation{
			ObligationID:      r.ObligationID,
			TransactionID:     r.TransactionID,
			State:             r.State,
			WindowSeconds:     r.WindowSeconds,
			Deadline:          r.Deadline,
			ConsumedQuantity:  r.ConsumedQuantity,
			ReceivedAt:        r.ReceivedAt,
			CreatedAt:         r.CreatedAt,
			RequiredFields:    r.RequiredFields,
			EstimatedQuantity: r.EstimatedQuantity,
			QuantityTolerance: r.QuantityTolerance,
			ValidationOutcome: r.ValidationOutcome,
			ValidatedAt:       r.ValidatedAt,
			SourceReportID:    r.SourceReportID,
			IssuedReportID:    r.IssuedReportID,
		},
		txCreatedAt:      r.TxCreatedAt,
		txBillingID:      r.TxBillingID,
		txTenantID:       r.TxTenantID,
		txAgentID:        r.TxAgentID,
		allowBrokerRelay: r.TenantAllowBrokerRelay,
	}
}

// joinRowFromGetObligationForUpdate routes through joinRowFromGetObligation
// after a straight-up struct conversion: the two sqlc row types are
// generated from queries that SELECT the same columns in the same order, so
// Go's identical-struct conversion rule (field names + types match; tags
// ignored) makes the cast safe and zero-cost. This keeps the 16-field
// obligation mapping in exactly one place.
func joinRowFromGetObligationForUpdate(r sqlc.GetObligationWithTransactionForUpdateRow) obligationJoinRow {
	return joinRowFromGetObligation(sqlc.GetObligationWithTransactionRow(r))
}

func reportContextFromJoinRow(jr obligationJoinRow) (ReportValidationContext, error) {
	obligation, err := obligationFromRow(jr.core)
	if err != nil {
		return ReportValidationContext{}, err
	}
	ctx := ReportValidationContext{
		Obligation:       obligation,
		TransactionID:    jr.core.TransactionID,
		BillingID:        textOrEmpty(jr.txBillingID),
		TenantID:         jr.txTenantID,
		AgentID:          jr.txAgentID,
		AllowBrokerRelay: jr.allowBrokerRelay,
	}
	if jr.txCreatedAt.Valid {
		ctx.CreatedAt = jr.txCreatedAt.Time
	}
	return ctx, nil
}

func stateOrDefault(s ObligationState) ObligationState {
	if s == "" {
		return ObligationStatePending
	}
	return s
}
