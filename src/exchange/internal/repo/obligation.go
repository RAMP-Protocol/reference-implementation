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
	ID            string
	TransactionID string
	State         string
	WindowSeconds int32
	Deadline      time.Time
	Consumed      string // decimal canonical representation (empty until report)
	ReceivedAt    time.Time
}

// ObligationRepo is the contract the service needs for usage reports.
type ObligationRepo interface {
	Create(ctx context.Context, tx pgx.Tx, o Obligation) (Obligation, error)
	MarkReceived(ctx context.Context, obligationID, consumedDecimal string) (Obligation, error)
	ByTransaction(ctx context.Context, transactionID string) (Obligation, error)
}

// NewObligationRepo composes an ObligationRepo over a sqlc.Querier.
func NewObligationRepo(q sqlc.Querier) ObligationRepo { return &obligationRepo{q: q} }

type obligationRepo struct{ q sqlc.Querier }

func (r *obligationRepo) Create(ctx context.Context, tx pgx.Tx, o Obligation) (Obligation, error) {
	qtx := sqlc.New(tx)
	row, err := qtx.CreateObligation(ctx, sqlc.CreateObligationParams{
		ObligationID:  o.ID,
		TransactionID: o.TransactionID,
		State:         sqlc.RampObligationState(stateOrDefault(o.State)),
		WindowSeconds: pgtype.Int4{Int32: o.WindowSeconds, Valid: o.WindowSeconds > 0},
		Deadline:      pgtype.Timestamptz{Time: o.Deadline, Valid: true},
	})
	if err != nil {
		return Obligation{}, fmt.Errorf("create obligation: %w", err)
	}
	return obligationFromRow(row), nil
}

// ErrObligationNotFound is returned when the obligation lookup has no match.
var ErrObligationNotFound = errors.New("repo: obligation not found")

func (r *obligationRepo) ByTransaction(ctx context.Context, transactionID string) (Obligation, error) {
	row, err := r.q.GetObligationByTransaction(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Obligation{}, ErrObligationNotFound
		}
		return Obligation{}, fmt.Errorf("get obligation by transaction: %w", err)
	}
	return obligationFromRow(row), nil
}

func (r *obligationRepo) MarkReceived(ctx context.Context, obligationID, consumedDecimal string) (Obligation, error) {
	consumed, err := numericFromDecimal(consumedDecimal)
	if err != nil {
		return Obligation{}, err
	}
	row, err := r.q.MarkObligationReceived(ctx, sqlc.MarkObligationReceivedParams{
		ObligationID:     obligationID,
		ConsumedQuantity: consumed,
	})
	if err != nil {
		return Obligation{}, fmt.Errorf("mark obligation received: %w", err)
	}
	return obligationFromRow(row), nil
}

func obligationFromRow(row sqlc.RampReportingObligation) Obligation {
	o := Obligation{
		ID:            row.ObligationID,
		TransactionID: row.TransactionID,
		State:         string(row.State),
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
	if dec, err := decimalFromNumeric(row.ConsumedQuantity); err == nil {
		o.Consumed = dec
	}
	return o
}

func stateOrDefault(s string) string {
	if s == "" {
		return string(sqlc.RampObligationStatePENDING)
	}
	return s
}
