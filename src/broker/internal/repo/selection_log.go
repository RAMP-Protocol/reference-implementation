package repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

// SelectionLogEntry is the domain representation of an audited selection decision.
type SelectionLogEntry struct {
	LogID             string
	RequestID         string
	AgentID           string
	Query             string
	CandidateOffers   any
	WinnerOfferID     string
	WinnerMarketplace string
	Rationale         any
}

// SelectionLogRepo records append-only broker selection decisions for audit.
type SelectionLogRepo interface {
	RecordSelection(ctx context.Context, entry SelectionLogEntry) error
}

// PgxSelectionLogRepo implements SelectionLogRepo against a pgx pool.
type PgxSelectionLogRepo struct {
	q *sqlc.Queries
}

// NewSelectionLogRepo constructs a SelectionLogRepo.
func NewSelectionLogRepo(pool *pgxpool.Pool) *PgxSelectionLogRepo {
	return &PgxSelectionLogRepo{q: sqlc.New(pool)}
}

// RecordSelection persists a selection decision.
func (r *PgxSelectionLogRepo) RecordSelection(ctx context.Context, entry SelectionLogEntry) error {
	candidates, err := json.Marshal(entry.CandidateOffers)
	if err != nil {
		return fmt.Errorf("marshal candidate offers: %w", err)
	}
	rationale, err := json.Marshal(entry.Rationale)
	if err != nil {
		return fmt.Errorf("marshal rationale: %w", err)
	}
	_, err = r.q.RecordSelection(ctx, sqlc.RecordSelectionParams{
		LogID:             entry.LogID,
		RequestID:         entry.RequestID,
		AgentID:           entry.AgentID,
		Query:             entry.Query,
		CandidateOffers:   candidates,
		WinnerOfferID:     optionalText(entry.WinnerOfferID),
		WinnerMarketplace: optionalText(entry.WinnerMarketplace),
		Rationale:         rationale,
	})
	if err != nil {
		return fmt.Errorf("record selection: %w", err)
	}
	return nil
}

func optionalText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
