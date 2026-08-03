package repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

// SelectionLogEntry is the domain representation of an audited selection decision.
type SelectionLogEntry struct {
	LogID           string
	RequestID       string
	AgentID         string
	Query           string
	CandidateOffers any
	Rationale       any
}

// CandidateInfo is the audited view of an evaluated offer, reconstructed from the
// selection_log.candidate_offers JSONB on read. It is the repo layer's OWN type
// (NOT transport.CandidateInfo — repo must not import transport, which already
// imports repo; that would be a compile-time import cycle). The json tags match
// the keys the write path persists, so the round-trip is field-stable.
type CandidateInfo struct {
	OfferID    string `json:"offer_id"`
	ExchangeID string `json:"exchange_id"`
	// UnitCost is the offer's canonical wire money string, mirroring
	// transport.CandidateInfo.UnitCost so the candidate_offers JSONB round-trips
	// field-stably. Money is a decimal string on the wire, never a float.
	UnitCost   string `json:"unit_cost"`
	TrustLevel string `json:"trust_level"`
}

// SelectionLogRepo records and reads back broker selection decisions for audit.
type SelectionLogRepo interface {
	RecordSelection(ctx context.Context, entry SelectionLogEntry) error
	// ByRequestID returns the selection-audit entries recorded for a resolve,
	// keyed by the request_id the Broker minted (and echoed on X-Request-ID).
	// RAMP defines no protocol reporting RPC, so this repository method is the
	// broker-internal observable surface for the selection audit until
	// BrokerOpsService/GetResolveAudit lands. Empty slice, no error, when
	// nothing matches.
	ByRequestID(ctx context.Context, requestID string) ([]SelectionLogEntry, error)
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
		LogID:           entry.LogID,
		RequestID:       entry.RequestID,
		AgentID:         entry.AgentID,
		Query:           entry.Query,
		CandidateOffers: candidates,
		Rationale:       rationale,
	})
	if err != nil {
		return fmt.Errorf("record selection: %w", err)
	}
	return nil
}

// ByRequestID reads the audited selection decisions for a resolve back through
// the production repository surface, reconstructing the JSONB candidate_offers
// into typed []CandidateInfo and the rationale into a generic map. The sqlc
// :many query returns an empty slice (not nil) when nothing matches.
func (r *PgxSelectionLogRepo) ByRequestID(ctx context.Context, requestID string) ([]SelectionLogEntry, error) {
	rows, err := r.q.SelectionsByRequestID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("selections by request id: %w", err)
	}
	entries := make([]SelectionLogEntry, 0, len(rows))
	for _, row := range rows {
		var candidates []CandidateInfo
		if err := json.Unmarshal(row.CandidateOffers, &candidates); err != nil {
			return nil, fmt.Errorf("unmarshal candidate offers (log %s): %w", row.LogID, err)
		}
		var rationale any
		if err := json.Unmarshal(row.Rationale, &rationale); err != nil {
			return nil, fmt.Errorf("unmarshal rationale (log %s): %w", row.LogID, err)
		}
		entries = append(entries, SelectionLogEntry{
			LogID:           row.LogID,
			RequestID:       row.RequestID,
			AgentID:         row.AgentID,
			Query:           row.Query,
			CandidateOffers: candidates,
			Rationale:       rationale,
		})
	}
	return entries, nil
}
