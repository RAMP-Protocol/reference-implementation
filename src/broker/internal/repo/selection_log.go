package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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
	// CreatedAt is when the Broker recorded the decision (server clock). It is
	// read-only: the write path lets the column default to NOW(), so
	// RecordSelection ignores whatever this field holds.
	CreatedAt time.Time
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
	// LatestOfferingOffer returns the most recent decision in which this Broker
	// offered offerID to agentID, at or before notAfter and no earlier than
	// notAfter minus window. Nil entry and nil error when nothing matches:
	// absence is a fact about the audit log, not a failure to read it, exactly
	// as ByRequestID's empty slice is.
	//
	// The window exists because the same agent may be offered the same offer
	// again later. An unbounded search would happily return a decision from a
	// week after the transaction it is being joined to, which is a different
	// event wearing the same two identifiers.
	//
	// agentID is the Exchange's canonical agent identity — the directory host,
	// not the directory URI a signer spelled. Callers holding a signed
	// Requester.id must reduce it through agentid.FromDirectory first; the two
	// name the same agent but are not byte-equal.
	LatestOfferingOffer(
		ctx context.Context, agentID, offerID string, notAfter time.Time, window time.Duration,
	) (*SelectionLogEntry, error)
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
	return decodeSelectionRows(rows)
}

// LatestOfferingOffer reads the newest decision that offered offerID to agentID
// inside the window ending at notAfter. The offer test is a JSONB containment
// check the database performs, so a decision that listed a hundred candidates
// costs the same as one that listed two, and no row the query rejects is ever
// decoded here.
func (r *PgxSelectionLogRepo) LatestOfferingOffer(
	ctx context.Context, agentID, offerID string, notAfter time.Time, window time.Duration,
) (*SelectionLogEntry, error) {
	// The containment operand is a one-element array holding only the key being
	// searched for. JSONB containment is recursive, so this matches any element
	// carrying that offer_id whatever else the element holds.
	member, err := json.Marshal([]map[string]string{{"offer_id": offerID}})
	if err != nil {
		return nil, fmt.Errorf("marshal offer member: %w", err)
	}
	rows, err := r.q.SelectionsOfferingOffer(ctx, sqlc.SelectionsOfferingOfferParams{
		AgentID:     agentID,
		OfferMember: member,
		NotAfter:    pgtype.Timestamptz{Time: notAfter, Valid: true},
		NotBefore:   pgtype.Timestamptz{Time: notAfter.Add(-window), Valid: true},
		MaxRows:     1,
	})
	if err != nil {
		return nil, fmt.Errorf("selections offering offer: %w", err)
	}
	entries, err := decodeSelectionRows(rows)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return &entries[0], nil
}

// decodeSelectionRows reconstructs the JSONB columns of a set of audit rows into
// their domain shapes. Both reads share it, so the two cannot decode the same
// stored row into two different entries.
func decodeSelectionRows(rows []sqlc.BrokerSelectionLog) ([]SelectionLogEntry, error) {
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
			CreatedAt:       row.CreatedAt.Time,
		})
	}
	return entries, nil
}
