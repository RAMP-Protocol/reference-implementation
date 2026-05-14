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

// TransactionRecord is the domain view of a transaction_log row.
type TransactionRecord struct {
	Expiry             time.Time
	CreatedAt          time.Time
	AgentIdentityHash  []byte
	SignedURLHash      []byte
	TransactionID      string
	TxRequestID        string
	TenantID           string
	AgentID            string
	ResourceID         string
	OfferID            string
	BillingID          string
	UnitCostDecimal    string // canonical decimal representation
	Currency           string
	ConsumedUnit       string
	DenialReason       string
	OfferSignature     string // verbatim, as the agent presented it
	SignedURLSignature string // verbatim signature substring extracted from the issued URL
}

// TransactionRepo is the write-before-sign contract for transaction log rows.
type TransactionRepo interface {
	Create(ctx context.Context, tx pgx.Tx, rec TransactionRecord) (*TransactionRecord, error)
	ByRequestID(ctx context.Context, txRequestID string) (*TransactionRecord, error)
	ByID(ctx context.Context, transactionID string) (*TransactionRecord, error)
}

// ErrTransactionNotFound signals an idempotency probe miss.
var ErrTransactionNotFound = errors.New("repo: transaction not found")

// NewTransactionRepo composes a TransactionRepo over the sqlc package.
// It accepts the sqlc Querier for non-tx reads and the concrete *sqlc.Queries
// for tx-scoped writes (created via sqlc.New(tx)).
func NewTransactionRepo(q sqlc.Querier) TransactionRepo { return &transactionRepo{q: q} }

type transactionRepo struct{ q sqlc.Querier }

func (r *transactionRepo) Create(ctx context.Context, tx pgx.Tx, rec TransactionRecord) (*TransactionRecord, error) {
	qtx := sqlc.New(tx)
	unitCost, err := numericFromDecimal(rec.UnitCostDecimal)
	if err != nil {
		return nil, err
	}
	row, err := qtx.CreateTransaction(ctx, sqlc.CreateTransactionParams{
		TransactionID:      rec.TransactionID,
		TxRequestID:        rec.TxRequestID,
		TenantID:           rec.TenantID,
		AgentID:            rec.AgentID,
		ResourceID:         rec.ResourceID,
		OfferID:            rec.OfferID,
		AgentIdentityHash:  rec.AgentIdentityHash,
		SignedUrlHash:      rec.SignedURLHash,
		Expiry:             pgtype.Timestamptz{Time: rec.Expiry, Valid: true},
		BillingID:          pgText(rec.BillingID),
		UnitCost:           unitCost,
		Currency:           rec.Currency,
		ConsumedUnit:       pgText(rec.ConsumedUnit),
		DenialReason:       nullDenial(rec.DenialReason),
		OfferSignature:     pgText(rec.OfferSignature),
		SignedUrlSignature: pgText(rec.SignedURLSignature),
	})
	if err != nil {
		return nil, fmt.Errorf("create transaction: %w", err)
	}
	return transactionFromRow(row), nil
}

func (r *transactionRepo) ByRequestID(ctx context.Context, txRequestID string) (*TransactionRecord, error) {
	row, err := r.q.GetTransactionByRequestID(ctx, txRequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTransactionNotFound
		}
		return nil, fmt.Errorf("get transaction by request id: %w", err)
	}
	return transactionFromRow(row), nil
}

// ByID returns the transaction_log row for a given transaction_id (PK).
// Used by the /admin/ledger endpoint that backs `make ledger TX=<id>`.
func (r *transactionRepo) ByID(ctx context.Context, transactionID string) (*TransactionRecord, error) {
	row, err := r.q.GetTransactionByID(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTransactionNotFound
		}
		return nil, fmt.Errorf("get transaction by id: %w", err)
	}
	return transactionFromRow(row), nil
}

func transactionFromRow(row sqlc.RampTransactionLog) *TransactionRecord {
	rec := &TransactionRecord{
		TransactionID:      row.TransactionID,
		TxRequestID:        row.TxRequestID,
		TenantID:           row.TenantID,
		AgentID:            row.AgentID,
		ResourceID:         row.ResourceID,
		OfferID:            row.OfferID,
		AgentIdentityHash:  row.AgentIdentityHash,
		SignedURLHash:      row.SignedUrlHash,
		BillingID:          textOrEmpty(row.BillingID),
		Currency:           row.Currency,
		ConsumedUnit:       textOrEmpty(row.ConsumedUnit),
		OfferSignature:     textOrEmpty(row.OfferSignature),
		SignedURLSignature: textOrEmpty(row.SignedUrlSignature),
	}
	if row.Expiry.Valid {
		rec.Expiry = row.Expiry.Time
	}
	if row.CreatedAt.Valid {
		rec.CreatedAt = row.CreatedAt.Time
	}
	if dec, err := decimalFromNumeric(row.UnitCost); err == nil {
		rec.UnitCostDecimal = dec
	}
	if row.DenialReason.Valid {
		rec.DenialReason = string(row.DenialReason.RampDenialReason)
	}
	return rec
}

func numericFromDecimal(raw string) (pgtype.Numeric, error) {
	var n pgtype.Numeric
	if err := n.Scan(raw); err != nil {
		return pgtype.Numeric{}, fmt.Errorf("scan numeric %q: %w", raw, err)
	}
	return n, nil
}

func decimalFromNumeric(n pgtype.Numeric) (string, error) {
	if !n.Valid {
		return "", nil
	}
	v, err := n.Value()
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v), nil
	}
	return s, nil
}

func nullDenial(s string) sqlc.NullRampDenialReason {
	if s == "" {
		return sqlc.NullRampDenialReason{}
	}
	return sqlc.NullRampDenialReason{
		RampDenialReason: sqlc.RampDenialReason(s),
		Valid:            true,
	}
}
