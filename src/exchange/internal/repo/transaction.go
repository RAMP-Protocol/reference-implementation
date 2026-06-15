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
	TransactionID     string
	TxRequestID       string
	TenantID          string
	AgentID           string
	ResourceID        string
	OfferID           string
	AgentIdentityHash []byte
	SignedURLHash     []byte
	Expiry            time.Time
	BillingID         string
	UnitCostDecimal   string // canonical decimal representation
	Currency          string
	ConsumedUnit      string
	DenialReason      string
	CreatedAt         time.Time
}

// PersistTxIntent carries the fields needed to mint a transaction-log row
// AND its companion reporting-obligation row in the same transaction. The
// service builds the intent once and both repos consume their own subset;
// each repo owns the column-shape for its table.
type PersistTxIntent struct {
	// Identifiers
	TransactionID string
	TxRequestID   string
	ObligationID  string

	// Tenant / caller binding
	TenantID string
	AgentID  string

	// Catalog binding (resource_id and offer_id are the same value for v1)
	ResourceID string
	OfferID    string

	// Audit + signed-URL evidence
	AgentIdentityHash []byte
	SignedURLHash     []byte
	Expiry            time.Time

	// Billing / pricing
	BillingID       string
	UnitCostDecimal string
	Currency        string

	// Reporting-obligation columns
	State             ObligationState
	WindowSeconds     int32
	Deadline          time.Time
	RequiredFields    []string
	EstimatedQuantity int64
	QuantityTolerance float64
}

// TransactionRepo is the write-before-sign contract for transaction log rows.
type TransactionRepo interface {
	Create(ctx context.Context, tx pgx.Tx, rec TransactionRecord) (TransactionRecord, error)
	// CreateForOffer mints a transaction-log row from a PersistTxIntent.
	// Equivalent to building a TransactionRecord inline and calling Create,
	// but keeps the column-shape mapping inside the repo.
	CreateForOffer(ctx context.Context, tx pgx.Tx, intent PersistTxIntent) (TransactionRecord, error)
	ByRequestID(ctx context.Context, txRequestID string) (TransactionRecord, error)
}

// ErrTransactionNotFound signals an idempotency probe miss.
var ErrTransactionNotFound = errors.New("repo: transaction not found")

// NewTransactionRepo composes a TransactionRepo over the sqlc package.
// It accepts the sqlc Querier for non-tx reads and the concrete *sqlc.Queries
// for tx-scoped writes (created via sqlc.New(tx)).
func NewTransactionRepo(q sqlc.Querier) TransactionRepo { return &transactionRepo{q: q} }

type transactionRepo struct{ q sqlc.Querier }

func (r *transactionRepo) Create(ctx context.Context, tx pgx.Tx, rec TransactionRecord) (TransactionRecord, error) {
	qtx := sqlc.New(tx)
	unitCost, err := numericFromDecimal(rec.UnitCostDecimal)
	if err != nil {
		return TransactionRecord{}, err
	}
	row, err := qtx.CreateTransaction(ctx, sqlc.CreateTransactionParams{
		TransactionID:     rec.TransactionID,
		TxRequestID:       rec.TxRequestID,
		TenantID:          rec.TenantID,
		AgentID:           rec.AgentID,
		ResourceID:        rec.ResourceID,
		OfferID:           rec.OfferID,
		AgentIdentityHash: rec.AgentIdentityHash,
		SignedUrlHash:     rec.SignedURLHash,
		Expiry:            pgtype.Timestamptz{Time: rec.Expiry, Valid: true},
		BillingID:         pgText(rec.BillingID),
		UnitCost:          unitCost,
		Currency:          rec.Currency,
		ConsumedUnit:      pgText(rec.ConsumedUnit),
		DenialReason:      nullDenial(rec.DenialReason),
	})
	if err != nil {
		return TransactionRecord{}, fmt.Errorf("create transaction: %w", err)
	}
	return transactionFromRow(row), nil
}

// CreateForOffer projects a PersistTxIntent onto a TransactionRecord and
// delegates to Create. The repo owns the field-mapping so the service no
// longer constructs TransactionRecord literals at the call site.
func (r *transactionRepo) CreateForOffer(
	ctx context.Context, tx pgx.Tx, intent PersistTxIntent,
) (TransactionRecord, error) {
	return r.Create(ctx, tx, TransactionRecord{
		TransactionID:     intent.TransactionID,
		TxRequestID:       intent.TxRequestID,
		TenantID:          intent.TenantID,
		AgentID:           intent.AgentID,
		ResourceID:        intent.ResourceID,
		OfferID:           intent.OfferID,
		AgentIdentityHash: intent.AgentIdentityHash,
		SignedURLHash:     intent.SignedURLHash,
		Expiry:            intent.Expiry,
		BillingID:         intent.BillingID,
		UnitCostDecimal:   intent.UnitCostDecimal,
		Currency:          intent.Currency,
	})
}

func (r *transactionRepo) ByRequestID(ctx context.Context, txRequestID string) (TransactionRecord, error) {
	row, err := r.q.GetTransactionByRequestID(ctx, txRequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TransactionRecord{}, ErrTransactionNotFound
		}
		return TransactionRecord{}, fmt.Errorf("get transaction by request id: %w", err)
	}
	return transactionFromRow(row), nil
}

func transactionFromRow(row sqlc.RampTransactionLog) TransactionRecord {
	rec := TransactionRecord{
		TransactionID:     row.TransactionID,
		TxRequestID:       row.TxRequestID,
		TenantID:          row.TenantID,
		AgentID:           row.AgentID,
		ResourceID:        row.ResourceID,
		OfferID:           row.OfferID,
		AgentIdentityHash: row.AgentIdentityHash,
		SignedURLHash:     row.SignedUrlHash,
		BillingID:         textOrEmpty(row.BillingID),
		Currency:          row.Currency,
		ConsumedUnit:      textOrEmpty(row.ConsumedUnit),
	}
	if row.Expiry.Valid {
		rec.Expiry = row.Expiry.Time
	}
	if dec, err := decimalFromNumeric(row.UnitCost); err == nil {
		rec.UnitCostDecimal = dec
	}
	if row.DenialReason.Valid {
		rec.DenialReason = string(row.DenialReason.RampDenialReason)
	}
	if row.CreatedAt.Valid {
		rec.CreatedAt = row.CreatedAt.Time
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
