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
	IdempotencyKey    string
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
	// ResultPayload is the serialized rampv1.TransactionResultItem built for the
	// ExecuteTransaction response, persisted on the row so a replayed
	// idempotency_key returns the original result verbatim. Nil for legacy
	// (pre-migration) rows, which fall back to the AlreadyExists replay refusal.
	ResultPayload []byte
}

// PersistTxIntent carries the fields needed to mint a transaction-log row
// AND its companion reporting-obligation row in the same transaction. The
// service builds the intent once and both repos consume their own subset;
// each repo owns the column-shape for its table.
type PersistTxIntent struct {
	// Identifiers
	TransactionID  string
	IdempotencyKey string
	ObligationID   string

	// Tenant / caller binding
	TenantID string
	AgentID  string

	// Catalog binding: resource_id is the resolved catalog entry; offer_id is
	// the presented signed offer's own per-offer UUID. Distinct values.
	ResourceID string
	OfferID    string

	// Audit + signed-URL evidence
	AgentIdentityHash []byte
	SignedURLHash     []byte
	Expiry            time.Time

	// ResultPayload is the serialized rampv1.TransactionResultItem for this item,
	// persisted on the transaction_log row so a replay returns it verbatim.
	ResultPayload []byte

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
	ByIdempotencyKey(ctx context.Context, idempotencyKey string) (TransactionRecord, error)
	// ByID returns the transaction with the given public transaction_id (the
	// value the resolve / ExecuteTransaction response returns). It is the
	// production read path for observing a persisted transaction by its id —
	// the surface tests assert through instead of a raw transaction_log SELECT.
	ByID(ctx context.Context, transactionID string) (TransactionRecord, error)
	// ClaimRequest durably claims (agentID, idempotencyKey) for the item set
	// itemsDigest identifies, before any item bills or persists. won=true means
	// this call inserted the claim (a fresh request). won=false means the key
	// was already claimed by this agent; storedDigest is the digest of the item
	// set it was first used with, so the caller can tell an exact retry from a
	// reuse with different items. The claim is what ties a retried request to
	// its original now that offer_id is a random per-offer UUID — the derived
	// per-item keys of a re-discovered offer never match the original rows.
	ClaimRequest(
		ctx context.Context, agentID, idempotencyKey string, itemsDigest []byte,
	) (won bool, storedDigest []byte, err error)
	// FinalizeRequest stores the finalized request-level response payload on
	// the claim, write-once: a claim whose payload is already set is left
	// untouched and won=false is returned (the first finalization is
	// immutable; the caller must then read and serve the stored winner). The
	// affected-row count is the won signal — it is never ignored.
	FinalizeRequest(ctx context.Context, agentID, idempotencyKey string, responsePayload []byte) (won bool, err error)
	// RequestResponse returns the finalized response payload stored on the
	// claim, or nil when the claim does not exist or has not been finalized.
	RequestResponse(ctx context.Context, agentID, idempotencyKey string) ([]byte, error)
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
		IdempotencyKey:    rec.IdempotencyKey,
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
		ResultPayload:     rec.ResultPayload,
	})
	if err != nil {
		return TransactionRecord{}, fmt.Errorf("create transaction: %w", err)
	}
	return transactionFromRow(row)
}

// CreateForOffer projects a PersistTxIntent onto a TransactionRecord and
// delegates to Create. The repo owns the field-mapping so the service no
// longer constructs TransactionRecord literals at the call site.
func (r *transactionRepo) CreateForOffer(
	ctx context.Context, tx pgx.Tx, intent PersistTxIntent,
) (TransactionRecord, error) {
	return r.Create(ctx, tx, TransactionRecord{
		TransactionID:     intent.TransactionID,
		IdempotencyKey:    intent.IdempotencyKey,
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
		ResultPayload:     intent.ResultPayload,
	})
}

func (r *transactionRepo) ByIdempotencyKey(ctx context.Context, idempotencyKey string) (TransactionRecord, error) {
	row, err := r.q.GetTransactionByIdempotencyKey(ctx, idempotencyKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TransactionRecord{}, ErrTransactionNotFound
		}
		return TransactionRecord{}, fmt.Errorf("get transaction by idempotency key: %w", err)
	}
	return transactionFromRow(row)
}

func (r *transactionRepo) ByID(ctx context.Context, transactionID string) (TransactionRecord, error) {
	row, err := r.q.GetTransactionByID(ctx, transactionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TransactionRecord{}, ErrTransactionNotFound
		}
		return TransactionRecord{}, fmt.Errorf("get transaction by id: %w", err)
	}
	return transactionFromRow(row)
}

func (r *transactionRepo) ClaimRequest(
	ctx context.Context, agentID, idempotencyKey string, itemsDigest []byte,
) (bool, []byte, error) {
	rows, err := r.q.InsertTransactionRequestClaim(ctx, sqlc.InsertTransactionRequestClaimParams{
		AgentID: agentID, IdempotencyKey: idempotencyKey, ItemsDigest: itemsDigest,
	})
	if err != nil {
		return false, nil, fmt.Errorf("claim transaction request: %w", err)
	}
	if rows == 1 {
		return true, nil, nil
	}
	// Lost the insert: the claim already exists. Claims are append-only, so the
	// read-after-lost-insert cannot miss.
	claim, err := r.q.GetTransactionRequestClaim(ctx, sqlc.GetTransactionRequestClaimParams{
		AgentID: agentID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return false, nil, fmt.Errorf("read transaction request claim: %w", err)
	}
	return false, claim.ItemsDigest, nil
}

func (r *transactionRepo) FinalizeRequest(
	ctx context.Context, agentID, idempotencyKey string, responsePayload []byte,
) (bool, error) {
	// Guarded on response_payload IS NULL: zero rows affected means the claim
	// is already finalized (a concurrent finalizer won) or absent.
	rows, err := r.q.FinalizeTransactionRequestClaim(ctx, sqlc.FinalizeTransactionRequestClaimParams{
		AgentID: agentID, IdempotencyKey: idempotencyKey, ResponsePayload: responsePayload,
	})
	if err != nil {
		return false, fmt.Errorf("finalize transaction request claim: %w", err)
	}
	return rows == 1, nil
}

func (r *transactionRepo) RequestResponse(
	ctx context.Context, agentID, idempotencyKey string,
) ([]byte, error) {
	claim, err := r.q.GetTransactionRequestClaim(ctx, sqlc.GetTransactionRequestClaimParams{
		AgentID: agentID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read transaction request claim response: %w", err)
	}
	return claim.ResponsePayload, nil
}

func transactionFromRow(row sqlc.RampTransactionLog) (TransactionRecord, error) {
	rec := TransactionRecord{
		TransactionID:     row.TransactionID,
		IdempotencyKey:    row.IdempotencyKey,
		TenantID:          row.TenantID,
		AgentID:           row.AgentID,
		ResourceID:        row.ResourceID,
		OfferID:           row.OfferID,
		AgentIdentityHash: row.AgentIdentityHash,
		SignedURLHash:     row.SignedUrlHash,
		BillingID:         textOrEmpty(row.BillingID),
		Currency:          row.Currency,
		ConsumedUnit:      textOrEmpty(row.ConsumedUnit),
		ResultPayload:     row.ResultPayload,
	}
	if row.Expiry.Valid {
		rec.Expiry = row.Expiry.Time
	}
	// Propagate the NUMERIC decode error rather than swallowing it: a money field
	// must never be silently zeroed by a decode failure.
	dec, err := decimalFromNumeric(row.UnitCost)
	if err != nil {
		return TransactionRecord{}, fmt.Errorf("decode unit_cost for transaction %q: %w", row.TransactionID, err)
	}
	rec.UnitCostDecimal = dec
	if row.DenialReason.Valid {
		rec.DenialReason = string(row.DenialReason.RampDenialReason)
	}
	if row.CreatedAt.Valid {
		rec.CreatedAt = row.CreatedAt.Time
	}
	return rec, nil
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
