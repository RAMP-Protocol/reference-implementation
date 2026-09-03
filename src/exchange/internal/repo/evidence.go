package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// EvidenceRecord is the append-once evidence captured for a successfully
// executed transaction item: the full signed offer, both parties' signatures,
// both verifying public keys, and the delivered URL. Every field is what a third
// party needs to re-verify BOTH signatures from the stored row alone, with no
// access to a live service or key registry.
//
// WHY each column is shaped the way it is — the provenance taxonomy, why the
// signed bytes are stored rather than re-derived, why public keys are stored
// rather than key ids — lives in ONE place: the migration `000024` header.
// The notes below
// state what a field IS, not why, so the reasoning cannot rot into five
// disagreeing copies as the design moves.
//
// One struct serves both directions, like TransactionRecord: on the write path
// the caller supplies the payload and TransactionID / TenantID / CreatedAt are
// left zero (CreateForOffer takes the keys separately and the database supplies
// the timestamp); on the read path it carries the full row.
type EvidenceRecord struct {
	TransactionID string
	TenantID      string

	// Exchange side (the signed offer).
	//
	// OfferID is the signed Offer.offer_id — the presented offer's own random
	// per-offer UUID, the same value transaction_log.offer_id stores (the
	// catalog resource identity is transaction_log.resource_id, a distinct
	// value). It is duplicated here so an evidence row reads standalone,
	// without a join.
	OfferID                  string
	OfferJSON                []byte // protojson of the full offer; presentational, queryable
	OfferCanonicalBytes      []byte // verbatim JCS bytes the Exchange signature covered
	OfferSignature           string // Exchange Ed25519 signature (hex)
	OfferSignatureAlgorithm  string // server-derived, not the wire label
	ExchangeSigningPublicKey []byte // 32-byte Ed25519 key that verifies OfferSignature

	// Agent side (the acceptance).
	AgentAcceptanceSignature          string // agent Ed25519 signature (hex)
	AgentAcceptanceCanonicalBytes     []byte // verbatim JCS bytes the acceptance covered
	AgentAcceptanceSignatureAlgorithm string // server-derived, not the wire label
	// The four acceptance-payload inputs, kept alongside the bytes so a third
	// party can rebuild and audit them rather than take the bytes on trust.
	RequesterID           string
	RequesterDomain       string
	RequestIdempotencyKey string // request-level key the acceptance signed
	AgentPublicKey        []byte // 32-byte Ed25519 key that verifies the acceptance
	// AgentDiscoveryURL is the anchored well-known directory AgentPublicKey was
	// pinned from. Empty when the agent has no directory anchor — absence is ''
	// here and NULL in ramp.agents; see the migration header.
	AgentDiscoveryURL string

	// Delivery + correlation. Covered by neither signature.
	SignedURLFull string  // full delivered signed URL, not just its hash
	RequestID     *string // X-Request-ID correlation; nil → SQL NULL
	// RequestIDMinted is true when this Exchange minted RequestID, false when it
	// was taken verbatim from the caller's header. nil exactly when RequestID is
	// nil; the two are coupled by a table CHECK.
	RequestIDMinted *bool
	CreatedAt       time.Time
}

// EvidenceRepo is the append-once evidence store. CreateForOffer takes an
// explicit pgx.Tx so the evidence row commits in the same transaction as the
// transaction_log + obligation writes (Architecture Rule 7).
//
// Reads come in two shapes. ByTransaction is the default and the one every
// tenant-facing caller uses; it follows the tree's By<OtherKey>(ctx, tenantID, k)
// shape, so the tenant scope is the first argument everywhere.
// ByTransactionCrossTenant exists for the operator admin plane, which has no
// per-tenant scope (ADR-022), and for the cross-tenant reconciliation sweep
// (ADR-011 D2); its call sites carry the admin:cross_tenant marker.
type EvidenceRepo interface {
	// CreateForOffer takes the two keys and the record rather than the shared
	// PersistTxIntent its TransactionRepo and ObligationRepo siblings consume.
	// The intent describes the transaction_log + obligation shape; carrying a
	// whole EvidenceRecord on it would hand the full offer, both signatures and
	// both public keys to two repos that must ignore them, and make an
	// evidence-shape change recompile and re-test their paths. It returns a bare
	// error, unlike those siblings: the caller already holds every persisted
	// value and the database assigns nothing back.
	CreateForOffer(ctx context.Context, tx pgx.Tx, transactionID, tenantID string, e EvidenceRecord) error
	ByTransaction(ctx context.Context, tenantID, transactionID string) (EvidenceRecord, error)
	ByTransactionCrossTenant(ctx context.Context, transactionID string) (EvidenceRecord, error)
}

// ErrEvidenceNotFound signals that no evidence row exists for a transaction_id.
var ErrEvidenceNotFound = errors.New("repo: transaction evidence not found")

// NewEvidenceRepo composes an EvidenceRepo over the sqlc.Querier (used for
// reads; the write binds a tx-scoped querier via sqlc.New(tx)).
func NewEvidenceRepo(q sqlc.Querier) EvidenceRepo { return &evidenceRepo{q: q} }

type evidenceRepo struct{ q sqlc.Querier }

func (r *evidenceRepo) CreateForOffer(
	ctx context.Context, tx pgx.Tx, transactionID, tenantID string, e EvidenceRecord,
) error {
	err := sqlc.New(tx).CreateEvidence(ctx, sqlc.CreateEvidenceParams{
		TransactionID:                     transactionID,
		TenantID:                          tenantID,
		OfferID:                           e.OfferID,
		OfferJson:                         e.OfferJSON,
		OfferCanonicalBytes:               e.OfferCanonicalBytes,
		OfferSignature:                    e.OfferSignature,
		OfferSignatureAlgorithm:           e.OfferSignatureAlgorithm,
		ExchangeSigningPublicKey:          e.ExchangeSigningPublicKey,
		AgentAcceptanceSignature:          e.AgentAcceptanceSignature,
		AgentAcceptanceCanonicalBytes:     e.AgentAcceptanceCanonicalBytes,
		AgentAcceptanceSignatureAlgorithm: e.AgentAcceptanceSignatureAlgorithm,
		RequesterID:                       e.RequesterID,
		RequesterDomain:                   e.RequesterDomain,
		RequestIdempotencyKey:             e.RequestIdempotencyKey,
		AgentPublicKey:                    e.AgentPublicKey,
		AgentDiscoveryUrl:                 e.AgentDiscoveryURL,
		SignedUrlFull:                     e.SignedURLFull,
		RequestID:                         pgTextPtr(e.RequestID),
		RequestIDMinted:                   pgBoolPtr(e.RequestIDMinted),
	})
	if err != nil {
		return fmt.Errorf("create transaction evidence: %w", err)
	}
	return nil
}

func (r *evidenceRepo) ByTransaction(
	ctx context.Context, tenantID, transactionID string,
) (EvidenceRecord, error) {
	row, err := r.q.GetEvidenceByTenantAndTransactionID(ctx, sqlc.GetEvidenceByTenantAndTransactionIDParams{
		TenantID:      tenantID,
		TransactionID: transactionID,
	})
	if err != nil {
		return EvidenceRecord{}, wrapEvidenceReadError(err)
	}
	return evidenceFromRow(row), nil
}

func (r *evidenceRepo) ByTransactionCrossTenant(ctx context.Context, transactionID string) (EvidenceRecord, error) {
	// admin:cross_tenant — intentional global read; see the EvidenceRepo doc.
	row, err := r.q.GetEvidenceByTransactionIDCrossTenant(ctx, transactionID)
	if err != nil {
		return EvidenceRecord{}, wrapEvidenceReadError(err)
	}
	return evidenceFromRow(row), nil
}

func wrapEvidenceReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEvidenceNotFound
	}
	return fmt.Errorf("get transaction evidence: %w", err)
}

func evidenceFromRow(row sqlc.RampTransactionEvidence) EvidenceRecord {
	rec := EvidenceRecord{
		TransactionID:                     row.TransactionID,
		TenantID:                          row.TenantID,
		OfferID:                           row.OfferID,
		OfferJSON:                         row.OfferJson,
		OfferCanonicalBytes:               row.OfferCanonicalBytes,
		OfferSignature:                    row.OfferSignature,
		OfferSignatureAlgorithm:           row.OfferSignatureAlgorithm,
		ExchangeSigningPublicKey:          row.ExchangeSigningPublicKey,
		AgentAcceptanceSignature:          row.AgentAcceptanceSignature,
		AgentAcceptanceCanonicalBytes:     row.AgentAcceptanceCanonicalBytes,
		AgentAcceptanceSignatureAlgorithm: row.AgentAcceptanceSignatureAlgorithm,
		RequesterID:                       row.RequesterID,
		RequesterDomain:                   row.RequesterDomain,
		RequestIdempotencyKey:             row.RequestIdempotencyKey,
		AgentPublicKey:                    row.AgentPublicKey,
		AgentDiscoveryURL:                 row.AgentDiscoveryUrl,
		SignedURLFull:                     row.SignedUrlFull,
		RequestID:                         textFromPG(row.RequestID),
		RequestIDMinted:                   boolFromPG(row.RequestIDMinted),
	}
	if row.CreatedAt.Valid {
		rec.CreatedAt = row.CreatedAt.Time
	}
	return rec
}
