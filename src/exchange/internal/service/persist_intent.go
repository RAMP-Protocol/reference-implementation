package service

import (
	"context"
	"errors"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/encoding/protojson"
	protobuf "google.golang.org/protobuf/proto" // aliased: tests define a local generic proto[T] helper that shadows the package name

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// buildPersistIntent assembles what the repos consume: the ids, the
// agent-identity hash, the evidence, and the obligation's deadline derived from
// the window the caller already planned — so persistTransaction reduces to
// "build, run tx, call the repos".
//
// The obligation's shape (window, required fields, tolerance, and whether one is
// owed at all) arrives on persistInput.plan rather than being derived here. The
// agent was handed those same values in its result item before this ran, and a
// second derivation is a second chance to disagree with them.
//
// The evidence record is returned ALONGSIDE the intent rather than embedded in
// it: the intent is the transaction_log + obligation shape, and threading a whole
// second aggregate through it hands the evidence payload to two repos that must
// ignore it. It takes no context — every value it persists arrives on
// persistInput, including the request correlation the caller resolved at the
// service boundary.
func (s *ExchangeService) buildPersistIntent(in persistInput) (repo.PersistTxIntent, repo.EvidenceRecord, error) {
	evidence, err := s.offerEvidence(in)
	if err != nil {
		return repo.PersistTxIntent{}, repo.EvidenceRecord{}, err
	}
	return repo.PersistTxIntent{
		TransactionID:  in.transactionID,
		IdempotencyKey: in.idempotencyKey,
		ResultPayload:  in.resultPayload,
		ObligationID:   uuid.NewString(),
		TenantID:       in.tenant.ID,
		AgentID:        in.agentID,
		// Two distinct identities, recorded unconflated: resource_id is the
		// resolved catalog entry the delivery binds to; offer_id is the
		// presented signed offer's own id (a random per-offer UUID).
		ResourceID:        in.entry.ResourceID,
		OfferID:           in.item.GetOffer().GetOfferId(),
		AgentIdentityHash: in.agentHash,
		SignedURLHash:     in.signed.Hash,
		Expiry:            in.signed.Expiry,
		BillingID:         in.auth.BillingID,
		UnitCostDecimal:   in.pricing.UnitCost.String(),
		Currency:          in.pricing.Currency,
		State:             repo.ObligationStatePending,
		WindowSeconds:     in.plan.WindowSeconds,
		Deadline:          s.clk.Now().Add(time.Duration(in.plan.WindowSeconds) * time.Second),
		RequiredFields:    in.plan.RequiredFields,
		EstimatedQuantity: int64(in.pricing.EstQty),
		QuantityTolerance: in.plan.QuantityTolerance,
	}, evidence, nil
}

// offerEvidence assembles the append-once evidence for the transaction_evidence
// row: the verified offer serialized two ways — human-auditable protojson and
// the verbatim RFC 8785 canonical bytes the Exchange signature covered — plus
// both parties' signatures, both verifying public keys, the delivered URL, and
// the acceptance-payload inputs (requester id/domain + the REQUEST-level
// idempotency key, not the derived per-item key) a third party needs to rebuild
// and re-verify the acceptance from the row alone.
//
// Neither canonical-bytes column is computed here. Both arrive on persistInput
// from the site that VERIFIED them, so what the row stores is what was checked
// rather than a second derivation that could quietly disagree with it.
//
// Both signature_algorithm values are server-derived constants rather than the
// presented labels: the canonical signing payloads clear signature_algorithm
// before canonicalising, so a caller can present any label under an otherwise
// valid signature. Verification bottoms out in ed25519.Verify on both legs, so
// the constant is the true statement about what was checked — and the row, being
// append-once, would carry a poisoned claim uncorrectably.
//
// The two constants come from different packages on purpose, and the asymmetry
// is the point: this Exchange SIGNED the offer, so the offer's label is its own
// signer's constant, while the AGENT signed the acceptance, so that label is the
// protocol's. Collapsing them to one spelling would erase which party each claim
// speaks for. They hold the same string today only because the signer's constant
// is defined as the protocol's.
func (s *ExchangeService) offerEvidence(in persistInput) (repo.EvidenceRecord, error) {
	offer := in.item.GetOffer()
	offerJSON, err := marshalOfferForEvidence(offer)
	if err != nil {
		return repo.EvidenceRecord{}, err
	}
	requester := in.req.GetRequester()
	return repo.EvidenceRecord{
		OfferID:                           offer.GetOfferId(),
		OfferJSON:                         offerJSON,
		OfferCanonicalBytes:               in.offerCanonicalBytes,
		OfferSignature:                    offer.GetSignature(),
		OfferSignatureAlgorithm:           signing.SignatureAlgorithm,
		ExchangeSigningPublicKey:          s.offerSigner.PublicKey(),
		AgentAcceptanceSignature:          in.item.GetAgentAcceptance().GetSignature(),
		AgentAcceptanceCanonicalBytes:     in.acceptanceCanonicalBytes,
		AgentAcceptanceSignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
		RequesterID:                       requester.GetId(),
		RequesterDomain:                   requester.GetDomain(),
		RequestIdempotencyKey:             in.req.GetIdempotencyKey(),
		AgentPublicKey:                    in.agentPublicKey,
		AgentDiscoveryURL:                 in.agentDiscoveryURL,
		SignedURLFull:                     in.signed.URL,
		RequestID:                         in.correlation.id,
		RequestIDMinted:                   in.correlation.minted,
	}, nil
}

// marshalOfferForEvidence renders the verified offer to proto-JSON for the
// human-auditable offer_json column, with signature_algorithm normalized to the
// Exchange constant. The presented label is outside signature coverage, so
// echoing it would let a caller write an unverified claim into the column a
// dispute reads — one no cross-check can catch, since canonicalisation clears
// that very field. offer.signature itself is echoed verbatim: it IS verified,
// and it is the anchor the agent's acceptance signs over.
//
// The marshal options here are LOCAL and deliberately not the SDK's canonical
// signing set. offer_json is presentational: it exists to be read and queried,
// and offer_canonical_bytes remains the arbiter of what was signed. Pinning
// UseProtoNames keeps the JSON keys matching the proto field names a reader
// expects; if the SDK ever changes its canonical option set, this column's
// rendering deliberately does not follow, and the integration test's
// re-canonicalisation cross-check still binds offer_json to the signed bytes
// because protojson accepts either field-name form on the way back in.
func marshalOfferForEvidence(offer *rampv1.Offer) ([]byte, error) {
	clone, ok := protobuf.Clone(offer).(*rampv1.Offer)
	if !ok {
		return nil, exchange.Newf(exchange.KindInternal, "offer clone type mismatch")
	}
	clone.SignatureAlgorithm = signing.SignatureAlgorithm
	out, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(clone)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "marshal offer json")
	}
	return out, nil
}

// requestCorrelation is the correlation id persisted with an evidence row and
// the provenance of that id, resolved TOGETHER so the pair the evidence table
// couples in a CHECK can never disagree.
//
// An absent id has no provenance to state: nothing routed a request-id setter
// into the context, which happens on any driver that is not behind the request-id
// middleware (a service-level test, a queue consumer, a replay tool). A present
// id whose provenance was never recorded reads as caller-supplied — the
// conservative direction, since claiming it was minted would assert a
// trustworthiness nobody established into a row that cannot be corrected.
type requestCorrelation struct {
	id     *string
	minted *bool
}

// resolveRequestCorrelation reads the pair off the context ONCE, at the service
// boundary. Everything downstream receives it as data on persistInput, the same
// shape the admin plane already uses (its handler builds AdminCaller.RequestID
// at the transport edge). Persistence therefore never reaches into ambient state
// for a value it writes.
func resolveRequestCorrelation(ctx context.Context) requestCorrelation {
	raw := reqctx.RequestID(ctx)
	if raw == "" {
		return requestCorrelation{}
	}
	minted, _ := reqctx.RequestIDMinted(ctx)
	return requestCorrelation{id: &raw, minted: &minted}
}

type persistInput struct {
	tenant  repo.Tenant
	entry   repo.CatalogEntry
	pricing PricingDoc
	// plan is the obligation shape the caller already derived and already told
	// the agent about in the result item. Passed in rather than recomputed here,
	// so the row written below and the ReportingObligation the agent holds state
	// the same window and the same field list by construction.
	plan obligationPlan
	req  *rampv1.TransactionRequest
	// item is THE item this persist is for. req is the per-item synthetic
	// request executeBatchItem projects, so req.items[0] happens to be the same
	// message today — but carrying the item explicitly keeps the evidence row
	// bound to its own offer by construction rather than by that invariant, so a
	// future caller handing over a multi-item req cannot silently record item 0's
	// offer, signature and acceptance on every row in the batch.
	item    *rampv1.TransactionItem
	agentID string
	auth    billing.AuthorizeResult
	signed  helpers.SignedURL
	// idempotencyKey is the durable dedup key written to
	// transaction_log.idempotency_key (TEXT UNIQUE). Every batch item carries the
	// DERIVED per-item key (idempotency_key+":"+offer_id) so N items under one
	// shared request key do not collide on the UNIQUE backstop.   It is
	// an Exchange-internal persistence key ONLY and never feeds
	// VerifyOfferAcceptance (which binds the request-level key).
	idempotencyKey string
	// agentHash is the 32-byte SHA-256 digest of the agent's RFC 7638
	// thumbprint, persisted to transaction_log.agent_identity_hash (ADR-013
	// 17.6). Same value whose base64url form rides in the URL's agent_id param.
	agentHash []byte
	// agentPublicKey is the raw 32-byte Ed25519 public key of the accepting agent
	// (the key verifyAgentAcceptance resolved and verified the acceptance
	// against), persisted verbatim to transaction_evidence.agent_public_key so the
	// acceptance re-verifies from the row with no agent-registry lookup —
	// rotation-safe, since the registry drops retired keys (ADR-003). agentHash
	// is a one-way thumbprint digest and cannot recover this key.
	agentPublicKey []byte
	// agentDiscoveryURL is the anchored well-known directory agentPublicKey was
	// pinned from. The registry overwrites a rotated key in place and keeps no
	// history, so the key alone proves only that SOME key signed; recording where
	// and when this Exchange obtained it is what lets the row speak to WHOSE key
	// it was.
	agentDiscoveryURL string
	// offerCanonicalBytes and acceptanceCanonicalBytes are the exact payloads the
	// two signatures were VERIFIED over, captured at their verify sites
	// (verifyPresentedOffer, verifyAgentAcceptance) and carried here unchanged.
	// They are inputs, not something persistence derives: re-deriving them here
	// would rebuild each payload from a separately assembled argument list, and a
	// divergence between what was checked and what was stored is invisible until a
	// dispute — in a row that can never be corrected.
	offerCanonicalBytes      []byte
	acceptanceCanonicalBytes []byte
	// correlation is the request id + provenance pair written to the evidence
	// row, resolved once at the service boundary and carried like every other
	// persisted value rather than read from the context down here.
	correlation requestCorrelation
	// transactionID is the public transaction_id minted by the caller BEFORE the
	// INSERT, so the per-item TransactionResultItem (which embeds it) can be
	// serialized into resultPayload and written on the SAME row in the same
	// transaction — making a replay a verbatim read of the persisted result.
	transactionID string
	// resultPayload is the serialized rampv1.TransactionResultItem for this item,
	// written into transaction_log.result_payload on the INSERT so a replayed
	// idempotency_key returns the original response without re-executing.
	resultPayload []byte
}

func (s *ExchangeService) persistTransaction(ctx context.Context, in persistInput) (repo.TransactionRecord, error) {
	intent, evidence, err := s.buildPersistIntent(in)
	if err != nil {
		return repo.TransactionRecord{}, err
	}
	var rec repo.TransactionRecord
	err = s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		created, err := s.transactions.CreateForOffer(ctx, tx, intent)
		if err != nil {
			return err
		}
		rec = created
		// A price whose metering is NONE owes no usage report, so no obligation
		// row is written and the execute gate has nothing to hold against the
		// agent later. The result item already told the agent the same thing.
		if in.plan.Required {
			if _, err := s.obligations.CreateForOffer(ctx, tx, intent); err != nil {
				return err
			}
		}
		// Evidence commits in the SAME transaction as the transaction_log +
		// obligation rows, after the transaction_log row exists (the evidence
		// FK on transaction_id) — one atomic ExecuteTransaction commit.
		return s.evidence.CreateForOffer(ctx, tx, intent.TransactionID, intent.TenantID, evidence)
	})
	if err != nil {
		return repo.TransactionRecord{}, classifyTxWriteError(err)
	}
	return rec, nil
}

// idempotencyUniqueConstraint is the UNIQUE constraint on transaction_log that
// makes a replayed idempotency_key the DURABLE dedup backstop (the in-memory LRU
// is only a fast-path cache). The name is load-bearing: migration 000001 created
// it inline on the column originally named tx_request_id, and migration 000016
// renamed only the COLUMN (to idempotency_key), NOT the constraint — so the name
// still reads tx_request_id. A match scoped to "idempotency_key" would never
// fire, and a bare-SQLSTATE match would wrongly classify an unrelated UNIQUE
// (e.g. catalog_uri_key) as an idempotency replay.
const idempotencyUniqueConstraint = "transaction_log_tx_request_id_key"

// pgUniqueViolation is SQLSTATE 23505 (unique_violation).
const pgUniqueViolation = "23505"

// classifyTxWriteError maps a transaction-write failure to its domain kind. A pg
// UNIQUE violation on the idempotency backstop is a REPLAY: the LRU missed (e.g.
// the row was written before a restart, so this process's cache is empty) but
// the durable row already exists. The stable client contract for a replay is
// AlreadyExists (KindIdempotent), not Internal — so on restart/failover a
// legitimate retry no longer drifts AlreadyExists -> Internal. Scoped to the
// constraint NAME (not bare SQLSTATE) so only the idempotency backstop is
// treated as a replay. The UNIQUE constraint remains the double-charge backstop
// either way; this only corrects the returned code.
func classifyTxWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) &&
		pgErr.Code == pgUniqueViolation &&
		pgErr.ConstraintName == idempotencyUniqueConstraint {
		return exchange.Wrap(exchange.KindIdempotent, err, "write transaction")
	}
	return exchange.Wrap(exchange.KindInternal, err, "write transaction")
}
