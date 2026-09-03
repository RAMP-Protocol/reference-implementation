package transport

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// TransactionEvidencePath is the operator evidence read, served on the internal
// admin listener only. It is a plain JSON GET rather than a protocol RPC: the
// RAMP protocol has no read surface for evidence and gains none here, and the
// only consumer is the operator tooling that renders the chain.
//
// The literal is owned by evidenceview, beside the shape this route serves, so
// the renderer in the other binary requests the same route this one mounts.
// The name stays here because callers already use it.
const TransactionEvidencePath = evidenceview.Path

// transactionEvidenceHandler serves GET /ops/transaction-evidence?tx=<id>.
//
// The response is served exactly as persisted — no value in it is recomputed —
// because a rendered ledger is only evidence if it shows what the store holds.
//
// Only tx is validated, and only for shape. There is no request-validation layer
// on this route, and it needs none: every other value in the response comes off
// an append-once row, so a rule over one could only refuse to state a fact that
// is already stored.
func transactionEvidenceHandler(svc *service.EvidenceReadService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The request-scoped logger, so the read-failure line below carries
		// request_id and joins to the request that caused it.
		// RequestIDMiddleware put it in the context.
		requestLogger := reqctx.FromContext(r.Context())

		// transaction_id is a server-minted UUID, so anything that is not one
		// cannot name a row. Refusing it here separates "you asked wrongly" from
		// "nothing matched", which is the difference between 400 and 404.
		txID := r.URL.Query().Get("tx")
		if uuid.Validate(txID) != nil {
			http.Error(w, "query parameter tx must be a transaction id", http.StatusBadRequest)
			return
		}

		view, err := svc.TransactionEvidenceCrossTenant(r.Context(), txID)
		if err != nil {
			var domain *exchange.Error
			if errors.As(err, &domain) && domain.Kind == exchange.KindNotFound {
				http.Error(w, "no evidence for that transaction", http.StatusNotFound)
				return
			}
			requestLogger.ErrorContext(r.Context(), "transaction evidence read failed",
				slog.String("transaction_id", txID), "err", err)
			http.Error(w, "transaction evidence unavailable", http.StatusInternalServerError)
			return
		}

		// Both headers are set before the first write, because the first write
		// sends them. Content-Type is explicit: without it net/http sniffs the
		// body and JSON sniffs as text/plain. no-store because the body carries
		// signatures, public keys and a correlation id.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// The encode error is discarded on purpose. The 200 and the headers are
		// already sent, so nothing can be answered — and the error is a poor
		// signal besides: it reports only a SYNCHRONOUS write failure, while a
		// client that disappears mid-response usually does so after Encode has
		// already returned into a socket buffer. A line that fires for a minority
		// of the cases it names is worse than none, because its absence proves
		// nothing. The caller sees the real symptom either way, as a decode
		// failure over a truncated body.
		_ = json.NewEncoder(w).Encode(evidenceResponse(view))
	}
}

// evidenceResponse projects the stored rows onto the shared JSON view.
func evidenceResponse(view service.EvidenceView) evidenceview.Response {
	return evidenceview.Response{
		Evidence:         evidenceJSON(view.Evidence),
		TransactionState: transactionStateJSON(view.Transaction),
		ObligationState:  obligationStateJSON(view.Obligation),
	}
}

// evidenceJSON projects the stored evidence row.
//
// The full signed URL is deliberately absent. On the CloudFront-RSA path a
// signed URL stays a live bearer capability until it expires, so serving it on a
// forensic read would hand out delivery access; the join to what the edge served
// is the URL's digest on the transaction state, which both sides compute and
// neither can redeem.
func evidenceJSON(e repo.EvidenceRecord) *evidenceview.Evidence {
	return &evidenceview.Evidence{
		TransactionID: e.TransactionID,
		TenantID:      e.TenantID,
		OfferID:       e.OfferID,
		CreatedAt:     e.CreatedAt,

		OfferSig:                 e.OfferSignature,
		OfferSigAlgorithm:        e.OfferSignatureAlgorithm,
		OfferCanonicalBytes:      e.OfferCanonicalBytes,
		ExchangeSigningPublicKey: e.ExchangeSigningPublicKey,

		AgentAcceptanceSignature:          e.AgentAcceptanceSignature,
		AgentAcceptanceSignatureAlgorithm: e.AgentAcceptanceSignatureAlgorithm,
		AgentAcceptanceCanonicalBytes:     e.AgentAcceptanceCanonicalBytes,
		AgentPublicKey:                    e.AgentPublicKey,

		RequesterID:           e.RequesterID,
		RequesterDomain:       e.RequesterDomain,
		RequestIdempotencyKey: e.RequestIdempotencyKey,

		// The correlation id and its provenance travel together or not at all: a
		// provenance flag without the id it describes says nothing, and an id
		// without it cannot be told apart from one the caller supplied. The
		// stored columns are already coupled by a table CHECK.
		RequestID:       e.RequestID,
		RequestIDMinted: e.RequestIDMinted,
	}
}

// transactionStateJSON projects the transaction-log facts beside the evidence
// row. There is no status field to carry: transaction_log has no status column,
// and the existence of an evidence row IS the statement that the transaction
// succeeded.
func transactionStateJSON(t repo.TransactionRecord) *evidenceview.TransactionState {
	return &evidenceview.TransactionState{
		IdempotencyKey:  t.IdempotencyKey,
		SignedURLHash:   t.SignedURLHash,
		SignedURLExpiry: timeOrNil(t.Expiry),
	}
}

// obligationStateJSON projects the reporting obligation, or nil when the
// transaction minted none.
func obligationStateJSON(o *repo.Obligation) *evidenceview.ObligationState {
	if o == nil {
		return nil
	}
	// The persisted state word is carried verbatim, with no mapping. A renderer
	// prints what the store holds; translating it here would let the displayed
	// word differ from the row under dispute.
	state := string(o.State)
	// The outcome word is carried verbatim for the same reason as the state
	// word above, and is empty until a report has been validated.
	outcome := string(o.ValidationOutcome)
	return &evidenceview.ObligationState{
		State:             state,
		ConsumedQuantity:  stringOrNil(o.ConsumedQuantity),
		WindowEnd:         o.Deadline,
		FulfilledAt:       timeOrNil(o.ReceivedAt),
		CreatedAt:         o.CreatedAt,
		ValidationOutcome: stringOrNil(outcome),
		ValidatedAt:       timeOrNil(o.ValidatedAt),
	}
}

// stringOrNil omits an empty decimal quantity rather than sending "", so "no
// report accepted yet" stays distinguishable from a report of zero units.
func stringOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// timeOrNil omits a zero time rather than sending it, because the zero time
// renders as year one and reads like a real instant.
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
