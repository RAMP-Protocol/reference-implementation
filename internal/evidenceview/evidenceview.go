// Package evidenceview is the JSON shape of the transaction-evidence read: the
// Exchange's admin handler writes it, the ramp-ledger renderer decodes it.
//
// One declaration serves both sides so a field cannot be added on the producer
// and silently missed by the consumer — the mismatch becomes a compile error
// rather than a field that renders empty. It holds no HTTP, no database and no
// service dependency, so both a service and an operator CLI can import it.
//
// The full signed URL is deliberately not part of this shape. On the
// CloudFront-RSA path a signed URL stays a live bearer capability until it
// expires, so serving it on a forensic read would hand out delivery access. The
// join between what the Exchange minted and what the edge worker served is
// SignedURLHash, a SHA-256 over the verbatim signed URL including its signature
// parameter, which both sides can compute and neither can redeem.
package evidenceview

import (
	"errors"
	"time"
)

// Path is the route the Exchange serves this shape on, and the route the
// ramp-ledger renderer requests it from. It is a plain JSON GET on the internal
// admin listener rather than an RPC: the protocol deliberately exposes no read
// surface for evidence, so this is an operator endpoint.
//
// It is declared here, beside the shape, because producer and consumer are
// different binaries. Two copies of the literal let a rename pass every test on
// both sides and then answer 404 at run time — which reads as a stale image or a
// misconfigured tunnel, not as a rename.
const Path = "/ops/transaction-evidence"

// Response is the whole read: the append-once evidence row, the transaction-log
// facts beside it, and the reporting obligation it minted if it minted one.
//
// The three members are pointers so a payload that omits one is a decode-time
// error rather than a zero value the renderer would describe in words. A value
// TransactionState missing from the JSON would leave SignedURLHash empty, and
// the renderer states that as "no signed URL: this transaction delivered
// directly" — a specific claim about what happened, made from nothing. Validate
// refuses that payload instead.
type Response struct {
	Evidence         *Evidence         `json:"evidence"`
	TransactionState *TransactionState `json:"transaction_state"`
	// ObligationState is optional, and the absence is reachable: a term whose
	// pricing carries PRICING_METERING_NONE is a one-time perpetual sale and
	// mints no obligation, so a transaction against it omits this object
	// entirely. A reader must state that absence rather than inventing a duty —
	// rendering a missing obligation as one in state "" is the failure this
	// shape exists to prevent. Validate therefore accepts a nil value.
	ObligationState *ObligationState `json:"obligation_state,omitempty"`
}

// ErrMissingEvidence reports a payload with no evidence object.
var ErrMissingEvidence = errors.New("evidenceview: evidence is required")

// ErrMissingTransactionState reports a payload with no transaction_state object.
var ErrMissingTransactionState = errors.New("evidenceview: transaction_state is required")

// ErrMissingEvidenceCreatedAt reports an evidence object with no created_at.
var ErrMissingEvidenceCreatedAt = errors.New("evidenceview: evidence.created_at is required")

// ErrMissingObligationWindowEnd reports an obligation object with no window_end.
var ErrMissingObligationWindowEnd = errors.New("evidenceview: obligation_state.window_end is required")

// ErrMissingObligationCreatedAt reports an obligation object with no created_at.
var ErrMissingObligationCreatedAt = errors.New("evidenceview: obligation_state.created_at is required")

// ErrPartialValidationOutcome reports an obligation object carrying exactly one
// of validation_outcome and validated_at.
var ErrPartialValidationOutcome = errors.New(
	"evidenceview: obligation_state.validation_outcome and validated_at are present together or absent together")

// ErrMissingObligationValidatedAt reports an obligation object whose
// validated_at is present but carries the zero time.
var ErrMissingObligationValidatedAt = errors.New(
	"evidenceview: obligation_state.validated_at is set but carries no instant")

// Validate checks the two required objects are present and that the timestamps
// which are never null carry a real instant. Call it once immediately after
// decoding; every reader downstream may then dereference Evidence and
// TransactionState, and print those timestamps, without a check of its own.
//
// The zero-time checks exist for the same reason the required objects are
// pointers. A missing created_at decodes to the zero time and prints as year
// one, which reads like a real instant and is a false statement on a surface
// whose only purpose is stating what happened. The producer always writes these
// fields, but this runs at the decode boundary, where a handler bug, a version
// skew or a truncated response is exactly what has to be caught.
func (r *Response) Validate() error {
	if r.Evidence == nil {
		return ErrMissingEvidence
	}
	if r.TransactionState == nil {
		return ErrMissingTransactionState
	}
	if r.Evidence.CreatedAt.IsZero() {
		return ErrMissingEvidenceCreatedAt
	}
	// An absent obligation is a fact about the transaction — a term whose
	// pricing carries PRICING_METERING_NONE mints none — so these run only
	// when one was sent.
	if r.ObligationState != nil {
		if r.ObligationState.WindowEnd.IsZero() {
			return ErrMissingObligationWindowEnd
		}
		if r.ObligationState.CreatedAt.IsZero() {
			return ErrMissingObligationCreatedAt
		}
		if err := r.ObligationState.validateOutcome(); err != nil {
			return err
		}
	}
	return nil
}

// validateOutcome holds ValidationOutcome and ValidatedAt to the coupling their
// field comments state: both present, or both absent. One without the other
// says a report was judged without saying when, or names an instant without
// saying what was decided, and a renderer would print either as a fact.
//
// The zero-time check is the same one CreatedAt gets, for the same reason: a
// set-but-zero ValidatedAt prints as year one and reads like a real instant.
func (o *ObligationState) validateOutcome() error {
	if (o.ValidationOutcome == nil) != (o.ValidatedAt == nil) {
		return ErrPartialValidationOutcome
	}
	if o.ValidatedAt != nil && o.ValidatedAt.IsZero() {
		return ErrMissingObligationValidatedAt
	}
	return nil
}

// Evidence is the stored evidence row: the signed offer, the agent's
// acceptance, both verifying public keys, and the correlation ids.
//
// Both canonical-bytes fields carry the verbatim bytes each signature covered,
// so a third party re-verifies from the row alone and the check survives any
// later change to how offers are canonicalized. Both signatures are hex
// strings, which is the form the protocol puts them in on the wire and the form
// the acceptance payload signs; the public keys are raw bytes, which
// encoding/json base64-encodes.
type Evidence struct {
	TransactionID string    `json:"transaction_id"`
	TenantID      string    `json:"tenant_id"`
	OfferID       string    `json:"offer_id"`
	CreatedAt     time.Time `json:"created_at"`

	OfferSig                 string `json:"offer_sig"`
	OfferSigAlgorithm        string `json:"offer_sig_algorithm"`
	OfferCanonicalBytes      []byte `json:"offer_canonical_bytes"`
	ExchangeSigningPublicKey []byte `json:"exchange_signing_public_key"`

	AgentAcceptanceSignature          string `json:"agent_acceptance_signature"`
	AgentAcceptanceSignatureAlgorithm string `json:"agent_acceptance_signature_algorithm"`
	AgentAcceptanceCanonicalBytes     []byte `json:"agent_acceptance_canonical_bytes"`
	AgentPublicKey                    []byte `json:"agent_public_key"`

	// The three acceptance-payload members kept beside the signed bytes, so a
	// reader can rebuild what was signed instead of trusting the bytes.
	RequesterID           string `json:"requester_id"`
	RequesterDomain       string `json:"requester_domain"`
	RequestIdempotencyKey string `json:"request_idempotency_key"`

	// RequestID is the X-Request-ID correlation value, and RequestIDMinted says
	// whether this Exchange generated it or took it verbatim from the caller's
	// header. The two are present together or absent together: the flag alone
	// describes nothing, and the id alone cannot be told apart from a
	// caller-supplied one.
	RequestID       *string `json:"request_id,omitempty"`
	RequestIDMinted *bool   `json:"request_id_minted,omitempty"`
}

// TransactionState is what the transaction-log row records about delivery.
// There is no status field because the log has no status column — the existence
// of an evidence row is itself the statement that the transaction succeeded.
type TransactionState struct {
	IdempotencyKey string `json:"idempotency_key"`
	// SignedURLHash is the SHA-256 over the verbatim signed URL. Empty when the
	// transaction delivered without minting one.
	SignedURLHash []byte `json:"signed_url_hash,omitempty"`
	// SignedURLExpiry is a pointer so an absent expiry is omitted rather than
	// sent as the zero time, which renders as year one and reads like a real
	// instant.
	SignedURLExpiry *time.Time `json:"signed_url_expiry,omitempty"`
}

// ObligationState is the reporting obligation the transaction minted.
type ObligationState struct {
	// State is the persisted vocabulary verbatim, with no mapping. A renderer
	// prints what the store holds; translating it here would let the displayed
	// word differ from the row under dispute.
	State string `json:"state"`
	// ConsumedQuantity is a decimal string because the column is
	// NUMERIC(20,8). Carrying it as a string cannot truncate a fractional
	// value, and nil means no report has been accepted yet — distinct from a
	// report of zero.
	ConsumedQuantity *string    `json:"consumed_quantity,omitempty"`
	WindowEnd        time.Time  `json:"window_end"`
	FulfilledAt      *time.Time `json:"fulfilled_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	// ValidationOutcome is the persisted outcome vocabulary verbatim, like
	// State, and nil until a report has been validated one way or the other.
	//
	// It is the latest reason a report was refused while its obligation stayed
	// PENDING, and it is the only such reason this route serves. Lateness is
	// not marked with an outcome of its own — a report is accepted however
	// late it is — so an obligation still PENDING after a report was filed
	// carries the reason here. That is the first thing an operator settling a
	// dispute asks, on a route whose whole purpose is saying what happened.
	//
	// It is the latest reason and not the history: the statement that records a
	// rejection updates the one obligation row, so a second refused report
	// overwrites the first outcome. The sequence of attempts is in the audit
	// log, which gets a row per rejection. An operator reconstructing what an
	// agent tried reads the log; this field says where the obligation stands
	// now.
	ValidationOutcome *string `json:"validation_outcome,omitempty"`
	// ValidatedAt is when the outcome above was decided, from the same service
	// clock as WindowEnd and FulfilledAt. Nil while no report has been
	// validated.
	ValidatedAt *time.Time `json:"validated_at,omitempty"`
}
