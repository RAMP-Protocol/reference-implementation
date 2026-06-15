package service

import (
	"context"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// maxTxRequestIDLen bounds the tx_request_id, which is threaded to the billing
// adapter as the idempotency key. 256 bytes is generous for any UUID/ULID/hash
// id while keeping the adapter dedup maps from growing by caller-supplied length.
const maxTxRequestIDLen = 256

// validateTxRequest checks the minimum envelope invariants. Identity is
// mandatory on every request: requester.id must be non-empty. The
// identity does not have to be registered with the exchange —
// resolveAgentID lazy-inserts unknown ids — but it MUST be present so
// the audit fingerprint, FK on transaction_log.agent_id, and downstream
// attribution have a non-anonymous handle to bind to.
func (s *ExchangeService) validateTxRequest(req *rampv1.TransactionRequest) error {
	if req == nil || req.GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "tx_request_id required")
	}
	// Cap the id length: it becomes the billing idempotency key, so an
	// unbounded id is an unbounded dedup-map entry at the adapter.
	if len(req.GetId()) > maxTxRequestIDLen {
		return exchange.Newf(exchange.KindInvalidRequest, "tx_request_id exceeds %d bytes", maxTxRequestIDLen)
	}
	if req.GetOfferId() == "" || req.GetOfferSignature() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "offer_id and offer_signature required")
	}
	if req.GetRequester() == nil {
		return exchange.Newf(exchange.KindInvalidRequest, "requester required")
	}
	if req.GetRequester().GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "requester.id required")
	}
	return nil
}

// idempotencyHit reports whether a tx_request_id was already processed.
// Implementation is an LRU bounded by cfg.IdempotencyLRU.
func (s *ExchangeService) idempotencyHit(txRequestID string) (string, bool) {
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	rec, ok := s.idemHit[txRequestID]
	return rec, ok
}

// idempotencyRecord stores the tx_request_id → transaction_id mapping,
// evicting the oldest entry when the LRU is full.
func (s *ExchangeService) idempotencyRecord(txRequestID, txID string) {
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if _, exists := s.idemHit[txRequestID]; exists {
		return
	}
	if len(s.idemSeq) >= s.cfg.IdempotencyLRU && s.cfg.IdempotencyLRU > 0 {
		oldest := s.idemSeq[0]
		s.idemSeq = s.idemSeq[1:]
		delete(s.idemHit, oldest)
	}
	s.idemHit[txRequestID] = txID
	s.idemSeq = append(s.idemSeq, txRequestID)
}

// verifyOffer rebuilds the same offer shape used at discovery time and
// verifies the provided signature against the Exchange's public key.
// Offers are stateless: no offer is stored server-side. The canonical payload
// (see signing.canonicalOfferPayload) intentionally excludes ExpiresAt and the
// signature itself, so a newly reissued offer at verify time produces the
// same bytes as the one discovered earlier.
func (s *ExchangeService) verifyOffer(entry repo.CatalogEntry, offerSig string) error {
	offer, err := s.buildOffer(entry)
	if err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "rebuild offer for verification")
	}
	if err := signing.VerifyOffer(offer, offerSig, s.offerSigner.PublicKey()); err != nil {
		return exchange.Wrap(exchange.KindSignatureInvalid, err, "offer signature verification")
	}
	return nil
}

// billingResolution names the inputs resolveBilling consumes so the call
// site stays under the per-function arg cap.
type billingResolution struct {
	tenantID       string
	agentID        string
	pricing        PricingDoc
	idempotencyKey string // = tx_request.id; anchors the billing lifecycle
}

// resolveBilling returns an AuthorizeResult for the transaction. Every
// caller has a non-empty requester.id (enforced at validateTxRequest)
// and goes through the billing adapter; the v0 anonymous-public bypass
// is gone with the entitlement-biscuit layer.
func (s *ExchangeService) resolveBilling(
	ctx context.Context, in billingResolution,
) (billing.AuthorizeResult, error) {
	return s.authorizeBilling(ctx, in)
}

// authorizeBilling reserves funds for the transaction.
func (s *ExchangeService) authorizeBilling(
	ctx context.Context, in billingResolution,
) (billing.AuthorizeResult, error) {
	pricing := in.pricing
	quantity := int64(pricing.EstQty)
	if quantity <= 0 {
		quantity = 1
	}
	amount, err := billing.NewAmount(fmt.Sprintf("%.8f", pricing.UnitCost), pricing.Currency)
	if err != nil {
		return billing.AuthorizeResult{}, exchange.Wrap(exchange.KindInternal, err, "parse unit cost")
	}
	res, err := s.billing.Authorize(ctx, billing.AuthorizeRequest{
		TenantID:       in.tenantID,
		AgentID:        in.agentID,
		UnitCost:       amount,
		Quantity:       quantity,
		Unit:           pricing.Unit,
		IdempotencyKey: in.idempotencyKey,
	})
	if err != nil {
		// Map the adapter sentinel to its domain Kind (e.g. a hard
		// ErrInsufficientBalance → KindBillingDenied, not KindInternal).
		return billing.AuthorizeResult{}, exchange.Wrap(billingErrorKind(err), err, "billing authorize")
	}
	if !res.Approved {
		return res, exchange.Newf(exchange.KindBillingDenied, "billing denied: %s", res.Reason)
	}
	return res, nil
}

// mintSignedURL dispatches to the correct URL signer based on the tenant's
// signing scheme and returns a ready-to-embed SignedURL. agentThumbprint, when
// non-empty, is embedded as the `agent_id` query parameter and covered by the
// signature, binding the URL to the requesting agent's key (ADR-013).
func (s *ExchangeService) mintSignedURL(
	ctx context.Context,
	tenant repo.Tenant,
	entry repo.CatalogEntry,
	agentThumbprint string,
) (signing.SignedURL, error) {
	urlSigner, err := signing.URLSignerFor(signing.TenantKeys{
		Scheme:              signing.Scheme(tenant.SigningScheme),
		Ed25519Ref:          tenant.Ed25519KeyRef,
		RSARef:              tenant.RSAKeyRef,
		CloudFrontKeyPairID: tenant.CloudFrontKeyPairID,
	}, s.keyStore)
	if err != nil {
		return signing.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "resolve url signer")
	}
	signed, err := urlSigner.SignURL(ctx, entry.URI, agentThumbprint, s.clk.Now().Add(s.cfg.URLTTL))
	if err != nil {
		return signing.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "sign url")
	}
	return signed, nil
}

// buildTxResponse assembles the wire TransactionResponse. The signed delivery
// URL is surfaced on the canonical RAMP-native field retrieval_endpoint
// (TransactionResponse field 18); ExpiresAt carries its expiry. The Broker and
// Edge read it there. buildTxResponse is only reached on the signed-URL success
// path (exchange.go ExecuteTransaction), so the field is always populated here;
// denial paths return earlier and leave retrieval_endpoint unset, per the proto
// field comment.
//
// agentThumbprint is the requesting key's RFC 7638 thumbprint (base64url-no-pad)
// computed once by agentBindingFor and shared with the URL's agent_id param. It
// is assigned to agent_identity_hash directly — the single encode/source of
// truth ADR-013 D4 requires — rather than re-encoding the persisted digest, so
// the URL binding and the response field cannot silently diverge.
func (s *ExchangeService) buildTxResponse(
	req *rampv1.TransactionRequest,
	rec repo.TransactionRecord,
	signed signing.SignedURL,
	pricing PricingDoc,
	agentThumbprint string,
) *rampv1.TransactionResponse {
	title := rec.OfferID
	unitCost := pricing.UnitCost
	cost := &rampv1.Cost{
		Amount:   pricing.UnitCost * float64(maxInt32(pricing.EstQty, 1)),
		Currency: pricing.Currency,
		UnitCost: &unitCost,
	}
	return &rampv1.TransactionResponse{
		Ver:            "1.0",
		Id:             req.GetId(),
		TransactionId:  &rec.TransactionID,
		BillingId:      &rec.BillingID,
		ResourceTitle:  &title,
		Cost:           cost,
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ExpiresAt:      timestamppb.New(signed.Expiry),
		// RFC 7638 thumbprint of the agent's key, base64url-no-pad. This is the
		// SAME string embedded as the URL's agent_id param (both flow from
		// agentBindingFor's single encode) and recomputed by the edge from the
		// presented key. The persisted 32-byte digest (rec.AgentIdentityHash) is
		// the raw form of this value; it is deliberately not re-encoded here.
		AgentIdentityHash: agentThumbprint,
		RetrievalEndpoint: strPtr(signed.URL),
		ReportingObligation: &rampv1.ReportingObligation{
			Required: true,
			Endpoint: strPtr("/ramp.v1.ExchangeService/ReportUsage"),
		},
	}
}

func maxInt32(v, fallback int32) int32 {
	if v <= 0 {
		return fallback
	}
	return v
}
