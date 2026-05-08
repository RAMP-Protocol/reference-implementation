package service

import (
	"context"
	"fmt"
	"time"

	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// validateTxRequest checks the minimum envelope invariants.
func (s *MarketplaceService) validateTxRequest(req *rampv1.TransactionRequest) error {
	if req == nil || req.GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "tx_request_id required")
	}
	if req.GetOfferId() == "" || req.GetOfferSignature() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "offer_id and offer_signature required")
	}
	if req.GetRequester() == nil || req.GetRequester().GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "requester.id required")
	}
	return nil
}

// idempotencyHit reports whether a tx_request_id was already processed.
// Implementation is an LRU bounded by cfg.IdempotencyLRU.
func (s *MarketplaceService) idempotencyHit(txRequestID string) (string, bool) {
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	rec, ok := s.idemHit[txRequestID]
	return rec, ok
}

// idempotencyRecord stores the tx_request_id → transaction_id mapping,
// evicting the oldest entry when the LRU is full.
func (s *MarketplaceService) idempotencyRecord(txRequestID, txID string) {
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
func (s *MarketplaceService) verifyOffer(entry repo.CatalogEntry, offerSig string) error {
	offer, err := s.buildOffer(entry)
	if err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "rebuild offer for verification")
	}
	if err := signing.VerifyOffer(offer, offerSig, s.offerSigner.PublicKey()); err != nil {
		return exchange.Wrap(exchange.KindSignatureInvalid, err, "offer signature verification")
	}
	return nil
}

// authorizeBilling reserves funds for the transaction.
func (s *MarketplaceService) authorizeBilling(
	ctx context.Context,
	tenantID, agentID string,
	pricing PricingDoc,
) (billing.AuthorizeResult, error) {
	quantity := int64(pricing.EstQty)
	if quantity <= 0 {
		quantity = 1
	}
	amount, err := billing.NewAmount(fmt.Sprintf("%.8f", pricing.UnitCost), pricing.Currency)
	if err != nil {
		return billing.AuthorizeResult{}, exchange.Wrap(exchange.KindInternal, err, "parse unit cost")
	}
	res, err := s.billing.Authorize(ctx, billing.AuthorizeRequest{
		TenantID: tenantID,
		AgentID:  agentID,
		UnitCost: amount,
		Quantity: quantity,
		Unit:     pricing.Unit,
	})
	if err != nil {
		return billing.AuthorizeResult{}, exchange.Wrap(exchange.KindInternal, err, "billing authorize")
	}
	if !res.Approved {
		return res, exchange.Newf(exchange.KindBillingDenied, "billing denied: %s", res.Reason)
	}
	return res, nil
}

// mintSignedURL dispatches to the correct URL signer based on the tenant's
// signing scheme and returns a ready-to-embed SignedURL. The txID and reqID
// audit correlators are embedded as `tx_id` / `req_id` query parameters
// before signing so they are covered by the URL signature; Lambda@Edge can
// then log them and `make ledger` can join the access log to the
// transaction_log row without re-hashing.
func (s *MarketplaceService) mintSignedURL(
	ctx context.Context,
	tenant repo.Tenant,
	entry repo.CatalogEntry,
	txID, reqID string,
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
	auditedURL, err := signing.AppendAuditQueryParams(entry.URI, map[string]string{
		"tx_id":  txID,
		"req_id": reqID,
	})
	if err != nil {
		return signing.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "append audit params")
	}
	signed, err := urlSigner.SignURL(ctx, auditedURL, time.Now().Add(s.cfg.URLTTL))
	if err != nil {
		return signing.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "sign url")
	}
	return signed, nil
}

// buildTxResponse assembles the wire TransactionResponse. The signed URL is
// carried under ext["signed_url"] (Struct), following the convention used
// across the scrappy demo pipeline — the Broker and Edge pick it up there.
func (s *MarketplaceService) buildTxResponse(
	req *rampv1.TransactionRequest,
	rec repo.TransactionRecord,
	signed signing.SignedURL,
	pricing PricingDoc,
) *rampv1.TransactionResponse {
	title := rec.OfferID
	unitCost := pricing.UnitCost
	ext, _ := structpb.NewStruct(map[string]any{
		"signed_url": signed.URL,
	})
	cost := &rampv1.Cost{
		Amount:   pricing.UnitCost * float64(maxInt32(pricing.EstQty, 1)),
		Currency: pricing.Currency,
		UnitCost: &unitCost,
	}
	return &rampv1.TransactionResponse{
		Ver:               "1.0",
		Id:                req.GetId(),
		TransactionId:     &rec.TransactionID,
		BillingId:         &rec.BillingID,
		ResourceTitle:     &title,
		Cost:              cost,
		DeliveryMethod:    rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ExpiresAt:         timestamppb.New(signed.Expiry),
		AgentIdentityHash: fmt.Sprintf("%x", rec.AgentIdentityHash),
		Ext:               ext,
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
