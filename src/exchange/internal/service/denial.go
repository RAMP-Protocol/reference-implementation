package service

import (
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// denialReasonByKind maps the Exchange's domain denial kinds onto the canonical
// proto DenialReason vocabulary (ADR-019). Only kinds that represent a refused
// transaction appear here; non-denial kinds (invalid request, not found,
// internal) are absent and either carry only a transport code (single-offer
// path) or abort the whole batch (batch path).
//
// This is the SINGLE source of truth for the denial vocabulary: the transport
// layer's executeTxError reuses DenialReasonForKind for the single-offer typed
// ErrorDetail, and the batch ExecuteTransaction loop reuses it to set each
// TransactionResultItem.denial_reason — so the per-item batch denial and the
// single-offer transport denial can never drift (the derived per-item key).
var denialReasonByKind = map[exchange.Kind]rampv1.DenialReason{
	exchange.KindBillingDenied:         rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE,
	exchange.KindAccountNotRegistered:  rampv1.DenialReason_DENIAL_REASON_BILLING_REF_INACTIVE,
	exchange.KindAccountInactive:       rampv1.DenialReason_DENIAL_REASON_BILLING_REF_INACTIVE,
	exchange.KindSignatureInvalid:      rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID,
	exchange.KindOfferExpired:          rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED,
	exchange.KindEntitlementMissing:    rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_MISSING,
	exchange.KindEntitlementMalformed:  rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_MALFORMED,
	exchange.KindEntitlementExpired:    rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_EXPIRED,
	exchange.KindEntitlementWrongBuyer: rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_WRONG_BUYER,
	exchange.KindSubscriptionLapsed:    rampv1.DenialReason_DENIAL_REASON_SUBSCRIPTION_LAPSED,
	exchange.KindEntitlementNotGranted: rampv1.DenialReason_DENIAL_REASON_ENTITLEMENT_NOT_GRANTED,
}

// DenialReasonForKind returns the canonical DenialReason for a transaction-denial
// error, or ok=false when the failure is not a denial (envelope-invalid /
// internal / not-found). For the batch path, ok=false means the error is NOT a
// per-item denial and MUST abort the whole batch; ok=true means it becomes the
// item's denial_reason and the loop continues (collect-and-continue).
func DenialReasonForKind(err error) (rampv1.DenialReason, bool) {
	var de *exchange.Error
	if !errors.As(err, &de) {
		return rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED, false
	}
	reason, ok := denialReasonByKind[de.Kind]
	return reason, ok
}
