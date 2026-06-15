package service

import (
	"errors"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// billingErrorKind maps a billing adapter sentinel to the domain Kind the
// transport layer renders, so every adapter error surfaces a stable
// connect.Code. Centralised because two call paths consume it: the live
// Authorize path (authorizeBilling) and the deferred dispute path (Refund).
// Keeping one table prevents the two from drifting to different codes for the
// same sentinel. A non-sentinel error falls through to KindInternal.
func billingErrorKind(err error) exchange.Kind {
	switch {
	case errors.Is(err, billing.ErrRefundUnsupported):
		return exchange.KindUnimplemented
	case errors.Is(err, billing.ErrUnknownBillingID):
		return exchange.KindNotFound
	case errors.Is(err, billing.ErrRefundBeforeRecord),
		errors.Is(err, billing.ErrRefundExceedsRecord):
		return exchange.KindFailedPrecondition
	case errors.Is(err, billing.ErrInvalidAmount):
		return exchange.KindInvalidRequest
	case errors.Is(err, billing.ErrInsufficientBalance):
		return exchange.KindBillingDenied
	default:
		return exchange.KindInternal
	}
}
