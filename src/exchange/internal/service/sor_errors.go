package service

import (
	"errors"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// sorErrorKind maps a SoR adapter sentinel to the domain Kind the transport
// layer renders, mirroring billingErrorKind so every adapter error surfaces a
// stable connect.Code. It keeps the sor package free of any internal/exchange
// import (the SoR carries billing-style bare sentinels).
func sorErrorKind(err error) exchange.Kind {
	switch {
	case errors.Is(err, sor.ErrAccountNotFound):
		return exchange.KindNotFound
	case errors.Is(err, sor.ErrSubdomainRequired), errors.Is(err, sor.ErrBillingRefRequired):
		// The Exchange always passes a verified subdomain (caller.AgentID) and a
		// freshly minted candidate billing_ref, so an empty-argument rejection can
		// only be an Exchange-side bug, never caller fault — surface it as internal,
		// not a 4xx the caller could act on.
		return exchange.KindInternal
	default:
		return exchange.KindInternal
	}
}
