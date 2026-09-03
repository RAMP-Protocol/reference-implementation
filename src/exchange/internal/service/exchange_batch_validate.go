// Batch ExecuteTransaction envelope validation: the checks that run BEFORE the
// request resolves its agent, claims its idempotency key, or executes any item.
// Split from the batch pipeline so the pre-claim gate reads as one unit — what a
// malformed body is refused for, and what a client is told about it.

package service

import (
	"strconv"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// validateBatchRequest checks the batch envelope invariants: the shared
// idempotency_key + requester, and each item's offer signature, agent
// acceptance signature, and signed canonical_url. A missing envelope field is
// KindInvalidRequest and aborts the whole batch (it is malformed, not a per-item
// business denial).
//
// Everything checked here runs before the request claims its idempotency key, so
// a body that fails any of these leaves the key free for the corrected request
// that follows.
func (s *ExchangeService) validateBatchRequest(req *rampv1.TransactionRequest) error {
	if req.GetIdempotencyKey() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "idempotency_key required").WithField("idempotency_key")
	}
	if len(req.GetIdempotencyKey()) > maxIdempotencyKeyLen {
		return exchange.Newf(exchange.KindInvalidRequest,
			"idempotency_key exceeds %d bytes", maxIdempotencyKeyLen).WithField("idempotency_key")
	}
	if req.GetRequester().GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "requester.id required")
	}
	if len(req.GetRequester().GetDomain()) > maxRequesterDomainLen {
		return exchange.Newf(exchange.KindInvalidRequest,
			"requester.domain exceeds %d bytes", maxRequesterDomainLen).WithField("requester.domain")
	}
	// At least one item is required: an empty items[] is a malformed envelope, not
	// an empty-but-valid batch (mirrors the broker C3 guard). Rejecting here
	// prevents returning an empty TransactionResponse for a body that carried no
	// work.
	if len(req.GetItems()) == 0 {
		return exchange.Newf(exchange.KindInvalidRequest, "at least one item required")
	}
	// Duplicate offer_ids within one request are rejected HERE, before any item
	// executes. Items run sequentially, so without this guard the first
	// duplicate can complete — authorization, URL signing, persistence — before
	// the second reaches the same derived transaction key
	// (idempotency_key + offer_id) and fails on the persistence backstop,
	// leaving the batch partially executed. Buying the same resource twice
	// takes two separately issued offers, each with its own offer_id.
	seen := make(map[string]int, len(req.GetItems()))
	for i, item := range req.GetItems() {
		if item.GetOffer().GetSignature() == "" {
			return exchange.Newf(exchange.KindInvalidRequest, "item %d: offer signature required", i)
		}
		if item.GetAgentAcceptance().GetSignature() == "" {
			return exchange.Newf(exchange.KindInvalidRequest, "item %d: agent_acceptance signature required", i)
		}
		// The signed canonical URL is REQUIRED: it is the only binding between an
		// offer and the catalog entry it was issued for. Every Exchange-issued
		// offer carries one, so an empty value marks an offer this Exchange never
		// issued — malformed, not a business denial. It is checked HERE, in the
		// envelope validator, because the per-item pipeline that consumes it runs
		// after admission has claimed the request key: rejecting it later would
		// consume the agent's idempotency key for a request that finalizes no
		// response, and a corrected request carrying a newly issued offer would
		// then be refused as a changed item set.
		if item.GetOffer().GetIdentity().GetCanonicalUrl() == "" {
			return exchange.Newf(exchange.KindInvalidRequest,
				"item %d: offer identity.canonical_url required", i).
				WithField("items.offer.identity.canonical_url").WithMeta("item_index", strconv.Itoa(i))
		}
		id := item.GetOffer().GetOfferId()
		if j, dup := seen[id]; dup {
			return exchange.Newf(exchange.KindInvalidRequest,
				"items %d and %d present duplicate offer_id %q; "+
					"executing the same resource twice takes two separately issued offers", j, i, id).
				WithField("items.offer.offer_id").WithMeta("item_index", strconv.Itoa(i))
		}
		seen[id] = i
	}
	return nil
}
