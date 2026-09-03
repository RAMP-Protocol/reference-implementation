// Body agent offer-acceptance verification + delivery-URL binding.
//
// The agent signs a detached, content-bound acceptance over the accepted Offer
// (helpers.VerifyOfferAcceptance / R2). Unlike the transport RFC 9421
// signature it is topology-independent: it stays valid no matter how many
// brokers relay the request, because it covers the offer + requester +
// idempotency, not the HTTP envelope. The Exchange therefore treats THIS
// signature — not the transport sig — as the authoritative agent identity and
// binds the delivery URL to the agent key it proves (RFC 7638 thumbprint).
//
// Per the binding decision, the verifying key is the agent's REGISTERED
// key (resolved from req.requester.id via the agents repo), uniform across
// agent-direct and broker-only/fan-out transport.

package service

import (
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// verifyAgentAcceptance verifies the body offer-acceptance signature against
// the request's agent key snapshot and returns the delivery-URL binding derived
// from THAT key (never the transport caller / broker key).
//
// It takes the key rather than the agent id, and it is a plain function with no
// service receiver and no context, so it CANNOT re-read the registry. Every
// item in one request is therefore checked against the one snapshot
// resolveAgent took — see agentKey for why a mid-request key rotation must not
// be able to split a response across two of them.
//
// Error mapping (ADR-019):
//   - no usable key in the snapshot          → KindInternal (agentKey.verifier)
//   - ErrAcceptanceSignatureInvalid (wrong  → KindSignatureInvalid
//     key / tampered binding)                 (DENIAL_REASON_SIGNATURE_INVALID)
func verifyAgentAcceptance(
	req *rampv1.TransactionRequest, key agentKey,
) (agentBinding, error) {
	pub, err := key.verifier()
	if err != nil {
		return agentBinding{}, err
	}
	// Items-only: the offer + acceptance are presented in items[0]
	// (executeBatchItem re-projects each item onto a 1-item synthetic request).
	item := req.GetItems()[0]
	// The three payload inputs are named once and reused for both the verify and
	// the canonical-bytes capture below, so the bytes recorded as evidence cannot
	// describe a different payload from the one that was checked. The REQUEST-level
	// idempotency key is what the agent signed; the derived per-item key
	// persistence uses is never fed to either call.
	offer, requester, idempotencyKey := item.GetOffer(), req.GetRequester(), req.GetIdempotencyKey()
	acceptanceErr := helpers.VerifyOfferAcceptance(
		offer,
		requester,
		idempotencyKey,
		item.GetAgentAcceptance().GetSignature(),
		pub,
	)
	if acceptanceErr != nil {
		if errors.Is(acceptanceErr, helpers.ErrAcceptanceSignatureInvalid) {
			return agentBinding{}, exchange.Wrap(exchange.KindSignatureInvalid, acceptanceErr,
				"agent offer-acceptance signature verification")
		}
		// A malformed hex signature, nil offer, or unsigned offer anchor surface
		// here — caller-attributable, but not a freshness/permission failure.
		return agentBinding{}, exchange.Wrap(exchange.KindSignatureInvalid, acceptanceErr,
			"verify agent offer-acceptance")
	}
	// Recompute the payload VerifyOfferAcceptance just checked, from the same three
	// values, so the evidence row stores the bytes this verification consumed. The
	// SDK verifies over them and discards them, so a recompute is the only way to
	// obtain them — but doing it here, beside the verify and off the same
	// variables, is what keeps the two from ever describing different payloads.
	acceptanceBytes, err := helpers.CanonicalAcceptanceBytes(offer, requester, idempotencyKey)
	if err != nil {
		return agentBinding{}, exchange.Wrap(exchange.KindInternal, err, "compute canonical acceptance bytes")
	}
	binding, err := agentBindingForKey(key, acceptanceBytes)
	if err != nil {
		return agentBinding{}, err
	}
	return binding, nil
}

// verifyRequestAcceptance proves that the registered agent authorized the
// complete ordered projection addressed to this Exchange. The canonical bytes
// it returns are the authenticated request identity persisted by ClaimRequest.
// It verifies against the same snapshot every item check uses, so the proof and
// the items it covers can never be checked against different keys.
func (s *ExchangeService) verifyRequestAcceptance(
	req *rampv1.TransactionRequest, key agentKey,
) (agentBinding, []byte, error) {
	pub, err := key.verifier()
	if err != nil {
		return agentBinding{}, nil, err
	}
	canonical, err := helpers.VerifyRequestAcceptanceProjection(
		req, req.GetAgentRequestAcceptance(), s.cfg.Exchange, pub,
	)
	if err != nil {
		return agentBinding{}, nil, exchange.Wrap(exchange.KindSignatureInvalid, err,
			"verify agent request acceptance")
	}
	binding, err := agentBindingForKey(key, nil)
	if err != nil {
		return agentBinding{}, nil, err
	}
	return binding, canonical, nil
}
