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
	"context"
	"crypto/ed25519"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// verifyAgentAcceptance resolves the agent's registered Ed25519 key for
// req.requester.id and verifies the body offer-acceptance signature against it,
// returning the delivery-URL binding derived from THAT key (never the transport
// caller / broker key). agentID is the already-resolved requester id.
//
// Error mapping (ADR-019):
//   - unknown / unregistered agent          → KindNotFound (resolveAgentID owns
//     this earlier; kept defensive here)
//   - malformed stored key                  → KindInternal
//   - ErrAcceptanceSignatureInvalid (wrong  → KindSignatureInvalid
//     key / tampered binding)                 (DENIAL_REASON_SIGNATURE_INVALID)
func (s *ExchangeService) verifyAgentAcceptance(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string,
) (agentBinding, error) {
	agent, err := s.agentAcceptanceKey(ctx, agentID)
	if err != nil {
		return agentBinding{}, err
	}
	pub := ed25519.PublicKey(agent.PublicKey)
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
	binding, err := agentBindingForKey(pub, agent.DiscoveryURL, acceptanceBytes)
	if err != nil {
		return agentBinding{}, err
	}
	return binding, nil
}

// agentAcceptanceKey loads the registered agent record whose Ed25519 key verifies
// the acceptance. The id was already proven registered by resolveAgentID, so a
// not-found here is a defensive NotFound; a stored key of the wrong length is an
// internal invariant violation. The whole record is returned, not just the key,
// because the success path also persists the agent's discovery URL as the
// provenance of that key — the registry overwrites a rotated key in place and
// keeps no history of where a retired one came from.
func (s *ExchangeService) agentAcceptanceKey(ctx context.Context, agentID string) (repo.Agent, error) {
	if s.agents == nil {
		return repo.Agent{}, exchange.Newf(exchange.KindInternal, "service has no agents repo wired")
	}
	agent, err := s.agents.ByID(ctx, agentID)
	if err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return repo.Agent{}, exchange.Newf(exchange.KindNotFound, "agent %q not registered", agentID)
		}
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "lookup agent acceptance key")
	}
	if len(agent.PublicKey) != ed25519.PublicKeySize {
		return repo.Agent{}, exchange.Newf(exchange.KindInternal,
			"agent %q has a non-ed25519 registered key (%d bytes)", agentID, len(agent.PublicKey))
	}
	return agent, nil
}
