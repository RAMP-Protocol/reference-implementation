// Agent-id resolution for ExecuteTransaction.
//
// An unknown requester.id is lazily registered (ADR-009 D2, v1.1): the Exchange
// pulls→verifies→persists the agent from its OWN Web Bot Auth key directory
// before the transaction proceeds. This adds NO new trust surface — the re-package
// execute path already fetches and trusts the agent's well-known key to verify
// the body AgentAcceptance binding, so persisting the agent row here records the
// same key the delivery URL will be bound to. A forged keyID cannot self-register
// (agentreg pins only a key the keyID's own directory publishes). When lazy
// registration is not configured (a harness without agentReg), resolveAgentLazily
// falls back to a registration-required rejection.

package service

import (
	"context"
	"crypto/ed25519"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// resolvedAgent is everything ONE ExecuteTransaction resolves about its
// requester, decided once before any verification runs: the id the transaction
// is attributed to, the account handle the paid path charges, and the key
// snapshot every signature in the request is verified against. The three come
// from a single read of the agent row, so they cannot describe different
// registrations of the same agent.
type resolvedAgent struct {
	id         string
	billingRef string
	key        agentKey
}

// resolveAgent returns the agent_id to attribute the transaction to, the
// agent's billing_ref (the account handle the paid path charges, ADR-021 D5),
// and the registered key every signature in this request is verified against.
// The id MUST resolve to a row in ramp.agents (so transaction_log.agent_id's FK
// is satisfied); an unknown id is lazily registered from its well-known, or
// rejected if it cannot be. The billing_ref comes ONLY from that resolved row —
// never from anything the caller sends — and is empty when the agent has not
// registered for paid content. When lazy registration is not wired (s.agents ==
// nil, a bare harness) the requester id is returned with no ref and no key; a
// request that then needs to verify a signature fails as an internal wiring
// fault (agentKey.verifier), which is what it is.
// requester.id is guaranteed non-empty by validateBatchRequest.
//
// requester.id is normalized to its directory host first (internal/agentid), so
// the id attributed to the transaction is the same one the caller's signed
// Signature-Agent resolves to. The two are constructed independently — one is the
// header the outbound signer emits, the other a body field — and nothing on the
// wire forces them into the same spelling. RAMP's own identity service does build
// both from one value, so its requests agree by construction; an external client
// is under no such obligation, and that is the case this normalization exists for.
// Left raw, transaction_log.agent_id would hold a different string from the row
// lookupCaller authorized, and the FK would point at a second registration for one
// agent.
//
// The SIGNED bytes are preserved separately: transaction_evidence.requester_id
// keeps requester.id verbatim, so what the agent attested and what the ledger
// attributes are both recoverable. They are joined through FromDirectory rather
// than by equality — see migration 000024's column comment.
func (s *ExchangeService) resolveAgent(
	ctx context.Context, req *rampv1.TransactionRequest,
) (resolvedAgent, error) {
	requesterID, err := agentid.FromDirectory(req.GetRequester().GetId())
	if err != nil {
		return resolvedAgent{}, exchange.Wrap(exchange.KindInvalidRequest, err,
			fmt.Sprintf("requester.id %q does not name a host", req.GetRequester().GetId())).
			WithField("requester.id")
	}
	if s.agents == nil {
		return resolvedAgent{id: requesterID}, nil
	}
	agent, err := s.resolveAgentLazily(ctx, requesterID)
	if err != nil {
		return resolvedAgent{}, err
	}
	return resolvedAgent{
		id:         requesterID,
		billingRef: agent.BillingRef,
		key:        agentKey{pub: ed25519.PublicKey(agent.PublicKey), discoveryURL: agent.DiscoveryURL},
	}, nil
}
