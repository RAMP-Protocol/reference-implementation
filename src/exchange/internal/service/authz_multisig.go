// Multisig transport-chain classification + relay authorization for the
// Exchange execute path.
//
// The transport signature chain (agent + relaying broker hops) is verified at
// the boundary by the multisig httpsig middleware, which exposes the ordered
// []httpsig.VerifiedRequest under httpsig.AllSignaturesFromContext. This
// file classifies those signatures into the agent and relay slots and gates a
// broker relay on the target tenant's allow_broker_relay flag.
//
// CRITICAL (binding decision): the AGENT identity that binds the
// delivery URL is NOT taken from the transport chain — it is proven by the BODY
// offer-acceptance signature (verifyAgentAcceptance in exchange.go) and bound to
// the agent's REGISTERED key. The transport chain only establishes WHO relayed
// the request so the broker-relay opt-in can be enforced. Broker-only transport
// (no agent transport signature) is therefore legitimate when a valid body
// acceptance is present and the tenant allows relay.

package service

import (
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// transportChain summarizes the classification of a verified transport
// signature chain: whether it carries a relaying broker hop and the broker's
// keyID (for audit). hasBroker is true when the chain carries a relay hop beyond
// the originating signature.
type transportChain struct {
	hasBroker bool
	brokerKey string
}

// classifyTransportChain classifies the verified transport chain by POSITION,
// per the forwarding-chain contract the verifier already enforced
// (sig1..sigN contiguous): sig1 is the originating agent and any signature
// beyond it is a relay hop. The outermost (last) signer is the party relaying to
// the Exchange; its keyID (an RFC 7638 thumbprint after the WBA split — there is
// no broker keyid prefix) is carried for audit only. The relay hop's role is NOT
// re-checked against the agents table: after the WBA split the relay is gated
// solely by the target tenant's allow_broker_relay flag (single-broker Option C),
// so a signature's POSITION in the chain is the only classification the execute
// path needs.
func classifyTransportChain(verified []helpers.VerifiedRequest) transportChain {
	var tc transportChain
	if len(verified) > 1 {
		tc.hasBroker = true
		tc.brokerKey = verified[len(verified)-1].KeyID
	}
	return tc
}

// authorizeExecute is the R4 authorization heart for ExecuteTransaction. It
//  1. classifies the verified transport chain (agent + relaying brokers) and
//     gates a broker hop on tenant.allow_broker_relay (PermissionDenied otherwise);
//  2. verifies the BODY offer-acceptance signature against the agent's REGISTERED
//     key and derives the delivery-URL binding from THAT key (never the broker's).
//
// It returns the Caller used for audit (the agent, identified by agentID and the
// acceptance-proven key) and the agentBinding the rest of the execute path feeds
// to mintSignedURL / persist. Any rejection is audited through logOutcome before
// it returns, matching every other execute authz outcome.
func (s *ExchangeService) authorizeExecute(
	ctx context.Context, req *rampv1.TransactionRequest, agent resolvedAgent, tenant repo.Tenant,
) (Caller, agentBinding, error) {
	chain := classifyTransportChain(helpers.AllSignaturesFromContext(ctx))
	auditCaller := Caller{KeyID: agent.id, Kind: CallerAgent, AgentID: agent.id}
	if relayErr := s.authorizeTransportRelay(ctx, chain, tenant); relayErr != nil {
		relayCaller := Caller{KeyID: chain.brokerKey, Kind: CallerBroker}
		s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ", relayCaller, &tenant, agent.id, "", relayErr)
		return Caller{}, agentBinding{}, relayErr
	}
	// The authoritative agent identity is the BODY acceptance key, not the
	// transport chain. Verify it against the request's ONE key snapshot and bind
	// the delivery URL to its RFC 7638 thumbprint. Computed before billing so a
	// bad-acceptance failure reserves no funds.
	binding, err := verifyAgentAcceptance(req, agent.key)
	if err != nil {
		var de *exchange.Error
		if errors.As(err, &de) {
			s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ", auditCaller, &tenant, agent.id, "", de)
		}
		return Caller{}, agentBinding{}, err
	}
	return auditCaller, binding, nil
}

// authorizeTransportRelay enforces the broker-relay opt-in for an execute
// request whose transport chain carries a relay hop. A chain with no relay hop is
// a no-op (agent-direct). When a hop relayed the request the target tenant MUST
// have allow_broker_relay = true, else the request is refused with
// PermissionDenied and the rejection is audited. That tenant flag is the SOLE
// gate — the relaying party's agents.requester_type is deliberately not consulted
// (see the Option-C paragraph below). The error message and code reuse the
// canonical authorizeForAgent broker-rule so the relay gate stays in one
// vocabulary.
//
// After the WBA split the relay is authorized purely by the tenant's
// allow_broker_relay opt-in (single-broker Option C): a single Signature-Agent
// header cannot carry a distinct directory per hop, so a relay hop is not
// re-identified against the agents table here — its key was already
// cryptographically verified by the multisig middleware, and the delivery-URL
// identity binds to the AGENT's body-acceptance key, never the relay's. Multi-hop
// relay and per-relay identity binding are out of scope (separate, threat-modeled
// ticket).
func (s *ExchangeService) authorizeTransportRelay(
	_ context.Context, chain transportChain, tenant repo.Tenant,
) *exchange.Error {
	if !chain.hasBroker {
		return nil
	}
	if !tenant.AllowBrokerRelay {
		return exchange.Newf(exchange.KindPermissionDenied,
			"broker %q rejected: tenant does not allow broker relay", chain.brokerKey)
	}
	return nil
}
