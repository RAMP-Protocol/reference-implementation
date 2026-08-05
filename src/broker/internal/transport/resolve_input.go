package transport

import (
	"context"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
)

// validateAndCanonicalizeRequest and authorizeAgentSelfAct are the transport adapter's
// request-admission gates: they run in BrokerConnectHandler.Resolve, BEFORE the
// resolve business core is entered. They live in transport (not in the resolve
// service) because both are boundary concerns — validation shapes the wire input,
// and authorization reads the httpsig verification context the broker middleware
// populated on the inbound request (helpers.FromContext). The resolve core
// receives an already-validated, already-authorized request.

// authorizeAgentSelfAct enforces agent self-action: the verified signer's
// Signature-Agent directory (its identity) MUST equal the caller-supplied
// req.AgentID. After the WBA split the RFC 9421 keyid is only the key's RFC 7638
// thumbprint (proof of possession), not the agent identity — the identity is the
// signed Signature-Agent directory origin. The broker httpsig middleware has
// already verified the signature (and that signature-agent is a covered
// component) before this runs; this check binds that verified directory to the
// agent the caller claims to be. Belt-and-braces: a missing httpsig context or
// an empty Signature-Agent (caller bypassed the middleware) is rejected as
// Unauthenticated rather than treated as any caller.
//
// BOTH sides are normalized to a host before comparison (internal/agentid), so
// the check turns on identity rather than on spelling. The two values are
// constructed independently — one is the header the agent signed, the other is a
// field it filled in — and comparing them raw made an agent that wrote
// "agent.example" in req.AgentID while signing "https://agent.example" look like
// an impersonator. Normalizing does not weaken the check: a different host still
// normalizes differently.
//
// That is half the property, and the half this function owns. Both values come
// from the SAME caller, so agreement between them proves only self-consistency;
// what makes the gate mean "this caller IS that agent" is the separate binding of
// the verified KEY to the Signature-Agent directory. Where that binding holds:
//
// the WBA path (internal/agentkeys) provides it: the key is resolved by
// fetching the directory the signature commits to, so a signer cannot name a
// directory that does not publish its key. This is the path EVERY inbound key
// takes — agentSig1Resolver has no other delegate (the Broker's own-key
// registry plays no part in it; its keys' private halves never sign an inbound
// request). Keep it that way: a resolver delegate that mapped thumbprint to
// key with no identity attached would satisfy this gate for any agent the
// signer cared to name.
//
// The Exchange re-verifies with its own equivalents of this gate: on
// single-signature RPCs, lookupCaller (src/exchange/internal/service/authz.go)
// proves the verified key is published by the claimed Signature-Agent
// directory and authorizeForAgent then refuses a caller acting for another
// agent's id; on ExecuteTransaction, the acting identity is proven by the body
// offer-acceptance signature against the key registered for requester.id
// (verifyAgentAcceptance), never taken from the transport chain.
//
// agentID arrives ALREADY canonical: validateAndCanonicalizeRequest rewrote req.AgentID in place
// before this runs. That ordering is the point. Normalizing here and comparing a
// local copy would leave the request itself carrying the caller's spelling, and
// everything downstream of this gate — the budget counter, the selection_log row,
// the requester.id relayed to the Exchange — keys on req.AgentID. The comparison
// would then say two spellings are one agent while the spend counter gave each
// its own bucket.
func authorizeAgentSelfAct(ctx context.Context, agentID string) *broker.Error {
	v := helpers.FromContext(ctx)
	if v == nil || v.SignatureAgent == "" {
		return broker.Newf(broker.KindUnauthenticated, "no verified caller in request context")
	}
	caller, err := agentid.FromDirectory(v.SignatureAgent)
	if err != nil {
		return broker.Wrapf(broker.KindUnauthenticated, err,
			"caller directory %q does not name a host", v.SignatureAgent)
	}
	if caller != agentID {
		return broker.Newf(broker.KindPermissionDenied,
			"caller %q may not act on behalf of agent %q", caller, agentID)
	}
	return nil
}

// validateAndCanonicalizeRequest shapes the wire input and canonicalizes
// req.AgentID IN PLACE. The mutation is in the name because a validator that
// silently rewrites what it was handed is a shape a reader has to be warned
// about; the pointer parameter alone is too quiet a signal at the call site.
//
// The rewrite belongs here rather than in the authorization gate for two reasons.
// It is an input-shape concern — "does agent_id name a host" is the same class of
// question as "is agent_id present" — and this is the only place the canonical
// value can be written back where every later reader sees it: req is a local
// value in Resolve, so the core, the budget key, the audit row and the forwarded
// requester.id all take the identity, not the spelling that reached the wire.
func validateAndCanonicalizeRequest(req *resolve.Request) error {
	if req.AgentID == "" {
		return broker.Newf(broker.KindInvalidArgument, "agent_id is required").WithField("agent_id")
	}
	agentID, err := agentid.FromDirectory(req.AgentID)
	if err != nil {
		return broker.Wrapf(broker.KindInvalidArgument, err,
			"agent_id %q does not name a host", req.AgentID).WithField("agent_id")
	}
	req.AgentID = agentID
	if req.Query == "" && req.URI == "" {
		// No single offending field — record the composite requirement so a client
		// learns which one-of set was unsatisfied (ADR-019 §1 free-form metadata).
		return broker.Newf(broker.KindInvalidArgument, "either query or uri is required").
			WithMeta("required_one_of", "query,uri")
	}
	return enforceHopBudget(req.MaxHops)
}
