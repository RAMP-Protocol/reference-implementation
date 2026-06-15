// Caller-identity authorization for the Exchange service.
//
// Authentication runs at the transport boundary via the httpsig middleware:
// every /ramp.* request must carry a valid RFC 9421 signature whose keyID
// resolves against the configured key store. The middleware stashes the
// verified principal under httpsig.FromContext.
//
// Authorization is what this file adds: the keyID alone is not enough — the
// service must check that the keyID has the right to act on the specific
// transaction / obligation in front of it. Per the implementation-plan Q1
// answer the keyID equals the agent_id directly, with broker keys
// distinguished by the agents.requester_type discriminator and authorized
// via the per-tenant allow_broker_relay flag (Q2).

package service

import (
	"context"
	"crypto/ed25519"
	"errors"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// CallerKind discriminates the verified caller's role.
type CallerKind int

// CallerKind values.
const (
	// CallerUnknown is the zero value used when no httpsig context is present.
	CallerUnknown CallerKind = iota
	// CallerAgent is a registered agent calling on its own behalf — keyID
	// equals the agent_id and may only act on its own obligations.
	CallerAgent
	// CallerBroker is a registered broker calling on behalf of an agent —
	// authorized per-tenant via the allow_broker_relay flag.
	CallerBroker
)

// Caller is the verified principal the service authorizes against. KeyID is
// the value the httpsig middleware verified; AgentID is the same string when
// Kind == CallerAgent and the empty string when Kind == CallerBroker (a broker
// does not carry an agent identity; the agent it acts on behalf of is named
// on the wire).
type Caller struct {
	KeyID   string
	Kind    CallerKind
	AgentID string
	// PublicKey is the Ed25519 key the httpsig middleware verified the caller's
	// request signature against — the cryptographically proven key. The
	// delivery-URL identity binding computes the RFC 7638 thumbprint from these
	// bytes (ADR-013 D5: bind to the proven key, not the claimed KeyID).
	PublicKey ed25519.PublicKey
}

// resolveCaller reads the verified httpsig context, looks the keyID up in the
// agents repo, and classifies the caller. Missing httpsig context →
// Unauthenticated; unknown keyID → Unauthenticated; everything else returns
// a populated Caller.
//
// Note that the httpsig middleware already failed unverified requests with
// 401 before reaching the service. The "missing context" branch here is a
// belt-and-braces check for service-internal callers that bypass the
// middleware (none today, but the code should not silently treat them as
// any caller).
func (s *ExchangeService) resolveCaller(ctx context.Context) (Caller, error) {
	v := httpsig.FromContext(ctx)
	if v == nil || v.KeyID == "" {
		return Caller{}, exchange.Newf(exchange.KindUnauthenticated, "no verified caller in request context")
	}
	if s.agents == nil {
		// Defensive: a service constructed without an agents repo cannot
		// authorize; refuse rather than fall open.
		return Caller{}, exchange.Newf(exchange.KindInternal, "service has no agents repo wired")
	}
	agent, err := s.agents.ByID(ctx, v.KeyID)
	if err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return Caller{}, exchange.Newf(exchange.KindUnauthenticated,
				"caller keyID %q not registered as an agent or broker", v.KeyID)
		}
		return Caller{}, exchange.Wrap(exchange.KindInternal, err, "lookup caller")
	}
	switch agent.RequesterType {
	case "BROKER":
		return Caller{KeyID: v.KeyID, Kind: CallerBroker, PublicKey: v.PublicKey}, nil
	default:
		// AGENT / HUMAN_TOOL / SERVICE / DELEGATED / RESEARCH all bind the
		// keyID to the agent_id and follow the same self-acting authz rule.
		return Caller{KeyID: v.KeyID, Kind: CallerAgent, AgentID: v.KeyID, PublicKey: v.PublicKey}, nil
	}
}

// authorizeForAgent enforces the caller-identity rule for a given
// (agent_id, tenant) pair. Agents must self-act; brokers must hold an
// allow_broker_relay opt-in on the tenant in question.
func authorizeForAgent(caller Caller, agentID string, allowBrokerRelay bool) *exchange.Error {
	switch caller.Kind {
	case CallerAgent:
		if caller.AgentID != agentID {
			return exchange.Newf(exchange.KindPermissionDenied,
				"caller %q may not act on behalf of agent %q", caller.AgentID, agentID)
		}
		return nil
	case CallerBroker:
		if !allowBrokerRelay {
			return exchange.Newf(exchange.KindPermissionDenied,
				"broker %q rejected: tenant does not allow broker relay", caller.KeyID)
		}
		return nil
	default:
		return exchange.Newf(exchange.KindUnauthenticated, "unclassified caller")
	}
}
