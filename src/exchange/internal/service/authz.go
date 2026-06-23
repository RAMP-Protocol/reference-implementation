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
	"strings"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
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
// Unauthenticated; everything else returns a populated Caller.
//
// Unknown keyID triggers ADR-009 D2 lazy registration: the service pulls the
// caller's own /.well-known/ramp.json (keyID IS the agent's domain anchor per
// ADR-009 D3/D4), verifies the asserted key is published there, persists the
// ramp.agents row, and re-reads it. A keyID that does not resolve to a
// published key stays Unauthenticated. The fetch uses agentreg's SSRF-guarded
// client. When no registry is wired (s.agentReg == nil) the unknown-keyID path
// is Unauthenticated, matching the pre-D2 behavior.
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
	// Lookup + requester_type classification lives in lookupCaller, shared with
	// the multisig path so both entry points classify a caller identically.
	return s.lookupCaller(ctx, v)
}

// classifySignatures separates verified signatures into agent and relay
// based on keyid prefix. Returns first agent signature and first relay
// signature (both may be nil).
func classifySignatures(verified []httpsig.VerifiedRequest) (
	agent *httpsig.VerifiedRequest,
	relay *httpsig.VerifiedRequest,
) {
	for i := range verified {
		v := &verified[i]
		if strings.HasPrefix(v.KeyID, httpsig.BrokerKeyIDPrefix) {
			if relay == nil {
				relay = v
			}
		} else {
			if agent == nil {
				agent = v
			}
		}
	}
	return agent, relay
}

// lookupCaller resolves a verified signature to a Caller by looking up the
// agent record and classifying the caller type. It is the single source of
// truth for caller classification, shared by resolveCaller (single-sig) and
// resolveMultisigCaller (multisig). Callers must guarantee s.agents != nil.
//
// The lookup runs through resolveAgentLazily, so an unknown keyID — arriving on
// either the single-sig path or the multisig agent/relay slot — triggers the
// ADR-009 D2 pull -> verify -> persist registration before classification.
func (s *ExchangeService) lookupCaller(
	ctx context.Context,
	v *httpsig.VerifiedRequest,
) (Caller, error) {
	agentRecord, err := s.resolveAgentLazily(ctx, v.KeyID)
	if err != nil {
		return Caller{}, err
	}

	caller := Caller{
		KeyID:     v.KeyID,
		PublicKey: v.PublicKey,
	}
	switch agentRecord.RequesterType {
	case "BROKER":
		caller.Kind = CallerBroker
	default:
		caller.Kind = CallerAgent
		caller.AgentID = v.KeyID
	}
	return caller, nil
}

// resolveMultisigCaller classifies each verified signature as agent or relay
// BY KEYID PREFIX. Classification is order-independent: keyid starting with
// "broker." = relay, else = agent. Returns agent (first non-broker keyid)
// and optional relay (first broker keyid).
func (s *ExchangeService) resolveMultisigCaller(
	ctx context.Context,
	verified []httpsig.VerifiedRequest,
) (agent Caller, relay *Caller, err error) {
	if s.agents == nil {
		return Caller{}, nil, exchange.Newf(exchange.KindInternal,
			"service has no agents repo wired")
	}

	agentVerified, relayVerified := classifySignatures(verified)

	if agentVerified == nil {
		return Caller{}, nil, exchange.Newf(exchange.KindUnauthenticated,
			"no agent signature in multisig request")
	}

	agent, err = s.lookupCaller(ctx, agentVerified)
	if err != nil {
		return Caller{}, nil, err
	}
	// The agent slot must resolve to a genuine agent. classifySignatures routes
	// by keyID prefix, but the DB requester_type is authoritative: a BROKER
	// whose keyID lacks the "broker." prefix would otherwise occupy the agent
	// slot and have the delivery URL bound to its key instead of the agent's
	// (ADR-013). Symmetric to the relay-slot check below.
	if agent.Kind != CallerAgent {
		return Caller{}, nil, exchange.Newf(exchange.KindUnauthenticated,
			"agent keyID %q has requester_type other than an agent role", agentVerified.KeyID)
	}

	if relayVerified != nil {
		relayCaller, err := s.lookupCaller(ctx, relayVerified)
		if err != nil {
			return Caller{}, nil, err
		}
		if relayCaller.Kind != CallerBroker {
			return Caller{}, nil, exchange.Newf(exchange.KindUnauthenticated,
				"relay keyID %q has requester_type other than BROKER", relayVerified.KeyID)
		}
		relay = &relayCaller
	}

	return agent, relay, nil
}

// authorizeRelay enforces the broker-relay opt-in for the relay caller and
// audits a rejection. A nil relay (single-agent multisig) is a no-op. Routes
// through authorizeForAgent so the relay gate and its message stay in one place.
func (s *ExchangeService) authorizeRelay(
	ctx context.Context, relay *Caller, agentID string, tenant repo.Tenant,
) *exchange.Error {
	if relay == nil {
		return nil
	}
	authzErr := authorizeForAgent(*relay, agentID, tenant.AllowBrokerRelay)
	if authzErr != nil {
		s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ", *relay, &tenant, agentID, "", authzErr)
	}
	return authzErr
}

// resolveAgentLazily looks the keyID up in the agents repo and, on a miss,
// runs the ADR-009 D2 pull -> verify -> persist sequence before re-reading.
// The agent's identity anchors discovery: the manifest is fetched from the
// keyID's own domain and the registry refuses a key the manifest does not
// publish, so a forged keyID cannot self-register.
func (s *ExchangeService) resolveAgentLazily(ctx context.Context, keyID string) (repo.Agent, error) {
	agent, err := s.agents.ByID(ctx, keyID)
	if err == nil {
		return agent, nil
	}
	if !errors.Is(err, repo.ErrAgentNotFound) {
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "lookup caller")
	}
	if s.agentReg == nil {
		return repo.Agent{}, exchange.Newf(exchange.KindUnauthenticated,
			"caller keyID %q not registered as an agent or broker", keyID)
	}
	// keyID IS the agent's domain anchor (ADR-009 D3/D4): pull its own
	// manifest, verify the key is published there, persist. manifestURL ==
	// keyID so agentreg's host-anchoring guard is satisfied.
	if regErr := s.agentReg.RegisterFromManifest(ctx, keyID, keyID); regErr != nil {
		s.logger.WarnContext(ctx, "lazy agent registration failed",
			"caller_keyid", keyID, "err", regErr)
		return repo.Agent{}, mapLazyRegisterError(keyID, regErr)
	}
	agent, err = s.agents.ByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return repo.Agent{}, exchange.Newf(exchange.KindUnauthenticated,
				"caller keyID %q not registered after lazy registration", keyID)
		}
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "lookup caller after registration")
	}
	s.logger.InfoContext(ctx, "lazy agent registration ok", "caller_keyid", keyID)
	return agent, nil
}

// mapLazyRegisterError classifies an agentreg failure. A caller fault (per
// agentreg.IsCallerFault — the manifest is absent (404), does not anchor the
// keyID, is malformed, or publishes no currently-valid key) resolves to
// Unauthenticated: the keyID is simply not a registrable identity. A genuinely
// transient transport/upstream failure (ErrFetch: connection refused, non-2xx
// other than 404) is Unavailable so the caller can retry once the manifest host
// is reachable.
func mapLazyRegisterError(keyID string, err error) error {
	if agentreg.IsCallerFault(err) {
		return exchange.Newf(exchange.KindUnauthenticated,
			"caller keyID %q is not published at its own /.well-known/ramp.json", keyID)
	}
	return exchange.Wrap(exchange.KindUnavailable, err, "fetch caller manifest")
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

// resolveCallerAndBinding detects whether the request is single-sig or
// multisig and returns the authorized caller and agent binding. For multisig
// requests (agent + broker), authorizes the broker relay and binds to the
// AGENT's key. For single-sig requests, binds to the caller's key.
func (s *ExchangeService) resolveCallerAndBinding(
	ctx context.Context, agentID string, tenant repo.Tenant,
) (Caller, agentBinding, error) {
	allSigs := httpsig.AllSignaturesFromContext(ctx)

	if len(allSigs) > 1 {
		// Multisig path: agent + broker relay
		agent, relay, err := s.resolveMultisigCaller(ctx, allSigs)
		if err != nil {
			return Caller{}, agentBinding{}, err
		}
		// Authorize the relay (if present) through the canonical gate so the
		// rule and its message live in one place and the rejection is audited
		// like every other authz outcome (EE-03).
		if authzErr := s.authorizeRelay(ctx, relay, agentID, tenant); authzErr != nil {
			return Caller{}, agentBinding{}, authzErr
		}
		// CRITICAL: Authorize and bind to AGENT (not broker)
		if authzErr := authorizeForAgent(agent, agentID, tenant.AllowBrokerRelay); authzErr != nil {
			return s.rejectExecuteAuthz(ctx, agent, &tenant, agentID, authzErr)
		}
		binding, err := agentBindingFor(agent)
		if err != nil {
			return Caller{}, agentBinding{}, err
		}
		return agent, binding, nil
	}

	// Single-sig path
	caller, err := s.resolveCaller(ctx)
	if err != nil {
		return Caller{}, agentBinding{}, err
	}
	// A broker may not be the sole signer on the delivery-URL binding path: the
	// multisig dispatch above gates on signature COUNT, so a lone broker sig
	// reaches here and would otherwise bind the URL to the broker's own key.
	// There is no agent identity to bind to (ADR-013); a broker must relay WITH
	// an agent signature (the multisig path). report_usage's own broker-relay
	// path is unaffected — it does not route through resolveCallerAndBinding.
	if caller.Kind == CallerBroker {
		authzErr := exchange.Newf(exchange.KindPermissionDenied,
			"broker %q may not act as sole signer; an agent co-signature is required", caller.KeyID)
		return s.rejectExecuteAuthz(ctx, caller, &tenant, agentID, authzErr)
	}
	if authzErr := authorizeForAgent(caller, agentID, tenant.AllowBrokerRelay); authzErr != nil {
		return s.rejectExecuteAuthz(ctx, caller, &tenant, agentID, authzErr)
	}
	binding, err := agentBindingFor(caller)
	if err != nil {
		return Caller{}, agentBinding{}, err
	}
	return caller, binding, nil
}

// rejectExecuteAuthz audits a REJECTED_AUTHZ outcome for the execute-transaction
// path and returns the zero caller/binding with err, so resolveCallerAndBinding's
// authz-failure sites stay a single line.
func (s *ExchangeService) rejectExecuteAuthz(
	ctx context.Context, caller Caller, tenant *repo.Tenant, agentID string, err *exchange.Error,
) (Caller, agentBinding, error) {
	s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ", caller, tenant, agentID, "", err)
	return Caller{}, agentBinding{}, err
}
