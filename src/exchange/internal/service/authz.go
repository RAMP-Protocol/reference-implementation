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
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
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
	v := helpers.FromContext(ctx)
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

// lookupCaller resolves a verified signature to a Caller by looking up the
// agent record and classifying the caller type. It is the single source of
// truth for caller classification on the single-sig caller-resolution path
// (resolveCaller). Callers must guarantee s.agents != nil.
//
// The lookup runs through resolveAgentLazily, so an unknown keyID triggers the
// ADR-009 D2 pull -> verify -> persist registration before classification.
//
// The signed Signature-Agent directory is normalized to its host before anything
// keys on it, so one host is one agent no matter which scheme the caller spelled
// (internal/agentid). Normalizing HERE, at the one place a verified signature
// becomes a caller identity, is what keeps the stored row, the re-pin, and the
// returned AgentID from ever holding three spellings of the same agent. A value
// that names no host cannot be an identity and cannot be a fetch target, so it is
// refused as an authentication failure rather than carried further.
func (s *ExchangeService) lookupCaller(
	ctx context.Context,
	v *helpers.VerifiedRequest,
) (Caller, error) {
	// callerHost, not "directory". After FromDirectory this is the BARE canonical
	// host ("a.example"), while "directory" in this codebase means the full origin
	// the Signature-Agent header carries ("https://a.example") — what
	// DirectoryFromHeader returns and what a fetch URL is built from. One word for
	// two shapes, in adjacent code, is how an origin ends up passed where a host is
	// expected. The prose below still says "directory" where it means the document
	// and the party serving it, which is the sense that has not changed.
	callerHost, err := agentid.FromDirectory(v.SignatureAgent)
	if err != nil {
		// Logged as raw_signature_agent, NOT caller_directory: every other site in
		// this file stamps caller_directory with the normalized host, and an
		// operator correlating on one attribute name must not be handed two
		// different kinds of value under it.
		reqctx.FromContext(ctx).WarnContext(ctx, "caller directory is not a usable identity",
			"raw_signature_agent", v.SignatureAgent, "err", err)
		return Caller{}, exchange.Newf(exchange.KindUnauthenticated,
			"caller directory %q does not name a host", v.SignatureAgent)
	}
	agentRecord, err := s.resolveAgentLazily(ctx, callerHost)
	if err != nil {
		return Caller{}, err
	}

	// Bind the verified key to the claimed identity. The RFC 9421 keyid is only
	// an RFC 7638 thumbprint (proof of key possession), and a resolver may verify
	// a signature against any key it knows. Authorization keys on the
	// Signature-Agent directory, so the directory MUST actually publish the key
	// that produced this signature; otherwise a holder of any resolver-known key
	// could set Signature-Agent to another registered directory and be authorized
	// as it.
	//
	// For an ALREADY-registered directory resolveAgentLazily returns the pinned
	// row without re-fetching, so a caller that rotated its directory key would
	// mismatch the stale pin. On a mismatch, re-learn the directory's
	// currently-valid key (bounded/debounced) and re-compare; only a key that
	// still differs after a fresh pin is an impersonation attempt. Rejection is
	// Unauthenticated (an authentication failure — the proven key is not published
	// by the claimed directory), matching the catalog-push gate and not leaking
	// whether the directory is a registered identity.
	if !bytes.Equal(agentRecord.PublicKey, v.PublicKey) {
		agentRecord = s.repinAndReload(ctx, callerHost, agentRecord)
		if !bytes.Equal(agentRecord.PublicKey, v.PublicKey) {
			return Caller{}, exchange.Newf(exchange.KindUnauthenticated,
				"signing key is not published by caller directory %q", callerHost)
		}
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
		caller.AgentID = callerHost
	}
	return caller, nil
}

// repinAndReload attempts a bounded, debounced re-fetch + re-pin of directory's
// currently-valid key and returns the reloaded agent row so lookupCaller can
// re-compare the proven key against the freshly pinned one. A re-pin failure
// (registry unwired, unreachable directory, transient fetch error) is NOT fatal
// here: it is logged and the prior row is returned, so the caller re-compares
// against the best key available and denies on mismatch. This keeps an
// impersonation attempt against an unreachable victim directory a clean
// Unauthenticated rather than an amplifying, retryable Unavailable.
func (s *ExchangeService) repinAndReload(ctx context.Context, callerHost string, current repo.Agent) repo.Agent {
	if s.agentReg == nil {
		return current
	}
	if err := s.agentReg.RefreshDirectoryKey(ctx, callerHost); err != nil {
		reqctx.FromContext(ctx).WarnContext(ctx, "caller key re-pin failed",
			"caller_directory", callerHost, "err", err)
		return current
	}
	reloaded, err := s.agents.ByID(ctx, callerHost)
	if err != nil {
		reqctx.FromContext(ctx).WarnContext(ctx, "caller reload after re-pin failed",
			"caller_directory", callerHost, "err", err)
		return current
	}
	return reloaded
}

// resolveAgentLazily looks the keyID up in the agents repo and, on a miss,
// runs the ADR-009 D2 pull -> verify -> persist sequence before re-reading.
// The agent's identity anchors discovery: the manifest is fetched from the
// keyID's own domain and the registry refuses a key the manifest does not
// publish, so a forged keyID cannot self-register.
func (s *ExchangeService) resolveAgentLazily(ctx context.Context, callerHost string) (repo.Agent, error) {
	agent, err := s.agents.ByID(ctx, callerHost)
	if err == nil {
		return agent, nil
	}
	if errors.Is(err, agentid.ErrNotAHost) {
		// A caller fault, not a server one. The repo refuses a value that cannot key
		// its column, and that is exactly the caller this gate exists to catch — so
		// it must not arrive as a 500. Classified here beside ErrAgentNotFound
		// because this is where repo errors become domain kinds.
		return repo.Agent{}, exchange.Newf(exchange.KindUnauthenticated,
			"caller directory %q does not name a host", callerHost)
	}
	if !errors.Is(err, repo.ErrAgentNotFound) {
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "lookup caller")
	}
	if s.agentReg == nil {
		return repo.Agent{}, exchange.Newf(exchange.KindUnauthenticated,
			"caller directory %q not registered as an agent or broker", callerHost)
	}
	// The Signature-Agent directory IS the agent's discovery anchor: fetch its
	// own WBA file, pin the currently-valid key, persist. directoryURL ==
	// directory so agentreg's host-anchoring guard is satisfied.
	if regErr := s.agentReg.RegisterFromDirectory(ctx, callerHost, callerHost); regErr != nil {
		reqctx.FromContext(ctx).WarnContext(ctx, "lazy agent registration failed",
			"caller_directory", callerHost, "err", regErr)
		return repo.Agent{}, mapLazyRegisterError(callerHost, regErr)
	}
	agent, err = s.agents.ByID(ctx, callerHost)
	if err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return repo.Agent{}, exchange.Newf(exchange.KindUnauthenticated,
				"caller directory %q not registered after lazy registration", callerHost)
		}
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "lookup caller after registration")
	}
	reqctx.FromContext(ctx).InfoContext(ctx, "lazy agent registration ok", "caller_directory", callerHost)
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
