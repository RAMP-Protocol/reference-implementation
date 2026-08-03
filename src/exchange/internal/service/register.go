package service

import (
	"context"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// Bounds on caller-supplied registration_data, enforced at the Register gate
// before anything is persisted. A valid request signature authenticates the
// caller; it does not license them to write unbounded data into the account's
// extra JSONB column. Both the number of keys and the total encoded size are
// capped. The values are generous for a real registration (a legal entity, an
// address, an email, and a handful of extension keys) yet firmly bounded. The
// coarser whole-body read cap (transport.MaxRPCReadBytes) sits in front of this;
// this is the tighter, semantic limit on what actually gets stored.
const (
	maxRegistrationDataKeys  = 64
	maxRegistrationDataBytes = 16 * 1024 // 16 KiB, summed over key + value lengths
)

// BillingRefGen mints a fresh candidate billing_ref (ADR-021 D2). Production
// wires uuid.NewString; tests inject a deterministic generator. It is a small,
// swappable seam and deliberately NOT part of the billing/ledger adapter —
// billing_ref is an account id the ledger only consumes, never generates.
type BillingRefGen func() string

// Register creates (or idempotently returns) the calling agent's account: a SoR
// record, a ledger account, and a billing_ref saved on the agent's ramp.agents
// row. Identity comes only from the verified request signature (ADR-017 D6); the
// request body is never trusted for it.
func (s *ExchangeService) Register(
	ctx context.Context,
	req *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	agent, err := s.resolveAccountAgent(ctx, "register its own account")
	if err != nil {
		return nil, err
	}
	// Fast path (ADR-021 D4): a row that already carries a billing_ref is already
	// registered — return the stored id plus the current active flag and change
	// nothing. An empty billing_ref means "not registered yet", never a real ref,
	// so a non-empty check guards it before it is trusted.
	if agent.BillingRef != "" {
		return s.registeredResponse(ctx, agent.BillingRef)
	}
	return s.firstRegister(ctx, agent.ID, req)
}

// resolveAccountAgent runs the identity-and-guard prologue both account RPCs
// (Register, GetAccountStatus) open with: verify the request signature, refuse a
// service with no SoR wired, reject a non-agent caller, and load the caller's
// agents row. Keeping it in one place means the auth guards can never drift
// between the two RPCs. The action phrase (e.g. "register its own account",
// "read its own account status") is woven into the caller-facing messages so
// each RPC still names what the caller was trying to do. Identity comes only
// from the verified request signature (ADR-017 D6); the request body is never
// trusted for it.
func (s *ExchangeService) resolveAccountAgent(ctx context.Context, action string) (repo.Agent, error) {
	caller, err := s.resolveCaller(ctx)
	if err != nil {
		return repo.Agent{}, err
	}
	if s.sor == nil {
		// Defensive, mirroring resolveCaller's nil-agents guard: a service built
		// without a SoR cannot serve account RPCs, so refuse rather than nil-panic.
		return repo.Agent{}, exchange.Newf(exchange.KindInternal, "service has no SoR adapter wired")
	}
	if caller.Kind != CallerAgent {
		// The account is the CALLER's own, keyed on its verified directory
		// identity. A broker carries no agent identity of its own (caller.AgentID
		// is empty), so it has no account to act on here.
		return repo.Agent{}, exchange.Newf(exchange.KindPermissionDenied,
			"only an agent may %s", action)
	}
	agent, err := s.agents.ByID(ctx, caller.AgentID)
	if err != nil {
		return repo.Agent{}, exchange.Wrap(exchange.KindInternal, err, "load agent to "+action)
	}
	return agent, nil
}

// registeredResponse builds the reply for an already-registered agent (the
// ADR-021 D4 fast path): the stored billing_ref plus the SoR-owned active flag,
// with no side effects.
func (s *ExchangeService) registeredResponse(
	ctx context.Context,
	billingRef string,
) (*rampv1.RegisterResponse, error) {
	active, err := s.sor.IsActive(ctx, billingRef)
	if err != nil {
		return nil, exchange.Wrap(sorErrorKind(err), err, "read account status")
	}
	return &rampv1.RegisterResponse{Ver: rampproto.Ver, BillingRef: billingRef, Active: active}, nil
}

// firstRegister runs the first-registration flow for an agent whose row has no
// billing_ref yet (ADR-021 §5).
//
// The three writes below touch three separate backends — the SoR pool, the
// TigerBeetle ledger, and the main Postgres — that cannot share one transaction,
// so there is deliberately NO db.WithTx around them. They run in a fixed order
// and each one is safe to run again: OnRegister is idempotent on the subdomain,
// EnsureAgentAccount on the effective billing_ref, and SetBillingRef is guarded
// so it never overwrites. If the process dies between any two steps, a later
// Register simply replays the steps that did not finish — and once SetBillingRef
// has landed, the fast path in Register takes over and does nothing.
func (s *ExchangeService) firstRegister(
	ctx context.Context,
	agentID string,
	req *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	tenant, err := s.tenants.ByDomain(ctx, s.cfg.DefaultTenantDomain)
	if err != nil {
		if errors.Is(err, repo.ErrTenantNotFound) {
			// The configured default tenant has not been seeded yet. That is an
			// operator setup precondition the caller cannot act on, not a server
			// fault, so surface it as FailedPrecondition with a plain message
			// rather than an opaque Internal.
			return nil, exchange.Wrap(exchange.KindFailedPrecondition, err,
				fmt.Sprintf("default tenant %q is not seeded", s.cfg.DefaultTenantDomain))
		}
		return nil, exchange.Wrap(exchange.KindInternal, err, "resolve default tenant")
	}
	// Flatten registration_data once, then bound it at the gate before any write.
	// The bound runs on the flattened map — the exact form that lands in storage —
	// so the byte count reflects what would actually be persisted.
	data := structToMap(req.GetRegistrationData())
	if err := validateRegistrationData(data); err != nil {
		return nil, err
	}
	candidate := s.billingRefGen()
	acct, err := s.sor.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef:       candidate,
		Subdomain:        agentID,
		Active:           tenant.ActivateNewAgentsByDefault,
		RegistrationData: data,
	})
	if err != nil {
		return nil, exchange.Wrap(sorErrorKind(err), err, "register account in system of record")
	}
	// The SoR returns the id that actually gets used — the candidate for a new
	// account, or the already-stored id when this subdomain was registered before
	// (ADR-021 D4, "the stored id wins"). Everything downstream keys on acct.BillingRef.
	if err := s.billing.EnsureAgentAccount(ctx, acct.BillingRef); err != nil {
		return nil, exchange.Wrap(billingErrorKind(err), err, "create ledger account")
	}
	if _, err := s.agents.SetBillingRef(ctx, agentID, acct.BillingRef); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "store billing ref")
	}
	return &rampv1.RegisterResponse{
		Ver:        rampproto.Ver,
		BillingRef: acct.BillingRef,
		Active:     acct.Active,
	}, nil
}

// validateRegistrationData rejects a flattened registration_data map that
// exceeds the gate bounds: too many keys, or too many total bytes. A violation
// is KindInvalidRequest (InvalidArgument at the wire) with the offending field
// named in structured metadata, and — because it runs before any write — leaves
// nothing persisted. The SoR store stays a simple store; this gate is the only
// place the bound lives.
func validateRegistrationData(data map[string]string) error {
	if len(data) > maxRegistrationDataKeys {
		return exchange.Newf(exchange.KindInvalidRequest,
			"registration_data has %d keys, over the %d limit",
			len(data), maxRegistrationDataKeys).WithField("registration_data")
	}
	total := 0
	for k, v := range data {
		total += len(k) + len(v)
	}
	if total > maxRegistrationDataBytes {
		return exchange.Newf(exchange.KindInvalidRequest,
			"registration_data is %d bytes, over the %d-byte limit",
			total, maxRegistrationDataBytes).WithField("registration_data")
	}
	return nil
}

// GetAccountStatus reports the calling agent's account state (ADR-021). It
// resolves identity from the verified request signature the same way Register
// does, reads the billing_ref stored on the agent's ramp.agents row, and returns
// {billing_ref, active}. An identity with no stored billing_ref is not
// registered for paid content yet and surfaces NotFound; an account that exists
// but is switched off is active=false, never NotFound.
func (s *ExchangeService) GetAccountStatus(
	ctx context.Context,
	_ *rampv1.GetAccountStatusRequest,
) (*rampv1.GetAccountStatusResponse, error) {
	agent, err := s.resolveAccountAgent(ctx, "read its own account status")
	if err != nil {
		return nil, err
	}
	if agent.BillingRef == "" {
		// No billing_ref on the row means the identity was never registered for paid
		// content. That is NotFound, distinct from a registered-but-inactive account
		// (handled below), which is a real account reporting active=false.
		return nil, exchange.Newf(exchange.KindNotFound,
			"agent has no account: not registered for paid content yet")
	}
	active, err := s.sor.IsActive(ctx, agent.BillingRef)
	if err != nil {
		// sorErrorKind maps sor.ErrAccountNotFound → KindNotFound defensively: once
		// the row carries a billing_ref the SoR should know the account, so a
		// not-found here can only be a store inconsistency, never a normal inactive
		// account. Surfacing NotFound (not a panic or a false "inactive") keeps the
		// two states honestly distinct.
		return nil, exchange.Wrap(sorErrorKind(err), err, "read account status")
	}
	return &rampv1.GetAccountStatusResponse{
		Ver:        rampproto.Ver,
		BillingRef: agent.BillingRef,
		Active:     active,
	}, nil
}
