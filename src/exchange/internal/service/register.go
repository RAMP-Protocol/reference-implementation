package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"google.golang.org/protobuf/types/known/structpb"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
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
	sourceAddr string,
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
	return s.firstRegister(ctx, agent.ID, req, sourceAddr)
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
	return &rampv1.RegisterResponse{Ver: helpers.ProtocolVersion, BillingRef: billingRef, Active: active}, nil
}

// firstRegister runs the first-registration flow for an agent whose row has no
// billing_ref yet (ADR-021 §5).
//
// The writes below touch three separate backends — the SoR pool, the
// TigerBeetle ledger, and the main Postgres — that cannot share one transaction,
// so there is deliberately NO db.WithTx around them. They run in a fixed order
// and each one is safe to run again: OnRegister is idempotent on the subdomain,
// EnsureAgentAccount on the effective billing_ref, the welcome credit on its
// key-derived ledger transfer id, and SetBillingRef is guarded so it never
// overwrites. If the process dies between any two steps, a later Register
// simply replays the steps that did not finish — and once SetBillingRef has
// landed, the fast path in Register takes over and does nothing.
func (s *ExchangeService) firstRegister(
	ctx context.Context,
	agentID string,
	req *rampv1.RegisterRequest,
	sourceAddr string,
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
	digest, err := s.gateRegistration(req)
	if err != nil {
		return nil, err
	}
	data := structToMap(req.GetRegistrationData())
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
	// The tenant-configured welcome credit (0 disables it) runs before
	// SetBillingRef, so a failed grant fails the RPC while the row still has no
	// billing_ref — the retry re-enters this branch instead of the fast path.
	// The shared welcome-slot idempotency key (billing.WelcomeCreditKey) makes
	// the retry (or an operator prefund under the same key) grant at most once.
	// Only an account
	// the SoR reports active is granted: a tenant holding new agents for review
	// (activate_new_agents_by_default = false) must not pay for every
	// self-signup, and an agent activated manually later is funded through the
	// operator script's shared service slot instead.
	if acct.Active && tenant.DefaultAgentCredit != nil && tenant.DefaultAgentCredit.Sign() > 0 {
		welcomeKey := billing.WelcomeCreditKey(acct.BillingRef)
		grant := billing.Amount{Value: tenant.DefaultAgentCredit, Currency: s.cfg.LedgerCurrency}
		if err := s.billing.Credit(ctx, acct.BillingRef, grant, welcomeKey); err != nil {
			return nil, exchange.Wrap(billingErrorKind(err), err, "grant default credit")
		}
		// The welcome credit has no aggregate cap, so this request-correlated
		// line is the operator's visibility into a drain on the liquidity
		// account.
		reqctx.FromContext(ctx).InfoContext(ctx, "granted default agent credit",
			"billing_ref", acct.BillingRef,
			"amount", money.DecimalString(tenant.DefaultAgentCredit))
	}
	if err := s.recordRegistration(ctx, registrationRecord{
		agentID:    agentID,
		billingRef: acct.BillingRef,
		digest:     digest,
		tenantID:   tenant.ID,
		sourceAddr: sourceAddr,
	}); err != nil {
		return nil, err
	}
	return &rampv1.RegisterResponse{
		Ver:        helpers.ProtocolVersion,
		BillingRef: acct.BillingRef,
		Active:     acct.Active,
	}, nil
}

// gateRegistration applies the checks a first registration must pass before
// anything is written: the payload bounds, then the terms digest, then the
// published schema. It reports the digest this registration accepted, which is
// nil when the Exchange publishes none.
//
// The whole order is the PROTOCOL's, and none of it is this Exchange's choice.
// The four payload checks — top-level member count, nesting depth, whether the
// payload has a JSON form at all, and its canonical byte size — run inside the
// SDK, which owns their sequence; see registrationDataBounds. Those four run
// before the terms gate, and the terms gate before the schema, for two stated
// reasons. A check that exists to stop work has to precede the work, so an
// unbounded payload is never handed to a schema. And a caller holding stale
// terms is told to re-fetch before it is told anything about the current
// schema's contents: the schema may itself have moved in the revision that
// caller has not read, so validating it against the current one would hand back
// field errors describing a document it has never seen. One refusal, one remedy.
//
// This gate runs on ACCOUNT CREATION ONLY. A repeat registration is answered
// from the stored record by Register's fast path and runs none of it.
//
// Every refusal here happens before the first write, so nothing is persisted.
func (s *ExchangeService) gateRegistration(req *rampv1.RegisterRequest) (*string, error) {
	if err := registrationDataBounds(req.GetRegistrationData()); err != nil {
		return nil, err
	}
	// The decoded object, not structToMap's flattened storage form: that is what
	// the schema is written against, and it is the form the agent pre-checks
	// with, so the two ends reach the same verdict on the same payload. A nested
	// object survives as an object here; flattened, it would arrive as a JSON
	// string and could never match an object subschema. The conversion runs after
	// the bounds because the bounds are what make it safe: an over-deep payload is
	// refused before AsMap walks it.
	payload := req.GetRegistrationData().AsMap()
	digest, err := s.acceptedTermsDigest(req.GetTermsDigest())
	if err != nil {
		return nil, err
	}
	// A nil validator — no schema configured — reports no failures, so the
	// pass-through case needs no branch here.
	if fieldErrors := s.regSchema.Validator().Validate(payload); len(fieldErrors) > 0 {
		return nil, registrationDataInvalid(fieldErrors)
	}
	return digest, nil
}

// registrationRecord is what the final step of a registration writes: the
// account link on the agent's row, and the audit row that dates it.
type registrationRecord struct {
	agentID    string
	billingRef string
	digest     *string
	tenantID   string
	// sourceAddr is the Connect peer address, which audit_log.source_addr
	// requires and only the transport can supply.
	sourceAddr string
}

// registerAuditAction is the action token every registration audit row carries.
// It names the service method, which is the convention the whole audit_log
// follows, and it is written from here alone so the log can never hold two
// spellings of the same event.
const registerAuditAction = "Register"

// registrationAudit is the applied-values payload of the registration audit
// row. It records the account id that was minted and the terms revision that was
// accepted — the two facts a later reader needs and cannot recover from anywhere
// else once the request is gone.
type registrationAudit struct {
	BillingRef          string  `json:"billing_ref"`
	AcceptedTermsDigest *string `json:"accepted_terms_digest"`
}

// recordRegistration writes the account link and its audit row in ONE
// transaction. These are the only two statements in the whole registration flow
// that share a database, so they are the only two that can share a commit: the
// SoR pool, the ledger and this Postgres are three separate backends, which is
// why firstRegister has no outer transaction around the rest.
//
// The audit row is appended only when the guarded UPDATE actually won. A losing
// caller — a second concurrent first registration for the same agent — gets the
// stored account back and returns the same response, but it did not register
// anything, so recording a second registration for one account would be false.
func (s *ExchangeService) recordRegistration(ctx context.Context, rec registrationRecord) error {
	detail, err := marshalAuditDetail(registrationAudit{
		BillingRef:          rec.billingRef,
		AcceptedTermsDigest: rec.digest,
	})
	if err != nil {
		return err
	}
	// The result is wrapped, not returned bare. db.WithTx is pgx.BeginFunc, so it
	// also reports the failures AROUND the callback — no connection to begin on,
	// or a commit that loses a serialization conflict — and those come straight
	// from the driver with no Kind on them. Without this wrap such a failure
	// leaves Register as a naked driver error: no kind for the transport to map,
	// and nothing saying which operation produced it.
	//
	// So the wrap deliberately fixes ONE kind for the whole transaction
	// boundary. Every failure inside or around the callback reaches the
	// transport as KindInternal, including a callback error that carried a kind
	// of its own — errors.As stops at this wrapper, not at what it wraps.
	if err := s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		_, won, err := s.agents.SetBillingRef(ctx, tx, rec.agentID, rec.billingRef, rec.digest)
		if err != nil {
			return exchange.Wrap(exchange.KindInternal, err, "store billing ref")
		}
		if !won {
			return nil
		}
		// Actor is the caller's verified directory identity. Unlike the admin
		// plane, which has no per-operator identity in v1, a registration is
		// signed by the agent it registers, so there is a real actor to record.
		actor := rec.agentID
		return appendAudit(ctx, tx, s.audit, repo.AuditEntry{
			Actor:      &actor,
			SourceAddr: rec.sourceAddr,
			// The action names the service method that made the change, which
			// is what every other audit row does — including
			// SetDefaultAgentCredit, which has no RPC of its own.
			Action:    registerAuditAction,
			Detail:    detail,
			TenantID:  rec.tenantID,
			RequestID: requestIDPtr(reqctx.RequestID(ctx)),
		})
	}); err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "record registration")
	}
	return nil
}

// registrationDataBounds rejects a registration_data payload that crosses one of
// the protocol's bounds, using the shared SDK check so this Exchange and the
// agent that pre-checks locally can never disagree about the same payload. The
// SDK fixes both the bounds (64 top-level members, 32 nested containers, 16384
// bytes of RFC 8785 canonical JSON) and the order they are applied in.
//
// It is handed the RAW Struct, not the converted map, and that is the whole
// reason this face exists. Two values cross the wire intact and have no JSON
// representation at all: a non-finite number, because Struct's number_value is
// an IEEE-754 double that carries NaN and the infinities perfectly well, and a
// Value with no member of its kind oneof set, which the binary decoder accepts
// and proto-JSON refuses to render. Converting first destroys the evidence for
// both. AsMap renders a non-finite double as the string "NaN", "Infinity" or
// "-Infinity", which a payload may legitimately carry, and renders an unset kind
// as nil, which is what a real JSON null gives. A map-based check therefore sees
// a well-formed value in both cases and accepts a payload that a Python or
// TypeScript Exchange refuses — two conformant implementations answering the
// same signed request differently.
//
// A violation here is a MALFORMED REQUEST, not a schema failure: it is
// KindInvalidRequest (InvalidArgument at the wire) carrying no
// RegistrationFailureReason, because INVALID_REGISTRATION_DATA names
// non-conformance to a published schema and applies only when one is published.
// It runs before any write, so a refusal leaves nothing persisted.
//
// The coarser whole-body read cap (transport.MaxRPCReadBytes) sits in front of
// this; this is the tighter, semantic limit.
func registrationDataBounds(payload *structpb.Struct) error {
	verdict := helpers.CheckRegistrationDataStruct(payload)
	if verdict == helpers.RegistrationDataAccepted {
		return nil
	}
	return exchange.Newf(exchange.KindInvalidRequest,
		"registration_data is malformed: %s", boundsMessage(verdict, payload)).
		WithField("registration_data")
}

// boundsMessage names WHICH bound a rejected payload crossed. The verdict token
// alone ("too_deep") does not tell a caller what number it exceeded, so each
// message carries the SDK's own constant rather than a copy of the number.
//
// The no-JSON-form verdict has no number to carry, so it names the offending
// member instead — the payload is passed in for that one case, and for no other.
// The SDK reports the class and not the member, and with up to 64 top-level
// members the class alone leaves a caller nothing to search for.
func boundsMessage(verdict helpers.RegistrationDataVerdict, payload *structpb.Struct) string {
	switch verdict {
	case helpers.RegistrationDataTooManyMembers:
		return fmt.Sprintf("more than %d top-level members", helpers.MaxRegistrationDataMembers)
	case helpers.RegistrationDataTooDeep:
		return fmt.Sprintf("nested more than %d containers deep", helpers.MaxRegistrationDataDepth)
	case helpers.RegistrationDataTooLarge:
		return fmt.Sprintf("larger than %d bytes in its canonical (RFC 8785) form",
			helpers.MaxRegistrationDataBytes)
	case helpers.RegistrationDataUncanonicalizable:
		// The byte bound is DEFINED as the length of the canonical encoding, so a
		// payload with no encoding has no length to report and "too large" would
		// state a measurement nobody took. Both members of the class are named,
		// because neither survives into the stored form to be found later.
		where := "carries a value"
		if member, ok := noJSONFormMember(payload); ok {
			where = fmt.Sprintf("member %q holds a value", member)
		}
		return where + " with no JSON form — a non-finite number (NaN or an " +
			"infinity), or a value with no type set — so the payload has no canonical " +
			"(RFC 8785) form and cannot be measured or stored"
	case helpers.RegistrationDataNoVerdict, helpers.RegistrationDataAccepted:
		// Neither is reachable: Accepted returns before this is called, and the
		// SDK documents NoVerdict as never returned. Answering with the token
		// keeps an unexpected verdict legible instead of silently empty.
		return verdict.String()
	default:
		return verdict.String()
	}
}

// acceptedTermsDigest applies the terms gate and reports which digest this
// registration accepted, or nil when there is nothing to record.
//
// The protocol fixes four cases, and this is the only place they are decided:
//
//	published, presented matches  -> proceed, and record the digest
//	published, presented differs  -> refuse as stale
//	published, presented absent   -> refuse as stale
//	not published, any presented  -> ignore the value, record nothing
//
// The last two lines are the ones worth stating plainly. An absent digest is
// refused rather than waved through, because the caller is claiming acceptance
// of terms it never named — and it gets the SAME reason as a mismatch, since the
// remedy is identical: fetch the terms this Exchange publishes, hash them, and
// register again. When no digest is published there is nothing to accept, so a
// submitted value is neither checked nor stored; recording it would assert an
// acceptance the Exchange cannot back with a terms document.
//
// The gate runs on FIRST registration only. A repeat returns the stored
// billing_ref through Register's fast path and accepts nothing a second time,
// which is what keeps a published terms revision from breaking the replay
// RegisterRequest documents.
func (s *ExchangeService) acceptedTermsDigest(presented string) (*string, error) {
	if s.cfg.TermsDigest == "" {
		return nil, nil
	}
	if presented != s.cfg.TermsDigest {
		return nil, termsDigestStale(s.cfg.TermsDigest)
	}
	accepted := s.cfg.TermsDigest
	return &accepted, nil
}

// GetAccountStatus reports the calling agent's account state (ADR-021). It
// resolves identity from the verified request signature the same way Register
// does, reads the billing_ref stored on the agent's ramp.agents row, and returns
// {billing_ref, active, terms_digest}. An identity with no stored billing_ref is
// not registered for paid content yet and surfaces NotFound; an account that
// exists but is switched off is active=false, never NotFound.
//
// terms_digest is the read side of the acceptance this Exchange recorded at
// registration. The protocol requires an Exchange holding one to return it, and
// gives absence exactly one meaning: no acceptance is recorded. Two situations
// produce that — this Exchange publishes no digest, so nothing was ever accepted,
// or the account predates the one it publishes now. Withholding a digest we hold
// would make the field say something untrue, so the stored column is returned
// whatever it holds and nothing is ever synthesised into it.
//
// The value is what was ACCEPTED, never what is published now. The two diverge
// the moment the operator revises its terms, and that divergence is the point: an
// agent compares this against a freshly fetched manifest digest to discover the
// terms moved under an account it already holds. A repeat Register will not tell
// it — a repeat is answered from the stored record and runs no gate.
//
// The contract also carries a message rule joining the digest to the account
// handle it hangs on: terms_digest may be present only when billing_ref is. This
// method satisfies it structurally rather than by a branch — the empty-ref case
// above has already returned NotFound, so every response that reaches the return
// below carries a billing_ref.
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
		Ver:         helpers.ProtocolVersion,
		BillingRef:  agent.BillingRef,
		Active:      active,
		TermsDigest: agent.AcceptedTermsDigest,
	}, nil
}
