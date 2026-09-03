package service

import (
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// maxIdempotencyKeyLen bounds the idempotency_key, which is threaded to the billing
// adapter as the idempotency key. 256 bytes is generous for any UUID/ULID/hash
// id while keeping the adapter dedup maps from growing by caller-supplied length.
const maxIdempotencyKeyLen = 256

// maxRequesterDomainLen is the RFC 1035 maximum length of a DNS name, and bounds
// requester.domain — the one caller-influenced value on the execute path that
// nothing else constrains. The proto validates only requester.type, and the
// domain is an AgentAcceptancePayload input, so it lands verbatim in an
// append-once evidence row that has no deletion path. The acceptance signature is
// no mitigation: the agent signs the requester it chose, with its own key, so an
// attacker signs whatever domain it likes. Mirrored by a CHECK on the column, so
// the bound holds even for a future writer that skips this validation.
//
// The unit is BYTES on both sides, and that is load-bearing rather than
// incidental: RFC 1035's limit counts octets, len() counts bytes, and the
// column's CHECK uses octet_length for the same reason. A character-counting
// CHECK would admit a 253-character internationalized domain of roughly 600
// bytes — making the layer designated as the backstop the looser of the two.
const maxRequesterDomainLen = 253

// verifyPresentedOffer verifies the PRESENTED, reflected Offer statelessly
// against the Exchange's own public key over the exact presented bytes
// (expires_at INCLUDED), then enforces the signed expiry against the service
// clock. There is NO reconstruct-from-catalog: the offer the agent presents is
// the offer the Exchange signed at discovery, and any post-discovery tamper of a
// covered field (price, terms, expiry, offer_id, …) breaks the signature.
//
// It returns the canonical bytes the signature was verified over, so the value
// persisted as evidence is the one this check actually consumed. The SDK verifies
// and discards them, so they are recomputed here — but from THIS offer, at THIS
// site, one statement after the verify. Deriving them again further down the call
// stack, from a separately assembled argument list, is what would let the stored
// bytes drift from the verified ones without anything failing until a dispute.
//
// Error mapping (ADR-019 denial vocabulary):
//   - helpers.ErrOfferSignatureInvalid → KindSignatureInvalid
//     (Unauthenticated / DENIAL_REASON_SIGNATURE_INVALID). Checked first, so a
//     tampered offer never leaks freshness state.
//   - helpers.ErrOfferExpired → KindOfferExpired
//     (Unauthenticated / DENIAL_REASON_OFFER_EXPIRED) — a stale-but-authentic
//     offer is NOT mislabeled as a signature failure.
func (s *ExchangeService) verifyPresentedOffer(offer *rampv1.Offer) ([]byte, error) {
	err := helpers.VerifyPresentedOffer(offer, s.offerSigner.PublicKey(), s.clk.Now())
	switch {
	case err == nil:
		canonical, cErr := helpers.CanonicalOfferBytes(offer)
		if cErr != nil {
			return nil, exchange.Wrap(exchange.KindInternal, cErr, "compute canonical offer bytes")
		}
		return canonical, nil
	case errors.Is(err, helpers.ErrOfferExpired):
		return nil, exchange.Wrap(exchange.KindOfferExpired, err, "presented offer expired")
	case errors.Is(err, helpers.ErrOfferSignatureInvalid):
		return nil, exchange.Wrap(exchange.KindSignatureInvalid, err, "presented offer signature verification")
	default:
		// A nil offer or a malformed key length surfaces here; treat as a bad
		// request rather than a signature/expiry denial.
		return nil, exchange.Wrap(exchange.KindInvalidRequest, err, "verify presented offer")
	}
}

// billingResolution names the inputs resolveBilling consumes so the call
// site stays under the per-function arg cap.
type billingResolution struct {
	tenantID string
	// billingRef is the paying account handle from the agent's ramp.agents row
	// (ADR-021 D5). It selects the ledger account the charge lands on; it is
	// never the caller's wire label. Empty means the agent is not registered.
	billingRef     string
	pricing        PricingDoc
	idempotencyKey string // = tx_request.id; anchors the billing lifecycle
	// resourceOwnerID is the catalog entry's owner-attested payee; feeRateBps is
	// the effective commission resolved at Authorize. Both ride onto the
	// AuthorizeRequest so a settling adapter freezes the split on the hold.
	resourceOwnerID string
	feeRateBps      int
}

// resolveBilling returns an AuthorizeResult for the transaction. It is the PAID
// path only — runBatchItemBilling calls it after the pricing.IsFree() bypass, so
// the free path never reaches here. An agent with no billing_ref never registered
// (ADR-021 D5), so it has no account to charge: deny before Authorize with a plain
// message, no side effects. A registered agent whose account the operator switched
// off in the SoR is denied next (checkAccountActive), still before any money is
// reserved. The ref comes only from the agent's row (resolveAgent), never from
// the caller's wire label, so a caller cannot spend another account.
func (s *ExchangeService) resolveBilling(
	ctx context.Context, in billingResolution,
) (billing.AuthorizeResult, error) {
	if in.billingRef == "" {
		return billing.AuthorizeResult{}, exchange.Newf(exchange.KindAccountNotRegistered,
			"agent is not registered for paid content: call Register first")
	}
	if err := s.checkAccountActive(ctx, in.billingRef); err != nil {
		return billing.AuthorizeResult{}, err
	}
	return s.authorizeBilling(ctx, in)
}

// checkAccountActive denies a paid transaction from an account the operator has
// switched off in the system of record. It runs on the paid path only, after
// the registration check and before any money is reserved. The read goes
// through the SoR adapter the service was wired with — in production that is
// the 30-second read-through cache (sor.CachingAdapter), so the SoR itself is
// asked at most once per cache lifetime per account and an operator's change
// takes effect within one lifetime.
//
// Error policy (ADR-021 Follow-up): definitive answers fail closed — a
// known-but-switched-off account and an account the SoR does not know are both
// denied in-body with DENIAL_REASON_ACCOUNT_INACTIVE. Transient read
// errors fail open — the transaction proceeds with a warning log, because the
// ledger balance check still bounds spending, a SoR outage must not stop every
// paid transaction, and the cache never stores errors, so enforcement resumes
// the moment the SoR answers again.
func (s *ExchangeService) checkAccountActive(ctx context.Context, billingRef string) error {
	active, err := s.sor.IsActive(ctx, billingRef)
	switch {
	case errors.Is(err, sor.ErrAccountNotFound):
		return exchange.Wrap(exchange.KindAccountInactive, err,
			"no billing account found for this agent: contact the operator")
	case err != nil:
		// Transient-only bucket (SoR unreachable, timing out). A definitive
		// negative answer must be classified above, next to ErrAccountNotFound,
		// so it fails closed instead of sliding into this fail-open arm.
		// The message is the op name and the condition lives in the "event"
		// attr, sharing logOutcome's greppable style: an operator following a
		// transaction's log stream by message sees the fail-open events too.
		reqctx.FromContext(ctx).WarnContext(ctx, "exchange.execute_transaction",
			"event", "sor_active_check_failed",
			"err", err.Error())
		return nil
	case !active:
		return exchange.Newf(exchange.KindAccountInactive,
			"account is switched off: contact the operator to turn it back on")
	default:
		return nil
	}
}

// authorizeBilling reserves funds for the transaction.
func (s *ExchangeService) authorizeBilling(
	ctx context.Context, in billingResolution,
) (billing.AuthorizeResult, error) {
	pricing := in.pricing
	quantity := int64(pricing.EstQty)
	if quantity <= 0 {
		quantity = 1
	}
	// pricing.UnitCost is already an exact decimal; pass its canonical string form
	// to billing.NewAmount directly. The prior fmt.Sprintf("%.8f", ...) round-trip
	// through float64 is gone — it was a precision-loss step the money-as-string
	// migration removes.
	amount, err := billing.NewAmount(pricing.UnitCost.String(), pricing.Currency)
	if err != nil {
		return billing.AuthorizeResult{}, exchange.Wrap(exchange.KindInternal, err, "parse unit cost")
	}
	res, err := s.billing.Authorize(ctx, billing.AuthorizeRequest{
		TenantID:        in.tenantID,
		BillingRef:      in.billingRef,
		UnitCost:        amount,
		Quantity:        quantity,
		Unit:            pricing.Unit,
		IdempotencyKey:  in.idempotencyKey,
		ResourceOwnerID: in.resourceOwnerID,
		FeeRateBps:      in.feeRateBps,
	})
	if err != nil {
		// Map the adapter sentinel to its domain Kind (e.g. a hard
		// ErrInsufficientBalance → KindBillingDenied, not KindInternal).
		return billing.AuthorizeResult{}, exchange.Wrap(billingErrorKind(err), err, "billing authorize")
	}
	if !res.Approved {
		return res, exchange.Newf(exchange.KindBillingDenied, "billing denied: %s", res.Reason)
	}
	return res, nil
}

// hasNoReservation reports whether no billing reservation handle was taken: an
// empty billingID means no Authorize ran (or the adapter minted no handle). Per
// ADR-009 D5 the free path has two shapes — the price-zero bypass persists an
// empty handle (hasNoReservation true), while a FreeAdapter-served resource
// mints a ULID (hasNoReservation false) — so this is NOT "is the resource
// free"; it is "is there a reservation to release". releaseHold keys off it:
// with no handle there is nothing to release. The paid path always carries a
// non-empty ULID handle from Authorize, so the empty check is exact.
func hasNoReservation(billingID string) bool { return billingID == "" }

// mintSignedURL dispatches to the correct URL signer based on the tenant's
// signing scheme and returns a ready-to-embed SignedURL. agentThumbprint, when
// non-empty, is embedded as the `agent_id` query parameter and covered by the
// signature, binding the URL to the requesting agent's key (ADR-013).
func (s *ExchangeService) mintSignedURL(
	ctx context.Context,
	tenant repo.Tenant,
	entry repo.CatalogEntry,
	agentThumbprint string,
) (helpers.SignedURL, error) {
	urlSigner, err := signing.URLSignerFor(signing.TenantKeys{
		Scheme:              signing.Scheme(tenant.SigningScheme),
		Ed25519Ref:          tenant.Ed25519KeyRef,
		RSARef:              tenant.RSAKeyRef,
		CloudFrontKeyPairID: tenant.CloudFrontKeyPairID,
	}, s.keyStore)
	if err != nil {
		// A deliberately unprovisioned RSA key is a configuration precondition,
		// not a server fault: the operator chose to run without one and a
		// CloudFront-scheme tenant arrived anyway. FailedPrecondition mirrors
		// the unseeded-default-tenant mapping in Register — same class of
		// deterministic, operator-fixable state. Everything else on this path
		// (unknown scheme, missing key ref, corrupt key) stays Internal.
		//
		// The caller gets a sanitized message: which env vars supply the key is
		// operator knowledge, and the operator reads server logs, not agent
		// responses — so the full refusal (env-var guidance included) goes
		// through the request-scoped logger and only the plain condition
		// crosses the wire.
		if errors.Is(err, signing.ErrRSAKeyUnavailable) {
			reqctx.FromContext(ctx).WarnContext(ctx, "exchange.execute_transaction",
				"event", "url_signer_unprovisioned",
				"tenant_id", tenant.ID,
				"err", err.Error())
			return helpers.SignedURL{}, exchange.Newf(exchange.KindFailedPrecondition,
				"delivery URL signing is not provisioned for this publisher")
		}
		return helpers.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "resolve url signer")
	}
	signed, err := urlSigner.SignURL(ctx, entry.URI, agentThumbprint, s.clk.Now().Add(s.cfg.URLTTL))
	if err != nil {
		return helpers.SignedURL{}, exchange.Wrap(exchange.KindInternal, err, "sign url")
	}
	return signed, nil
}

func maxInt32(v, fallback int32) int32 {
	if v <= 0 {
		return fallback
	}
	return v
}

// logOutcome emits one structured log line per ExecuteTransaction or
// ReportUsage attempt, correlated by request_id. tenant may be nil (e.g. for
// failures that happen before tenant resolution). err is the
// outcome-classifying error; nil on success.
func (s *ExchangeService) logOutcome(
	ctx context.Context, op, outcome string,
	caller Caller, tenant *repo.Tenant,
	agentID, transactionID string,
	err *exchange.Error,
) {
	attrs := []any{
		"op", op,
		"outcome", outcome,
		"caller_keyid", caller.KeyID,
		"caller_kind", callerKindLabel(caller.Kind),
		"agent_id", agentID,
		"transaction_id", transactionID,
	}
	if tenant != nil {
		attrs = append(attrs, "tenant_id", tenant.ID)
	}
	// Emit through the request-scoped logger (reqctx.FromContext) so the
	// outcome line carries the request_id that RequestIDMiddleware bound onto
	// the context logger. The construction-time s.logger has no request_id
	// attribute, so logging through it would silently drop the correlation
	// this doc comment promises. Falls back to
	// slog.Default() when no middleware ran (e.g. a direct service call).
	logger := reqctx.FromContext(ctx)
	if err != nil {
		attrs = append(attrs, "kind", err.Kind.String(), "err", err.Message)
		logger.WarnContext(ctx, "exchange."+op, attrs...)
		return
	}
	logger.InfoContext(ctx, "exchange."+op, attrs...)
}

func callerKindLabel(k CallerKind) string {
	switch k {
	case CallerAgent:
		return "agent"
	case CallerBroker:
		return "broker"
	default:
		return "unknown"
	}
}
