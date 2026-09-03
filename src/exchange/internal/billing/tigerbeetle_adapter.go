package billing

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
)

const (
	// defaultHoldTimeout backstops the pending expiry when none is wired: the
	// signed-URL TTL (5m) plus a 1m grace so a settle/void can still land at the
	// edge of URL validity. Boot wiring overrides it with the real URLTTL + grace.
	defaultHoldTimeout = 6 * time.Minute
	// maxAuthGenerations bounds the hold-generation probe (a resolved hold cannot
	// reuse its permanent transfer id, so Authorize advances to a fresh generation).
	// In practice the generation is 0 or 1; the bound is a runaway backstop.
	maxAuthGenerations = 256
)

var errAuthGenerationsExhausted = errors.New("billing: authorize exhausted hold generations")

// TigerBeetleAdapter is the persisted billing.Adapter backed by a TigerBeetle
// ledger. The agent-balance lifecycle maps onto two-phase transfers: Authorize is a
// pending transfer, Record posts it, Release voids it. Idempotency is ledger-native
// (deterministic transfer ids → duplicate-id rejection), never an in-process map.
// Record posts the two-posting owner/platform settlement split at the rate frozen on
// the hold, and Refund reverses that split proportionally off the posted fee; both are
// idempotent via check-then-act on deterministic leg ids.
type TigerBeetleAdapter struct {
	tb          *tigerbeetle.Client
	ledger      uint32
	currency    string
	holdTimeout time.Duration
	// idNS namespaces every derived account/transfer id. It is empty in production
	// (hashing stays unsalted); tests set a unique value per instance so cases on
	// the shared cluster never collide.
	idNS string
}

// TigerBeetleOptions configures a TigerBeetleAdapter. HoldTimeout falls back
// to the package default when zero. The asset scale is not an option: it is
// deliberately fixed at money.AssetScale for every deployment.
type TigerBeetleOptions struct {
	Client      *tigerbeetle.Client
	Ledger      uint32
	Currency    string
	HoldTimeout time.Duration
	IDNamespace string
}

// NewTigerBeetleAdapter builds an adapter from opts.
func NewTigerBeetleAdapter(opts TigerBeetleOptions) *TigerBeetleAdapter {
	a := &TigerBeetleAdapter{
		tb:          opts.Client,
		ledger:      opts.Ledger,
		currency:    opts.Currency,
		holdTimeout: opts.HoldTimeout,
		idNS:        opts.IDNamespace,
	}
	if a.holdTimeout <= 0 {
		a.holdTimeout = defaultHoldTimeout
	}
	return a
}

var _ Adapter = (*TigerBeetleAdapter)(nil)

// Health reports whether the ledger is answering. It is deliberately NOT part of
// the Adapter interface: the free and in-memory adapters have no backend to probe,
// so requiring the method of them would buy a nil-returning stub apiece and say
// nothing. The composition root type-asserts for it instead, which is what makes
// /readyz cover the ledger only on the deployment that actually has one.
//
// The caller owns the deadline. Client.Health otherwise runs to the client's
// op-timeout (5s by default), which is too long for a readiness probe — pass a
// context with a tighter bound.
func (a *TigerBeetleAdapter) Health(ctx context.Context) error {
	return a.tb.Health(ctx)
}

// classifyUnavailable threads ErrBackendUnavailable into the error chain when a
// TigerBeetle call hit its deadline (tigerbeetle.ErrUnavailable), so the service
// maps the failure to a retryable KindUnavailable instead of KindInternal. Every
// other error passes through unchanged. It is applied at each public method's
// return via a deferred assignment on the named error result, so a timeout at any
// call depth is classified once, at the boundary.
func classifyUnavailable(err error) error {
	if err != nil && errors.Is(err, tigerbeetle.ErrUnavailable) {
		return fmt.Errorf("%w: %w", ErrBackendUnavailable, err)
	}
	return err
}

// Authorize reserves the estimated charge as a pending transfer against the agent
// account. Insufficient balance is a soft denial (Approved=false), matching
// InMemoryAdapter. Idempotent on (billing_ref, IdempotencyKey) while the hold is live.
//
// Deliberate divergences from InMemoryAdapter, all persisted-ledger consequences
// (gated in the shared conformance suite by the requiresIdempotencyKey capability
// where they change an outcome):
//   - an empty idempotency key is soft-denied (see the guard below), not executed;
//   - an unknown agent is lazily created as a zero-balance account, so a non-zero
//     charge is denied as "insufficient balance" rather than "unknown account";
//   - a zero-cost term creates a real zero-amount pending (valid since TigerBeetle
//     0.16) that settles nothing, rather than short-circuiting.
func (a *TigerBeetleAdapter) Authorize(ctx context.Context, req AuthorizeRequest) (res AuthorizeResult, err error) {
	defer func() { err = classifyUnavailable(err) }()
	if req.IdempotencyKey == "" {
		// A persisted ledger requires an idempotency anchor. An empty key derives
		// the same hold id for every empty-key authorize on the same account, so
		// two of them would share and cross-settle one hold. The InMemory contract
		// permits an empty key (no dedup, always executes); a persisted adapter
		// refuses it. The RPC boundary already guarantees a non-empty key, so this
		// is a defense-in-depth guard rather than a reachable path.
		return AuthorizeResult{Approved: false, Reason: "idempotency key required"}, nil
	}
	if req.BillingRef == "" {
		// An empty billing_ref derives the same, ref-independent account for every
		// unregistered caller, so two agents would share and cross-settle one
		// account. The service denies an unregistered agent before it ever reaches
		// the adapter (it has no ref to spend), so this is a defense-in-depth guard
		// against a shared empty-ref account, not a reachable path.
		return AuthorizeResult{Approved: false, Reason: "billing ref required"}, nil
	}
	if req.Quantity <= 0 {
		return AuthorizeResult{Approved: false, Reason: "non-positive quantity"}, nil
	}
	// The charge currency must match the configured ledger currency: the amount is
	// posted in the ledger's minor units, so a mismatched label would silently
	// relabel the money. A zero-cost term settles nothing, so — like InMemory — the
	// held currency is irrelevant there and the gate is skipped.
	if req.UnitCost.Value.Sign() != 0 && req.UnitCost.Currency != a.currency {
		return AuthorizeResult{Approved: false, Reason: "currency mismatch"}, nil
	}
	minor, err := a.toMinor(totalCharge(req.UnitCost, req.Quantity))
	if err != nil {
		return AuthorizeResult{}, err
	}
	agentAcct, err := a.accountID(tigerbeetle.PrefixAgent, req.BillingRef)
	if err != nil {
		return AuthorizeResult{}, err
	}
	ownerID, err := a.ownerAccount(req.ResourceOwnerID)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if err := a.ensureAccounts(ctx, agentAcct, ownerID); err != nil {
		return AuthorizeResult{}, err
	}
	denial, ok, err := a.checkBalance(ctx, agentAcct, minor)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if !ok {
		return denial, nil
	}
	return a.reserve(ctx, holdParams{
		billingRef: req.BillingRef, authKey: req.IdempotencyKey,
		agentAcct: agentAcct, owner: ownerID, minor: minor, bps: req.FeeRateBps,
	})
}

// holdParams bundles the values Authorize freezes on a hold: the paying account's
// billing_ref (part of the pending id so two accounts sharing one idempotency key
// get separate holds), the ledger account debited, the resource-owner account
// credited, the gross in minor units, and the commission rate in basis points
// (stamped on the pending's user_data so Record recovers it).
type holdParams struct {
	billingRef string
	authKey    string
	agentAcct  tigerbeetle.ID
	owner      tigerbeetle.ID
	minor      *big.Int
	bps        int
}

// reserve runs the generation probe: it finds the first hold generation for authKey
// that is free (create it) or live (return its id), skipping resolved generations.
func (a *TigerBeetleAdapter) reserve(ctx context.Context, h holdParams) (AuthorizeResult, error) {
	for gen := 0; gen < maxAuthGenerations; gen++ {
		pendingID, err := a.pendingID(h.billingRef, h.authKey, gen)
		if err != nil {
			return AuthorizeResult{}, err
		}
		state, _, err := a.classifyHold(ctx, pendingID, "authorize")
		if err != nil {
			return AuthorizeResult{}, err
		}
		switch state {
		case tigerbeetle.HoldLive:
			return AuthorizeResult{BillingID: tigerbeetle.EncodeID(pendingID), Approved: true}, nil
		case tigerbeetle.HoldFree:
			return a.createHold(ctx, pendingID, h)
		case tigerbeetle.HoldResolved:
			continue
		}
	}
	return AuthorizeResult{}, errAuthGenerationsExhausted
}

func (a *TigerBeetleAdapter) createHold(
	ctx context.Context, pendingID tigerbeetle.ID, h holdParams,
) (AuthorizeResult, error) {
	bps := uint64(0)
	if h.bps > 0 {
		bps = uint64(h.bps)
	}
	out, err := a.tb.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID:          pendingID,
		Debit:       h.agentAcct,
		Credit:      h.owner,
		Amount:      h.minor,
		Ledger:      a.ledger,
		Timeout:     a.timeoutSeconds(),
		UserData128: tigerbeetle.IDFromUint64(bps),
	})
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("billing: create hold: %w", err)
	}
	switch out {
	case tigerbeetle.PendingCreated, tigerbeetle.PendingExists:
		return AuthorizeResult{BillingID: tigerbeetle.EncodeID(pendingID), Approved: true}, nil
	case tigerbeetle.PendingInsufficientFunds:
		return AuthorizeResult{Approved: false, Reason: "insufficient balance"}, nil
	default:
		return AuthorizeResult{}, fmt.Errorf("billing: unexpected pending outcome %v", out)
	}
}

// Record settles the reserved hold by posting the revenue/fee split at the rate frozen
// on the hold. Idempotency is check-then-act: a hold already settled re-derives the same
// post id, which is looked up (not blindly re-issued — a duplicate inside a linked batch
// can break the chain). The advisory quantity and key are unused; the settled amount is
// the reserved gross.
func (a *TigerBeetleAdapter) Record(ctx context.Context, billingID string, _ int64, _ string) (err error) {
	defer func() { err = classifyUnavailable(err) }()
	pendingID, err := tigerbeetle.DecodeID(billingID)
	if err != nil {
		return ErrUnknownBillingID
	}
	state, postID, err := a.classifyHold(ctx, pendingID, "record")
	if err != nil {
		return err
	}
	switch state {
	case tigerbeetle.HoldFree:
		return ErrUnknownBillingID
	case tigerbeetle.HoldResolved:
		_, settled, lErr := a.tb.LookupTransfer(ctx, postID)
		if lErr != nil {
			return fmt.Errorf("billing: record lookup post: %w", lErr)
		}
		if settled {
			return nil // already recorded — idempotent no-op
		}
		return ErrUnknownBillingID // voided (released), not recordable
	}
	return a.settleSplit(ctx, pendingID, postID)
}

// Release voids the hold. A replay re-derives the same void-transfer id → no-op
// success; an already-resolved or unknown hold returns ErrUnknownBillingID (callers
// treat it as a successful no-op for Release).
func (a *TigerBeetleAdapter) Release(ctx context.Context, billingID string, _ string) (err error) {
	defer func() { err = classifyUnavailable(err) }()
	pendingID, err := tigerbeetle.DecodeID(billingID)
	if err != nil {
		return ErrUnknownBillingID
	}
	_, voidID, err := a.resolveIDs(pendingID)
	if err != nil {
		return err
	}
	out, err := a.tb.VoidPending(ctx, tigerbeetle.ResolveParams{ID: voidID, PendingID: pendingID})
	if err != nil {
		return fmt.Errorf("billing: release: %w", err)
	}
	return resolveErr(out)
}

// Refund reverses a settled charge, proportionally splitting the reversal back out of
// the resource-owner and platform accounts using the fee posted at settlement. It is
// idempotent per (billingID, key) via check-then-act on the deterministic refund-leg
// ids; a token of the reason (first 8 bytes of its sha256) is stamped on the net
// leg's user_data_64 as a verifiable, PII-free audit trace (TigerBeetle has no
// free-text field). The token is frozen at the first refund — an idempotent replay is
// a no-op and keeps the original.
func (a *TigerBeetleAdapter) Refund(
	ctx context.Context, billingID string, amount Amount, reason, key string,
) (err error) {
	defer func() { err = classifyUnavailable(err) }()
	pendingID, err := tigerbeetle.DecodeID(billingID)
	if err != nil {
		return ErrUnknownBillingID
	}
	if cErr := a.classifyForRefund(ctx, pendingID); cErr != nil {
		return cErr
	}
	rMinor, err := a.refundMinor(amount)
	if err != nil {
		return err
	}
	netID, feeID, err := a.refundLegIDs(pendingID, key)
	if err != nil {
		return err
	}
	_, replay, err := a.tb.LookupTransfer(ctx, netID)
	if err != nil {
		return fmt.Errorf("billing: refund lookup: %w", err)
	}
	if replay {
		return nil // idempotent replay — no-op against both accounts
	}
	return a.reverseRefund(ctx, refundReq{
		pendingID: pendingID, netID: netID, feeID: feeID, rMinor: rMinor, reason: reason,
	})
}

// GetBalance returns the settled balance (credits_posted − debits_posted); pending
// holds are excluded, matching InMemoryAdapter. An unknown account is an error.
func (a *TigerBeetleAdapter) GetBalance(ctx context.Context, billingRef string) (amt Amount, err error) {
	defer func() { err = classifyUnavailable(err) }()
	id, err := a.accountID(tigerbeetle.PrefixAgent, billingRef)
	if err != nil {
		return Amount{}, err
	}
	acc, found, err := a.tb.LookupAccount(ctx, id)
	if err != nil {
		return Amount{}, fmt.Errorf("billing: get balance: %w", err)
	}
	if !found {
		return Amount{}, fmt.Errorf("billing: unknown account %q", billingRef)
	}
	bal := new(big.Int).Sub(acc.CreditsPosted.BigInt(), acc.DebitsPosted.BigInt())
	return a.fromMinor(bal), nil
}

// GetQuota returns 0 (no cap): a unit-count quota is not modelled on the ledger. The
// conformance suite neither seeds nor asserts quota, so parity holds.
func (a *TigerBeetleAdapter) GetQuota(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// checkBalance pre-checks available funds (credits_posted − debits_posted −
// debits_pending) so an insufficient balance is a clean soft denial rather than a
// failed transfer whose (poisoned) id could never be retried.
func (a *TigerBeetleAdapter) checkBalance(
	ctx context.Context, agentAcct tigerbeetle.ID, minor *big.Int,
) (AuthorizeResult, bool, error) {
	acc, found, err := a.tb.LookupAccount(ctx, agentAcct)
	if err != nil {
		return AuthorizeResult{}, false, fmt.Errorf("billing: lookup agent: %w", err)
	}
	available := new(big.Int)
	if found {
		available.Sub(acc.CreditsPosted.BigInt(), acc.DebitsPosted.BigInt())
		available.Sub(available, acc.DebitsPending.BigInt())
	}
	if available.Cmp(minor) < 0 {
		return AuthorizeResult{Approved: false, Reason: "insufficient balance"}, false, nil
	}
	return AuthorizeResult{}, true, nil
}

// pendingID derives the hold's transfer id from the paying account's billing_ref,
// the caller's idempotency key, and the generation. The billing_ref is part of the
// id so two accounts that reuse the same idempotency key derive different holds and
// cannot collide on one shared pending — each settles only its own account. The
// boundary between the ref and the key stays unambiguous because billing_ref is
// server-minted (a UUID, ADR-021 D1) and never contains a colon; the caller may put
// colons in the key, but the key sits AFTER the ref, so it cannot shift where the
// ref ends. The guard below enforces that invariant instead of trusting it: a
// colon-bearing ref (a future generator bug) fails loudly here rather than
// silently deriving an id another account could also derive.
func (a *TigerBeetleAdapter) pendingID(billingRef, authKey string, gen int) (tigerbeetle.ID, error) {
	if strings.Contains(billingRef, ":") {
		return tigerbeetle.ID{}, fmt.Errorf("billing: billing_ref %q must not contain ':'", billingRef)
	}
	businessID := a.idNS + tigerbeetle.TransferPendingPrefix +
		billingRef + ":" + authKey + ":" + strconv.Itoa(gen)
	id, err := tigerbeetle.TransferID(businessID)
	if err != nil {
		return id, fmt.Errorf("billing: derive pending id: %w", err)
	}
	return id, nil
}

// resolveIDs derives the post and void transfer ids from the pending id (not the
// caller's key), so the Authorize probe can compute them without knowing the
// Record/Release key, and a replay re-derives the same id.
func (a *TigerBeetleAdapter) resolveIDs(pendingID tigerbeetle.ID) (postID, voidID tigerbeetle.ID, err error) {
	hexID := tigerbeetle.EncodeID(pendingID)
	if postID, err = tigerbeetle.TransferID(a.idNS + tigerbeetle.TransferPostPrefix + hexID); err != nil {
		return postID, voidID, fmt.Errorf("billing: derive post id: %w", err)
	}
	if voidID, err = tigerbeetle.TransferID(a.idNS + tigerbeetle.TransferVoidPrefix + hexID); err != nil {
		return postID, voidID, fmt.Errorf("billing: derive void id: %w", err)
	}
	return postID, voidID, nil
}

// classifyHold derives a hold's post/void ids and probes its lifecycle state in
// one round-trip. The three lifecycle callers (reserve, Record, classifyForRefund)
// share this probe and keep their own state-specific switch; op names the caller
// so a ClassifyHold failure is attributable. postID is returned because the
// resolved-state branches look the settled leg up; voidID is only needed for the
// probe itself.
func (a *TigerBeetleAdapter) classifyHold(
	ctx context.Context, pendingID tigerbeetle.ID, op string,
) (state tigerbeetle.HoldState, postID tigerbeetle.ID, err error) {
	var voidID tigerbeetle.ID
	postID, voidID, err = a.resolveIDs(pendingID)
	if err != nil {
		return 0, postID, err
	}
	state, err = a.tb.ClassifyHold(ctx, pendingID, postID, voidID)
	if err != nil {
		return 0, postID, fmt.Errorf("billing: classify hold (%s): %w", op, err)
	}
	return state, postID, nil
}

// timeoutSeconds is the pending hold's TigerBeetle timeout, in seconds. A hold that
// is neither recorded nor released is reclaimed natively by TigerBeetle when the
// timeout elapses, returning the reserved amount to the agent; a late Record/Release
// of an expired hold then maps to ErrUnknownBillingID. The status mapping is
// unit-tested (transfers_status_test.go) and the native-expiry path is driven by a
// short-timeout integration test (TestTigerBeetleExpiry_LateRecordRelease).
func (a *TigerBeetleAdapter) timeoutSeconds() uint32 {
	s := int64(a.holdTimeout / time.Second)
	if s <= 0 {
		return 1
	}
	if s > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(s)
}

// toMinor converts a currency amount to an integer number of minor units at the
// ledger's asset scale. At scale 8 every amount the Exchange produces (8-decimal
// prices) is exact; a value with finer precision is rejected rather than silently
// rounded. The conversion itself is money.MinorUnits so the adapter, the repo
// layer, and the test fixtures share one money-math source of truth.
func (a *TigerBeetleAdapter) toMinor(amt Amount) (*big.Int, error) {
	minor, err := money.MinorUnits(amt.Value)
	if errors.Is(err, money.ErrAmountNotRepresentable) {
		// Translate the conversion-layer sentinel into the billing sentinel so a
		// finer-than-scale price surfaces as KindInvalidRequest (4xx), not a 500.
		return nil, fmt.Errorf("%w: %w", ErrAmountNotRepresentable, err)
	}
	return minor, err
}

func (a *TigerBeetleAdapter) fromMinor(minor *big.Int) Amount {
	return Amount{
		Value:    new(big.Rat).SetFrac(minor, money.ScaleFactor()),
		Currency: a.currency,
	}
}

func resolveErr(out tigerbeetle.ResolveOutcome) error {
	switch out {
	case tigerbeetle.ResolveApplied, tigerbeetle.ResolveExists:
		return nil
	case tigerbeetle.ResolveNotFound, tigerbeetle.ResolveAlreadyResolved:
		return ErrUnknownBillingID
	default:
		return fmt.Errorf("billing: unexpected resolve outcome %v", out)
	}
}
