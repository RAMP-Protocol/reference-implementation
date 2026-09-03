package billing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// op identifiers for the (billingID, op, key) idempotency guard. Package-level
// so a future adapter (TigerBeetle) reuses the exact strings and the guard +
// write-back of a single method cannot drift to different literals.
const (
	opRecord  = "record"
	opRelease = "release"
	opRefund  = "refund"
)

// maxRawKeyLen bounds the idempotency-key bytes retained in the dedup maps. A
// longer key is collapsed to a fixed-width hash by boundKey, so a caller cannot
// grow the maps by submitting ever-longer keys.
const maxRawKeyLen = 256

// reservation tracks a pending Authorize that has not yet been Record'd or
// Release'd.
type reservation struct {
	BillingRef string
	EstAmt     Amount // estimated total charge; the amount Record settles
	EstQty     int64  // authorized quantity; restored to quota on Release
	// AuthKey is the IdempotencyKey supplied at Authorize ("" if none). Record
	// and Release use it to free the live-hold dedup entry on resolve. Stored
	// raw; the bounded form is derived at map-access time via authMapKey.
	AuthKey string
}

// recordedTx retains the settled charge for a billingID after Record so Refund
// can validate against it. (Record removes the reservation; without this the
// refund path could not tell "recorded" from "never issued".)
type recordedTx struct {
	BillingRef string
	Amt        Amount
}

// RefundEntry is the audit memo for a single applied refund. Reason carries the
// dispute-resolution note (ADR-011 D7 inverse-posting memo); it is persisted so
// the partial-refund audit trail survives. Exposed via InMemoryAdapter.RefundLog.
type RefundEntry struct {
	Amt    Amount
	Reason string
	Key    string // idempotencyKey supplied at Refund ("" if none)
}

// InMemoryAdapter is a thread-safe prepaid-balance implementation suitable
// for scrappy-demo and unit tests.
//
// Balance semantics: the actual balance only decreases when Record is called.
// Authorize checks whether the available balance (actual balance minus all
// pending reservations for the same account and currency) covers the requested
// charge; on approval it stores the reservation without touching the actual
// balance. Release returns the reservation with no balance change. Record
// deducts the reservation amount and releases the hold. Refund credits the
// account's balance back, capped at the recorded charge.
type InMemoryAdapter struct {
	mu        sync.Mutex
	balances  map[string]Amount        // billing_ref → actual balance
	quotas    map[string]int64         // billing_ref → remaining quota (unit-agnostic)
	reserved  map[string]reservation   // billing_id → pending reservation
	recorded  map[string]recordedTx    // billing_id → settled charge (for Refund)
	refunded  map[string]*big.Rat      // billing_id → cumulative refunded amount
	refundLog map[string][]RefundEntry // billing_id → ordered refund memos
	authSeen  map[string]string        // (billing_ref, auth_key) → billing_id (live holds)
	// opSeen records processed (billing_id, op, key) tuples for Record/Release/
	// Refund idempotency. It is deliberately NOT bounded by an LRU: evicting a
	// refund entry would let a same-key refund replay re-run validateRefund and
	// credit a SECOND time while still under the cumulative cap — silently
	// breaking refund idempotency. Eviction would be safe for record/release
	// (a replay degrades to ErrUnknownBillingID, never a double-charge) but not
	// for refund, so no eviction happens at all. Count growth is one entry per
	// committed transaction (idempotency_key is UNIQUE); durable unbounded-volume
	// idempotency is the persisted adapter's (TigerBeetle) responsibility, not
	// the demo-tier in-memory adapter's. Per-entry size is bounded by boundKey.
	opSeen map[string]struct{}
	// creditSeen records applied Credit idempotency keys. The key ALONE is the
	// dedup anchor (no billing_ref in the map key), mirroring the persisted
	// adapter where the key alone derives the ledger transfer id.
	creditSeen map[string]struct{}
	nextIdx    uint64
	idPrefix   string
}

// InMemoryOptions seeds an InMemoryAdapter.
type InMemoryOptions struct {
	Balances map[string]Amount
	Quotas   map[string]int64
	IDPrefix string // default "bill-"
}

// NewInMemoryAdapter creates an adapter with the given seed state.
func NewInMemoryAdapter(opts InMemoryOptions) *InMemoryAdapter {
	a := &InMemoryAdapter{
		balances:   map[string]Amount{},
		quotas:     map[string]int64{},
		reserved:   map[string]reservation{},
		recorded:   map[string]recordedTx{},
		refunded:   map[string]*big.Rat{},
		refundLog:  map[string][]RefundEntry{},
		authSeen:   map[string]string{},
		opSeen:     map[string]struct{}{},
		creditSeen: map[string]struct{}{},
		idPrefix:   opts.IDPrefix,
	}
	if a.idPrefix == "" {
		a.idPrefix = "bill-"
	}
	for k, v := range opts.Balances {
		a.balances[k] = Amount{Value: new(big.Rat).Set(v.Value), Currency: v.Currency}
	}
	for k, v := range opts.Quotas {
		a.quotas[k] = v
	}
	return a
}

func seenKey(parts ...string) string { return strings.Join(parts, "\x00") }

// boundKey caps the stored dedup-key size: a key longer than maxRawKeyLen
// collapses to a fixed-width hash so map-entry size cannot grow with key length.
// Short keys pass through unchanged.
func boundKey(key string) string {
	if len(key) <= maxRawKeyLen {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return "h:" + hex.EncodeToString(sum[:])
}

// authMapKey composes the authSeen map key for an account + raw idempotency key.
// boundKey is applied here (not at the call sites) so the Authorize write and
// the freeAuth delete always agree on the stored form.
func authMapKey(billingRef, rawKey string) string {
	return seenKey(billingRef, boundKey(rawKey))
}

// opAlreadyDone reports whether (billingID, op, key) was already processed.
// An empty key disables dedup (always false). Caller holds a.mu.
func (a *InMemoryAdapter) opAlreadyDone(billingID, op, key string) bool {
	if key == "" {
		return false
	}
	_, done := a.opSeen[seenKey(billingID, op, boundKey(key))]
	return done
}

// markOpDone records (billingID, op, key) as processed. Empty key is a no-op.
// Caller holds a.mu.
func (a *InMemoryAdapter) markOpDone(billingID, op, key string) {
	if key == "" {
		return
	}
	a.opSeen[seenKey(billingID, op, boundKey(key))] = struct{}{}
}

// EnsureAgentAccount creates a zero-balance account entry under billingRef so
// the freshly registered agent exists for subsequent balance reads. A repeat
// call — or a ref that already holds a (possibly funded) balance — is a no-op
// success: the existing balance is never reset. The zero balance is denominated
// in DemoCurrency, this tier's currency.
func (a *InMemoryAdapter) EnsureAgentAccount(_ context.Context, billingRef string) error {
	if billingRef == "" {
		return errEmptyBillingRef
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.balances[billingRef]; !ok {
		a.balances[billingRef] = Amount{Value: new(big.Rat), Currency: DemoCurrency}
	}
	return nil
}

// Credit grants a one-time credit to the account's balance, creating the
// account in the amount's currency when it does not exist yet. A replay of an
// already-applied idempotency key is a no-op success regardless of amount —
// the first credit wins, mirroring the persisted adapter's key-derived ledger
// transfer id.
//
// Two currency rules apply, and they catch different faults. The shared gate
// rejects an amount that is not in the deployment currency. The check below
// rejects a credit in the deployment currency against a balance denominated in
// something else — a balance this adapter can only hold if a caller seeded one
// directly. Without the second check a USD grant would pass the gate and be
// added into a EUR balance, leaving a total whose currency label is a lie.
func (a *InMemoryAdapter) Credit(
	_ context.Context, billingRef string, amount Amount, idempotencyKey string,
) error {
	if err := validateCreditArgs(billingRef, amount, idempotencyKey, DemoCurrency); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, done := a.creditSeen[boundKey(idempotencyKey)]; done {
		return nil
	}
	bal, ok := a.balances[billingRef]
	if !ok {
		bal = Amount{Value: new(big.Rat), Currency: amount.Currency}
	}
	// Deliberately a plain error, not ErrInvalidAmount: the credit is valid and
	// the stored balance is not, so this is invalid server state rather than a
	// caller fault. ErrInvalidAmount maps to a 4xx and would blame the Register
	// caller for a seed it never supplied; a plain error falls through to
	// KindInternal.
	if bal.Currency != amount.Currency {
		return fmt.Errorf("billing: account currency %q does not match credit currency %q",
			bal.Currency, amount.Currency)
	}
	bal.Value.Add(bal.Value, amount.Value)
	a.balances[billingRef] = bal
	a.creditSeen[boundKey(idempotencyKey)] = struct{}{}
	return nil
}

// Authorize holds funds for the transaction. A repeat call with the same
// non-empty IdempotencyKey while the hold is live returns the same BillingID
// (no second reservation). Otherwise denies on unknown account, zero/negative
// request, currency mismatch, insufficient available balance, or exhausted
// quota. Available balance = actual balance − pending reservations.
//
// Zero-cost short-circuit: when the total charge (UnitCost × Quantity) is zero —
// a FREE term, or any PER_UNIT term with a rate/unit_cost of 0 — there is
// nothing to charge, so the currency-match and balance gates do NOT apply. Such
// a term is authorized regardless of which currency the agent holds (it need not
// hold the term's currency at all). The agent must still exist and the quota cap
// still applies: the bypass relaxes only the money gate, not eligibility or the
// unit-count quota. The reservation is recorded with the term's own currency at
// a zero amount, so a later Record settles nothing and the agent's real balance —
// in whatever currency it is denominated — is untouched.
//
// Reachability: the Exchange service short-circuits a price-zero term BEFORE
// calling Authorize — it floors quantity to ≥1 and bypasses the adapter entirely
// for unit_cost == 0 (ADR-009 D2), persisting a NULL billing_id with no quota or
// eligibility check. So this zero-charge branch is reached only by a direct
// caller passing a genuine zero charge (e.g. a non-zero unit_cost at quantity 0),
// for whom the agent-existence and quota gates below deliberately still apply.
func (a *InMemoryAdapter) Authorize(_ context.Context, req AuthorizeRequest) (AuthorizeResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if req.IdempotencyKey != "" {
		if bid, ok := a.authSeen[authMapKey(req.BillingRef, req.IdempotencyKey)]; ok {
			return AuthorizeResult{BillingID: bid, Approved: true}, nil
		}
	}

	bal, ok := a.balances[req.BillingRef]
	if !ok {
		return AuthorizeResult{Approved: false, Reason: "unknown account"}, nil
	}
	if req.Quantity <= 0 {
		return AuthorizeResult{Approved: false, Reason: "non-positive quantity"}, nil
	}

	charge := totalCharge(req.UnitCost, req.Quantity).Value

	// A zero charge bypasses the currency-match and balance gates: there is
	// nothing to charge, so neither the held currency nor the available balance
	// can be a reason to refuse. Non-zero charges fall through to the full gate.
	if charge.Sign() != 0 {
		if denial, ok := a.checkCurrencyAndBalance(req, bal, charge); !ok {
			return denial, nil
		}
	}

	if denial, ok := a.consumeQuota(req); !ok {
		return denial, nil
	}

	return a.reserve(req, charge), nil
}

// checkCurrencyAndBalance enforces the money gate for a non-zero charge: the
// agent's balance currency must match the term's currency, and the available
// balance (actual minus same-currency pending reservations) must cover the
// charge. Returns (denial, false) on refusal, (zero, true) on pass. Caller holds
// a.mu. Only reached for non-zero charges (the zero-cost path skips it).
func (a *InMemoryAdapter) checkCurrencyAndBalance(
	req AuthorizeRequest, bal Amount, charge *big.Rat,
) (AuthorizeResult, bool) {
	if bal.Currency != req.UnitCost.Currency {
		return AuthorizeResult{Approved: false, Reason: "currency mismatch"}, false
	}
	totalReserved := new(big.Rat)
	for _, r := range a.reserved {
		if r.BillingRef == req.BillingRef && r.EstAmt.Currency == bal.Currency {
			totalReserved.Add(totalReserved, r.EstAmt.Value)
		}
	}
	available := new(big.Rat).Sub(new(big.Rat).Set(bal.Value), totalReserved)
	if available.Cmp(charge) < 0 {
		return AuthorizeResult{Approved: false, Reason: "insufficient balance"}, false
	}
	return AuthorizeResult{}, true
}

// consumeQuota enforces and decrements the unit-count quota cap. It applies to
// every authorization, zero-cost or not — quota is independent of money. Returns
// (denial, false) when the request exceeds remaining quota, (zero, true)
// otherwise. Caller holds a.mu.
func (a *InMemoryAdapter) consumeQuota(req AuthorizeRequest) (AuthorizeResult, bool) {
	if q, hasQuota := a.quotas[req.BillingRef]; hasQuota {
		if q < req.Quantity {
			return AuthorizeResult{Approved: false, Reason: "quota exhausted"}, false
		}
		a.quotas[req.BillingRef] = q - req.Quantity
	}
	return AuthorizeResult{}, true
}

// reserve records the pending reservation and the live-hold dedup entry, then
// returns the approval. The reservation carries the term's own currency at the
// computed charge (zero for a zero-cost term). Caller holds a.mu.
func (a *InMemoryAdapter) reserve(req AuthorizeRequest, charge *big.Rat) AuthorizeResult {
	a.nextIdx++
	id := fmt.Sprintf("%s%06d", a.idPrefix, a.nextIdx)
	a.reserved[id] = reservation{
		BillingRef: req.BillingRef,
		EstAmt:     Amount{Value: charge, Currency: req.UnitCost.Currency},
		EstQty:     req.Quantity,
		AuthKey:    req.IdempotencyKey,
	}
	if req.IdempotencyKey != "" {
		a.authSeen[authMapKey(req.BillingRef, req.IdempotencyKey)] = id
	}
	return AuthorizeResult{BillingID: id, Approved: true}
}

// Record settles the transaction against the authorized reservation. Deducts
// the reserved amount (res.EstAmt) from the balance, retains it for a possible
// later Refund, and releases the hold + the live-hold dedup key. The quantity
// argument is advisory. A replay with the same idempotencyKey is a no-op
// success; otherwise an absent reservation (already recorded or released)
// returns ErrUnknownBillingID.
func (a *InMemoryAdapter) Record(_ context.Context, billingID string, _ int64, idempotencyKey string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.opAlreadyDone(billingID, opRecord, idempotencyKey) {
		return nil
	}

	res, ok := a.reserved[billingID]
	if !ok {
		return ErrUnknownBillingID
	}

	bal := a.balances[res.BillingRef]
	bal.Value.Sub(bal.Value, new(big.Rat).Set(res.EstAmt.Value))
	a.balances[res.BillingRef] = bal
	a.recorded[billingID] = recordedTx{
		BillingRef: res.BillingRef,
		Amt:        Amount{Value: new(big.Rat).Set(res.EstAmt.Value), Currency: res.EstAmt.Currency},
	}
	delete(a.reserved, billingID)
	a.freeAuth(res)
	a.markOpDone(billingID, opRecord, idempotencyKey)
	return nil
}

// Release returns a previously held reservation without recording any
// consumption. Restores any quota decremented at Authorize and frees the
// live-hold dedup key (so a retry under the same key re-authorizes fresh). A
// replay with the same idempotencyKey is a no-op success; an absent reservation
// returns ErrUnknownBillingID, which callers treat as a successful no-op.
func (a *InMemoryAdapter) Release(_ context.Context, billingID string, idempotencyKey string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.opAlreadyDone(billingID, opRelease, idempotencyKey) {
		return nil
	}

	res, ok := a.reserved[billingID]
	if !ok {
		return ErrUnknownBillingID
	}
	if _, hasQuota := a.quotas[res.BillingRef]; hasQuota {
		a.quotas[res.BillingRef] += res.EstQty
	}
	delete(a.reserved, billingID)
	a.freeAuth(res)
	a.markOpDone(billingID, opRelease, idempotencyKey)
	return nil
}

// Refund credits the agent's balance back for a previously recorded charge,
// capped at the recorded amount net of prior refunds, and persists the reason
// memo. Idempotent on (billingID, idempotencyKey).
func (a *InMemoryAdapter) Refund(
	_ context.Context, billingID string, amount Amount, reason string, idempotencyKey string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.opAlreadyDone(billingID, opRefund, idempotencyKey) {
		return nil
	}

	rec, err := a.validateRefund(billingID, amount)
	if err != nil {
		return err
	}

	bal := a.balances[rec.BillingRef]
	bal.Value.Add(bal.Value, new(big.Rat).Set(amount.Value))
	a.balances[rec.BillingRef] = bal
	prev := a.refunded[billingID]
	if prev == nil {
		prev = new(big.Rat)
		a.refunded[billingID] = prev
	}
	prev.Add(prev, new(big.Rat).Set(amount.Value))
	a.refundLog[billingID] = append(a.refundLog[billingID], RefundEntry{
		Amt:    Amount{Value: new(big.Rat).Set(amount.Value), Currency: amount.Currency},
		Reason: reason,
		Key:    idempotencyKey,
	})
	a.markOpDone(billingID, opRefund, idempotencyKey)
	return nil
}

// validateRefund classifies a refund attempt against the recorded ledger.
// Caller holds a.mu.
func (a *InMemoryAdapter) validateRefund(billingID string, amount Amount) (recordedTx, error) {
	rec, ok := a.recorded[billingID]
	if !ok {
		if _, held := a.reserved[billingID]; held {
			return recordedTx{}, ErrRefundBeforeRecord
		}
		return recordedTx{}, ErrUnknownBillingID
	}
	if amount.Value == nil || amount.Value.Sign() <= 0 || amount.Currency != rec.Amt.Currency {
		return recordedTx{}, ErrInvalidAmount
	}
	prev := a.refunded[billingID]
	if prev == nil {
		prev = new(big.Rat)
	}
	if new(big.Rat).Add(prev, amount.Value).Cmp(rec.Amt.Value) > 0 {
		return recordedTx{}, ErrRefundExceedsRecord
	}
	return rec, nil
}

// freeAuth removes the live-hold dedup entry for a resolved reservation.
// Caller holds a.mu.
func (a *InMemoryAdapter) freeAuth(res reservation) {
	if res.AuthKey != "" {
		delete(a.authSeen, authMapKey(res.BillingRef, res.AuthKey))
	}
}

// RefundLog returns a copy of the applied-refund memos for a billingID. This is
// an InMemory-only accessor (not part of the Adapter interface), used by tests
// and audit tooling to assert the persisted reason.
func (a *InMemoryAdapter) RefundLog(billingID string) []RefundEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	src := a.refundLog[billingID]
	out := make([]RefundEntry, len(src))
	copy(out, src)
	return out
}

// GetBalance returns the actual settled balance for an account. Pending
// reservations are not included (they represent authorised but not yet
// consumed funds).
func (a *InMemoryAdapter) GetBalance(_ context.Context, billingRef string) (Amount, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bal, ok := a.balances[billingRef]
	if !ok {
		return Amount{}, fmt.Errorf("billing: unknown account %q", billingRef)
	}
	return Amount{Value: new(big.Rat).Set(bal.Value), Currency: bal.Currency}, nil
}

// GetQuota returns the remaining quota for an account. Zero when the account
// has no quota cap configured.
func (a *InMemoryAdapter) GetQuota(_ context.Context, billingRef string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quotas[billingRef], nil
}
