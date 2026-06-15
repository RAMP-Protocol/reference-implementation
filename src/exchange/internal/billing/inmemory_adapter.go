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
	AgentID string
	EstAmt  Amount // estimated total charge; the amount Record settles
	EstQty  int64  // authorized quantity; restored to quota on Release
	// AuthKey is the IdempotencyKey supplied at Authorize ("" if none). Record
	// and Release use it to free the live-hold dedup entry on resolve. Stored
	// raw; the bounded form is derived at map-access time via authMapKey.
	AuthKey string
}

// recordedTx retains the settled charge for a billingID after Record so Refund
// can validate against it. (Record removes the reservation; without this the
// refund path could not tell "recorded" from "never issued".)
type recordedTx struct {
	AgentID string
	Amt     Amount
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
// pending reservations for the same agent and currency) covers the requested
// charge; on approval it stores the reservation without touching the actual
// balance. Release returns the reservation with no balance change. Record
// deducts the reservation amount and releases the hold. Refund credits the
// agent's balance back, capped at the recorded charge.
type InMemoryAdapter struct {
	mu        sync.Mutex
	balances  map[string]Amount        // agent_id → actual balance
	quotas    map[string]int64         // agent_id → remaining quota (unit-agnostic)
	reserved  map[string]reservation   // billing_id → pending reservation
	recorded  map[string]recordedTx    // billing_id → settled charge (for Refund)
	refunded  map[string]*big.Rat      // billing_id → cumulative refunded amount
	refundLog map[string][]RefundEntry // billing_id → ordered refund memos
	authSeen  map[string]string        // (agent_id, auth_key) → billing_id (live holds)
	// opSeen records processed (billing_id, op, key) tuples for Record/Release/
	// Refund idempotency. It is deliberately NOT bounded by an LRU: evicting a
	// refund entry would let a same-key refund replay re-run validateRefund and
	// credit a SECOND time while still under the cumulative cap — silently
	// breaking refund idempotency. Eviction would be safe for record/release
	// (a replay degrades to ErrUnknownBillingID, never a double-charge) but not
	// for refund, so no eviction happens at all. Count growth is one entry per
	// committed transaction (tx_request_id is UNIQUE); durable unbounded-volume
	// idempotency is the persisted adapter's (TigerBeetle) responsibility, not
	// the demo-tier in-memory adapter's. Per-entry size is bounded by boundKey.
	opSeen   map[string]struct{}
	nextIdx  uint64
	idPrefix string
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
		balances:  map[string]Amount{},
		quotas:    map[string]int64{},
		reserved:  map[string]reservation{},
		recorded:  map[string]recordedTx{},
		refunded:  map[string]*big.Rat{},
		refundLog: map[string][]RefundEntry{},
		authSeen:  map[string]string{},
		opSeen:    map[string]struct{}{},
		idPrefix:  opts.IDPrefix,
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

// authMapKey composes the authSeen map key for an agent + raw idempotency key.
// boundKey is applied here (not at the call sites) so the Authorize write and
// the freeAuth delete always agree on the stored form.
func authMapKey(agentID, rawKey string) string {
	return seenKey(agentID, boundKey(rawKey))
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

// Authorize holds funds for the transaction. A repeat call with the same
// non-empty IdempotencyKey while the hold is live returns the same BillingID
// (no second reservation). Otherwise denies on unknown agent, zero/negative
// request, currency mismatch, insufficient available balance, or exhausted
// quota. Available balance = actual balance − pending reservations.
func (a *InMemoryAdapter) Authorize(_ context.Context, req AuthorizeRequest) (AuthorizeResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if req.IdempotencyKey != "" {
		if bid, ok := a.authSeen[authMapKey(req.AgentID, req.IdempotencyKey)]; ok {
			return AuthorizeResult{BillingID: bid, Approved: true}, nil
		}
	}

	bal, ok := a.balances[req.AgentID]
	if !ok {
		return AuthorizeResult{Approved: false, Reason: "unknown agent"}, nil
	}
	if req.Quantity <= 0 {
		return AuthorizeResult{Approved: false, Reason: "non-positive quantity"}, nil
	}
	if bal.Currency != req.UnitCost.Currency {
		return AuthorizeResult{Approved: false, Reason: "currency mismatch"}, nil
	}

	charge := new(big.Rat).Mul(req.UnitCost.Value, big.NewRat(req.Quantity, 1))

	// Compute available balance: actual balance minus pending reservations for
	// this agent in the same currency.
	totalReserved := new(big.Rat)
	for _, r := range a.reserved {
		if r.AgentID == req.AgentID && r.EstAmt.Currency == bal.Currency {
			totalReserved.Add(totalReserved, r.EstAmt.Value)
		}
	}
	available := new(big.Rat).Sub(new(big.Rat).Set(bal.Value), totalReserved)
	if available.Cmp(charge) < 0 {
		return AuthorizeResult{Approved: false, Reason: "insufficient balance"}, nil
	}

	if q, hasQuota := a.quotas[req.AgentID]; hasQuota {
		if q < req.Quantity {
			return AuthorizeResult{Approved: false, Reason: "quota exhausted"}, nil
		}
		a.quotas[req.AgentID] = q - req.Quantity
	}

	a.nextIdx++
	id := fmt.Sprintf("%s%06d", a.idPrefix, a.nextIdx)
	a.reserved[id] = reservation{
		AgentID: req.AgentID,
		EstAmt:  Amount{Value: charge, Currency: req.UnitCost.Currency},
		EstQty:  req.Quantity,
		AuthKey: req.IdempotencyKey,
	}
	if req.IdempotencyKey != "" {
		a.authSeen[authMapKey(req.AgentID, req.IdempotencyKey)] = id
	}
	return AuthorizeResult{BillingID: id, Approved: true}, nil
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

	bal := a.balances[res.AgentID]
	bal.Value.Sub(bal.Value, new(big.Rat).Set(res.EstAmt.Value))
	a.balances[res.AgentID] = bal
	a.recorded[billingID] = recordedTx{
		AgentID: res.AgentID,
		Amt:     Amount{Value: new(big.Rat).Set(res.EstAmt.Value), Currency: res.EstAmt.Currency},
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
	if _, hasQuota := a.quotas[res.AgentID]; hasQuota {
		a.quotas[res.AgentID] += res.EstQty
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

	bal := a.balances[rec.AgentID]
	bal.Value.Add(bal.Value, new(big.Rat).Set(amount.Value))
	a.balances[rec.AgentID] = bal
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
		delete(a.authSeen, authMapKey(res.AgentID, res.AuthKey))
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

// GetBalance returns the actual settled balance for an agent. Pending
// reservations are not included (they represent authorised but not yet
// consumed funds).
func (a *InMemoryAdapter) GetBalance(_ context.Context, agentID string) (Amount, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	bal, ok := a.balances[agentID]
	if !ok {
		return Amount{}, fmt.Errorf("billing: unknown agent %q", agentID)
	}
	return Amount{Value: new(big.Rat).Set(bal.Value), Currency: bal.Currency}, nil
}

// GetQuota returns the remaining quota for an agent. Zero when the agent
// has no quota cap configured.
func (a *InMemoryAdapter) GetQuota(_ context.Context, agentID string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quotas[agentID], nil
}
