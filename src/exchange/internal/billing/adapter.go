// Package billing abstracts the money movement for Exchange transactions.
// The Adapter is called by the Marketplace service: Authorize reserves funds
// before the transaction log is written, Record finalizes the charge after
// the signed URL is handed out, and GetBalance/GetQuota expose state that
// drives quota-based denial decisions.
package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// Amount is the currency-normalized value transferred in a single operation.
// Stored as big.Rat to avoid float rounding when aggregating balances.
type Amount struct {
	Value    *big.Rat
	Currency string
}

// NewAmount parses a decimal string (e.g. "0.05") into an Amount.
func NewAmount(raw, currency string) (Amount, error) {
	r := new(big.Rat)
	if _, ok := r.SetString(raw); !ok {
		return Amount{}, fmt.Errorf("billing: cannot parse amount %q", raw)
	}
	return Amount{Value: r, Currency: currency}, nil
}

// AuthorizeRequest captures what the Marketplace needs billing to evaluate.
type AuthorizeRequest struct {
	TenantID string
	AgentID  string
	UnitCost Amount
	Quantity int64  // unit count from the Offer (e.g. estimated_quantity)
	Unit     string // e.g. "tokens", "pages"
}

// AuthorizeResult carries the post-authorize state back to the service.
type AuthorizeResult struct {
	BillingID string
	Approved  bool
	Reason    string // populated when Approved is false
}

// Adapter is the narrow interface exchange.MarketplaceService depends on.
type Adapter interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResult, error)
	Record(ctx context.Context, billingID string, consumedQuantity int64) error
	GetBalance(ctx context.Context, agentID string) (Amount, error)
	GetQuota(ctx context.Context, agentID string) (int64, error)
}

// ErrUnknownBillingID is returned by Record when billingID was not issued
// by this adapter (or was already released).
var ErrUnknownBillingID = errors.New("billing: unknown billing id")

// InMemoryAdapter is a thread-safe prepaid-balance implementation suitable
// for scrappy-demo and testing. Balances are per-agent; authorization
// deducts balance immediately and holds the reservation until Record.
type InMemoryAdapter struct {
	mu       sync.Mutex
	balances map[string]Amount // agent_id -> remaining balance
	quotas   map[string]int64  // agent_id -> remaining quota (unit-agnostic)
	reserved map[string]reserved
	nextIdx  uint64
	idPrefix string
}

type reserved struct {
	AgentID string
	Amount  Amount
	Qty     int64
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
		balances: map[string]Amount{},
		quotas:   map[string]int64{},
		reserved: map[string]reserved{},
		idPrefix: opts.IDPrefix,
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

// Authorize holds funds for the transaction. Denies on unknown agent,
// zero/negative request, currency mismatch, insufficient balance, or
// exhausted quota.
func (a *InMemoryAdapter) Authorize(_ context.Context, req AuthorizeRequest) (AuthorizeResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

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
	if bal.Value.Cmp(charge) < 0 {
		return AuthorizeResult{Approved: false, Reason: "insufficient balance"}, nil
	}
	if q, hasQuota := a.quotas[req.AgentID]; hasQuota {
		if q < req.Quantity {
			return AuthorizeResult{Approved: false, Reason: "quota exhausted"}, nil
		}
		a.quotas[req.AgentID] = q - req.Quantity
	}
	bal.Value.Sub(bal.Value, charge)
	a.balances[req.AgentID] = bal

	a.nextIdx++
	id := fmt.Sprintf("%s%06d", a.idPrefix, a.nextIdx)
	a.reserved[id] = reserved{
		AgentID: req.AgentID,
		Amount:  Amount{Value: charge, Currency: req.UnitCost.Currency},
		Qty:     req.Quantity,
	}
	return AuthorizeResult{BillingID: id, Approved: true}, nil
}

// Record finalizes the reservation. In this stub all funds are already
// deducted at Authorize; Record just drops the hold so GetBalance reflects
// final state and records the consumed quantity (reserved for future
// reconciliation with UsageReport).
func (a *InMemoryAdapter) Record(_ context.Context, billingID string, _ int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.reserved[billingID]; !ok {
		return ErrUnknownBillingID
	}
	delete(a.reserved, billingID)
	return nil
}

// GetBalance returns the current available balance for an agent.
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
// has no quota cap configured (the adapter treats "no entry" as unlimited
// and reports 0; callers that need to distinguish should not call GetQuota
// unless they first checked via the configuration layer).
func (a *InMemoryAdapter) GetQuota(_ context.Context, agentID string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quotas[agentID], nil
}
