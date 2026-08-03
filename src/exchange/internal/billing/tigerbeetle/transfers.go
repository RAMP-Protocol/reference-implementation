package tigerbeetle

import (
	"context"
	"fmt"
	"math/big"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// transferCode is the non-zero reason code stamped on every lifecycle transfer
// (TigerBeetle rejects code 0). It aliases CodeSettlement so the pending's code and
// an accompanying settlement leg are provably equal, not equal by coincidence.
const transferCode = CodeSettlement

// PendingOutcome classifies the result of creating a pending (Authorize) transfer.
type PendingOutcome int

const (
	// PendingCreated means a new hold was reserved.
	PendingCreated PendingOutcome = iota
	// PendingExists means the transfer id already existed (idempotent replay).
	PendingExists
	// PendingInsufficientFunds means the debit would break the account's
	// DebitsMustNotExceedCredits invariant.
	PendingInsufficientFunds
)

// ResolveOutcome classifies the result of posting or voiding a pending transfer.
type ResolveOutcome int

const (
	// ResolveApplied means the post or void succeeded.
	ResolveApplied ResolveOutcome = iota
	// ResolveExists means the post/void transfer id already existed (idempotent replay).
	ResolveExists
	// ResolveNotFound means the referenced pending id does not exist.
	ResolveNotFound
	// ResolveAlreadyResolved means the pending was already posted, voided, or expired.
	ResolveAlreadyResolved
)

// HoldState is the lifecycle position of a hold, derived by ClassifyHold from the
// presence of its pending / post / void transfers on the ledger.
type HoldState int

const (
	// HoldFree means no pending transfer exists for the probed id (a fresh slot).
	HoldFree HoldState = iota
	// HoldLive means the pending exists and has not been posted or voided.
	HoldLive
	// HoldResolved means the pending exists and was already posted or voided.
	HoldResolved
)

// PendingTransfer describes a two-phase reservation (Authorize).
type PendingTransfer struct {
	ID      ID       // deterministic transfer id (the idempotency guard)
	Debit   ID       // account debited (the agent)
	Credit  ID       // counter-account credited
	Amount  *big.Int // integer minor units; must be non-nil and non-negative
	Ledger  uint32
	Timeout uint32 // pending expiry in seconds; 0 = never expires
	// UserData128 carries application metadata frozen on the hold — the settling
	// adapter stamps the resolved fee rate here at Authorize and reads it back at
	// Record, so the fee is computed from one transaction's truth without a database
	// read. Zero when unused. A post-pending transfer inherits it from the pending.
	UserData128 ID
}

// ResolveParams references a pending transfer to post or void. The resolving
// transfer carries its own unique ID; the pending's accounts / ledger / code are
// inherited and left zero here (TigerBeetle allows zero-or-match on a resolve).
type ResolveParams struct {
	ID        ID // the post/void transfer's own id
	PendingID ID // the pending transfer being resolved
}

// CreatePending reserves funds via a pending transfer. A duplicate id maps to
// PendingExists (the ledger-native idempotency guard); an over-limit debit maps to
// PendingInsufficientFunds. ctx is honoured for pre-flight cancellation.
func (c *Client) CreatePending(ctx context.Context, p PendingTransfer) (PendingOutcome, error) {
	if p.Amount == nil || p.Amount.Sign() < 0 {
		return 0, fmt.Errorf("tigerbeetle: create pending: %w: bad amount", ErrCreateTransfer)
	}
	results, err := withDeadline(ctx, c.opTimeout, func() ([]tb.CreateTransferResult, error) {
		return c.inner.CreateTransfers([]tb.Transfer{{
			ID:              p.ID,
			DebitAccountID:  p.Debit,
			CreditAccountID: p.Credit,
			Amount:          tb.BigIntToUint128(p.Amount),
			UserData128:     p.UserData128,
			Timeout:         p.Timeout,
			Ledger:          p.Ledger,
			Code:            uint16(transferCode),
			Flags:           tb.TransferFlags{Pending: true}.ToUint16(),
		}})
	})
	if err != nil {
		return 0, fmt.Errorf("tigerbeetle: create pending: %w", err)
	}
	if len(results) == 0 {
		return PendingCreated, nil
	}
	return pendingOutcome(results[0].Status)
}

// PostPending settles a pending transfer in full (Record). The pending's amount is
// posted via AmountMax.
func (c *Client) PostPending(ctx context.Context, p ResolveParams) (ResolveOutcome, error) {
	return c.resolve(ctx, p, tb.TransferFlags{PostPendingTransfer: true}.ToUint16(), tb.AmountMax)
}

// VoidPending cancels a pending transfer (Release), restoring the reserved amount.
func (c *Client) VoidPending(ctx context.Context, p ResolveParams) (ResolveOutcome, error) {
	return c.resolve(ctx, p, tb.TransferFlags{VoidPendingTransfer: true}.ToUint16(), tb.ToUint128(0))
}

func (c *Client) resolve(
	ctx context.Context, p ResolveParams, flags uint16, amount tb.Uint128,
) (ResolveOutcome, error) {
	results, err := withDeadline(ctx, c.opTimeout, func() ([]tb.CreateTransferResult, error) {
		return c.inner.CreateTransfers([]tb.Transfer{{
			ID:        p.ID,
			PendingID: p.PendingID,
			Amount:    amount,
			Flags:     flags,
		}})
	})
	if err != nil {
		return 0, fmt.Errorf("tigerbeetle: resolve pending: %w", err)
	}
	if len(results) == 0 {
		return ResolveApplied, nil
	}
	return resolveOutcome(results[0].Status)
}

// ClassifyHold reports whether a hold is free, live, or resolved by looking up its
// pending / post / void transfer ids in one round-trip. It is the ledger-native
// basis for the adapter's Authorize generation probe: a permanent transfer id
// cannot be reused, so a fresh Authorize after settlement must advance to a new
// generation rather than reuse the resolved pending id.
func (c *Client) ClassifyHold(ctx context.Context, pendingID, postID, voidID ID) (HoldState, error) {
	found, err := c.lookupTransferSet(ctx, []ID{pendingID, postID, voidID})
	if err != nil {
		return 0, err
	}
	switch {
	case !found[EncodeID(pendingID)]:
		return HoldFree, nil
	case !found[EncodeID(postID)] && !found[EncodeID(voidID)]:
		return HoldLive, nil
	default:
		return HoldResolved, nil
	}
}

func (c *Client) lookupTransferSet(ctx context.Context, ids []ID) (map[string]bool, error) {
	transfers, err := withDeadline(ctx, c.opTimeout, func() ([]tb.Transfer, error) {
		return c.inner.LookupTransfers(ids)
	})
	if err != nil {
		return nil, fmt.Errorf("tigerbeetle: lookup transfers: %w", err)
	}
	set := make(map[string]bool, len(transfers))
	for i := range transfers {
		set[EncodeID(transfers[i].ID)] = true
	}
	return set, nil
}

func pendingOutcome(s tb.CreateTransferStatus) (PendingOutcome, error) {
	switch s {
	case tb.TransferCreated:
		return PendingCreated, nil
	case tb.TransferExists:
		return PendingExists, nil
	case tb.TransferExceedsCredits:
		return PendingInsufficientFunds, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrCreateTransfer, s)
	}
}

func resolveOutcome(s tb.CreateTransferStatus) (ResolveOutcome, error) {
	switch s {
	case tb.TransferCreated:
		return ResolveApplied, nil
	case tb.TransferExists:
		return ResolveExists, nil
	case tb.TransferPendingTransferNotFound:
		return ResolveNotFound, nil
	case tb.TransferPendingTransferAlreadyPosted,
		tb.TransferPendingTransferAlreadyVoided,
		tb.TransferPendingTransferExpired:
		return ResolveAlreadyResolved, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrCreateTransfer, s)
	}
}
