package tigerbeetle

import (
	"context"
	"fmt"
	"math/big"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// TransferCode is the reason stamped on a transfer's Code field. It is a distinct
// named type from AccountCode (ids.go) so the two code families cannot be passed
// where the other is expected. TigerBeetle requires a non-zero code and indexes it
// for queries; SumAccountRefunds filters on CodeRefund. CodeSettlement matches the
// pending's transferCode so a post-pending's inherited code and an accompanying
// plain settlement leg agree.
type TransferCode uint16

// The transfer "why" codes. TigerBeetle rejects code 0, so these start at 1.
const (
	CodeSettlement TransferCode = 1
	CodeRefund     TransferCode = 2
)

// refundPageLimit bounds one GetAccountTransfers page. Realistic refund counts per
// billing id are tiny; the loop pages regardless so a large history still sums.
const refundPageLimit uint32 = 254

// LinkedOutcome classifies the result of an atomic linked batch.
type LinkedOutcome int

const (
	// LinkedApplied means every leg was newly created (or already existed on an
	// idempotent replay); the whole batch committed.
	LinkedApplied LinkedOutcome = iota
	// LinkedExceedsCredits means a debit leg would break a debit account's
	// DebitsMustNotExceedCredits invariant, so the whole chain rolled back.
	LinkedExceedsCredits
	// LinkedPendingResolved means a post-pending leg referenced a pending that was
	// already posted, voided, or natively expired — the hold is gone, so the batch
	// did not apply. Callers map it to ErrUnknownBillingID (a late Record on an
	// expired/resolved hold), matching the single post-pending path's
	// ResolveAlreadyResolved.
	LinkedPendingResolved
	// LinkedExistsMismatch means a leg's id already exists with different contents
	// (amount, accounts, flags, ...), so the batch did not apply and the existing
	// transfer stands. Credit maps a single-leg mismatch to a no-op success (the
	// first credit under an id wins, whatever its amount); the settle and refund
	// paths treat it as an error, because their leg ids are derived from the same
	// inputs as their contents and a mismatch means those drifted.
	LinkedExistsMismatch
)

// Leg is one transfer in a CreateLinked batch. A non-zero PendingID makes the leg a
// post-pending resolve (a partial post when Amount is below the pending's amount,
// restoring the remainder), inheriting the pending's accounts/ledger/code; a zero
// PendingID makes it a plain single-phase transfer that debits Debit and credits
// Credit on Ledger with Code. All legs in a batch succeed or fail together.
type Leg struct {
	ID          ID           // the leg's own deterministic transfer id
	PendingID   ID           // non-zero → post-pending resolve; zero → plain transfer
	Debit       ID           // plain transfer only
	Credit      ID           // plain transfer only
	Amount      *big.Int     // integer minor units; non-nil, non-negative
	Ledger      uint32       // plain transfer only
	Code        TransferCode // plain transfer only; non-zero
	UserData128 ID           // optional group tag (e.g. the billing id, for refund legs)
	UserData64  uint64       // optional audit scalar (e.g. a refund reason token)
}

// CreateLinked submits legs as one atomic linked chain: every leg but the last
// carries flags.linked, so TigerBeetle commits or rolls back the whole batch (the
// AC2 zero-movement guarantee). A retry that re-issues an already-committed batch is
// NOT a safe no-op — a duplicate id inside a linked chain can break the chain — so
// callers must check whether the legs already exist first (check-then-act).
func (c *Client) CreateLinked(ctx context.Context, legs []Leg) (LinkedOutcome, error) {
	batch, err := buildLinkedBatch(legs)
	if err != nil {
		return 0, err
	}
	results, err := withDeadline(ctx, c.opTimeout, func() ([]tb.CreateTransferResult, error) {
		return c.inner.CreateTransfers(batch)
	})
	if err != nil {
		return 0, fmt.Errorf("tigerbeetle: create linked: %w", err)
	}
	return linkedOutcome(results)
}

func buildLinkedBatch(legs []Leg) ([]tb.Transfer, error) {
	if len(legs) == 0 {
		return nil, fmt.Errorf("tigerbeetle: create linked: %w: empty batch", ErrCreateTransfer)
	}
	batch := make([]tb.Transfer, len(legs))
	for i := range legs {
		leg := legs[i]
		if leg.Amount == nil || leg.Amount.Sign() < 0 {
			return nil, fmt.Errorf("tigerbeetle: create linked: %w: leg %d amount", ErrCreateTransfer, i)
		}
		linked := i < len(legs)-1
		if leg.PendingID != (ID{}) {
			batch[i] = tb.Transfer{
				ID:          leg.ID,
				PendingID:   leg.PendingID,
				Amount:      tb.BigIntToUint128(leg.Amount),
				UserData128: leg.UserData128,
				UserData64:  leg.UserData64,
				Flags:       tb.TransferFlags{PostPendingTransfer: true, Linked: linked}.ToUint16(),
			}
			continue
		}
		batch[i] = tb.Transfer{
			ID:              leg.ID,
			DebitAccountID:  leg.Debit,
			CreditAccountID: leg.Credit,
			Amount:          tb.BigIntToUint128(leg.Amount),
			UserData128:     leg.UserData128,
			UserData64:      leg.UserData64,
			Ledger:          leg.Ledger,
			Code:            uint16(leg.Code),
			Flags:           tb.TransferFlags{Linked: linked}.ToUint16(),
		}
	}
	return batch, nil
}

// linkedOutcome reduces the per-leg results to a single outcome. A rolled-back chain
// reports the first failing leg's real status plus linked_event_failed on the rest;
// scanning past the linked_event_failed markers finds the root cause.
func linkedOutcome(results []tb.CreateTransferResult) (LinkedOutcome, error) {
	for i := range results {
		switch results[i].Status {
		case tb.TransferCreated, tb.TransferExists, tb.TransferLinkedEventFailed:
			continue
		case tb.TransferExceedsCredits, tb.TransferExceedsDebits:
			return LinkedExceedsCredits, nil
		case tb.TransferPendingTransferAlreadyPosted,
			tb.TransferPendingTransferAlreadyVoided,
			tb.TransferPendingTransferExpired:
			return LinkedPendingResolved, nil
		case tb.TransferExistsWithDifferentFlags,
			tb.TransferExistsWithDifferentDebitAccountID,
			tb.TransferExistsWithDifferentCreditAccountID,
			tb.TransferExistsWithDifferentAmount,
			tb.TransferExistsWithDifferentPendingID,
			tb.TransferExistsWithDifferentUserData128,
			tb.TransferExistsWithDifferentUserData64,
			tb.TransferExistsWithDifferentUserData32,
			tb.TransferExistsWithDifferentTimeout,
			tb.TransferExistsWithDifferentCode,
			tb.TransferExistsWithDifferentLedger:
			return LinkedExistsMismatch, nil
		default:
			return 0, fmt.Errorf("tigerbeetle: create linked: %w: leg %d: %s",
				ErrCreateTransfer, i, results[i].Status)
		}
	}
	return LinkedApplied, nil
}

// TransferInfo is the subset of a transfer the settling adapter reads back: the
// reserved amount, the metadata carried in user_data (the frozen fee rate), and the
// accounts. Returned by LookupTransfer so callers need not import the raw client.
type TransferInfo struct {
	Amount      *big.Int
	UserData128 ID
	UserData64  uint64
	Debit       ID
	Credit      ID
}

// LookupTransfer returns the transfer with the given id, or ok=false if it does not
// exist. It reads the full record (unlike ClassifyHold's existence-only probe), so
// Record can recover a hold's gross (Amount) and frozen rate (UserData128).
func (c *Client) LookupTransfer(ctx context.Context, id ID) (TransferInfo, bool, error) {
	transfers, err := withDeadline(ctx, c.opTimeout, func() ([]tb.Transfer, error) {
		return c.inner.LookupTransfers([]ID{id})
	})
	if err != nil {
		return TransferInfo{}, false, fmt.Errorf("tigerbeetle: lookup transfer: %w", err)
	}
	if len(transfers) == 0 {
		return TransferInfo{}, false, nil
	}
	t := transfers[0]
	return TransferInfo{
		Amount:      t.Amount.BigInt(),
		UserData128: t.UserData128,
		UserData64:  t.UserData64,
		Debit:       t.DebitAccountID,
		Credit:      t.CreditAccountID,
	}, true, nil
}

// SumAccountRefunds sums the amounts of credit transfers to account that carry group
// in user_data_128 and the given code — the ledger-native "refunded-so-far" for a
// billing id. TigerBeetle indexes user_data and code and is the documented way to
// group related transfers for querying; this pages through the (chronologically
// ordered) results until exhausted.
func (c *Client) SumAccountRefunds(ctx context.Context, account, group ID, code TransferCode) (*big.Int, error) {
	sum := new(big.Int)
	var timestampMin uint64
	for {
		transfers, err := withDeadline(ctx, c.opTimeout, func() ([]tb.Transfer, error) {
			return c.inner.GetAccountTransfers(tb.AccountFilter{
				AccountID:    account,
				UserData128:  group,
				Code:         uint16(code),
				TimestampMin: timestampMin,
				Limit:        refundPageLimit,
				Flags:        tb.AccountFilterFlags{Credits: true}.ToUint32(),
			})
		})
		if err != nil {
			return nil, fmt.Errorf("tigerbeetle: sum refunds: %w", err)
		}
		for i := range transfers {
			sum.Add(sum, transfers[i].Amount.BigInt())
		}
		if len(transfers) < int(refundPageLimit) {
			return sum, nil
		}
		timestampMin = transfers[len(transfers)-1].Timestamp + 1
	}
}
