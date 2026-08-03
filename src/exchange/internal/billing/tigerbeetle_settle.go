package billing

import (
	"context"
	"fmt"
	"math/big"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// refundReq carries the inputs Refund resolves before the reversal: the settled hold,
// the deterministic leg ids for this (billing, key) pair, and the refund amount.
type refundReq struct {
	pendingID tigerbeetle.ID
	netID     tigerbeetle.ID
	feeID     tigerbeetle.ID
	rMinor    *big.Int
	reason    string
}

// refundLegs is the fully-resolved reversal: the accounts, the deterministic leg ids,
// and the net/fee amounts to credit back to the agent.
type refundLegs struct {
	pendingID tigerbeetle.ID
	netID     tigerbeetle.ID
	feeID     tigerbeetle.ID
	agent     tigerbeetle.ID
	owner     tigerbeetle.ID
	netRev    *big.Int
	feeRev    *big.Int
	reason    string
}

// settleSplit posts the two-posting settlement split at Record. It recovers the gross
// and frozen rate from the hold, computes the floor fee, and — when the fee is non-zero
// — posts the net to the owner and moves the fee to the platform account in one atomic
// linked batch. A zero fee (the default rate) collapses to a single full post, leaving
// the whole gross on the owner account.
func (a *TigerBeetleAdapter) settleSplit(ctx context.Context, pendingID, postID tigerbeetle.ID) error {
	info, ok, err := a.tb.LookupTransfer(ctx, pendingID)
	if err != nil {
		return fmt.Errorf("billing: settle lookup: %w", err)
	}
	if !ok {
		return ErrUnknownBillingID
	}
	gross := info.Amount
	fee := feeMinor(gross, rateBps(info.UserData128))
	if fee.Sign() == 0 {
		out, pErr := a.tb.PostPending(ctx, tigerbeetle.ResolveParams{ID: postID, PendingID: pendingID})
		if pErr != nil {
			return fmt.Errorf("billing: settle full: %w", pErr)
		}
		return resolveErr(out)
	}
	platformID, err := a.platformFeeAccount()
	if err != nil {
		return err
	}
	if eErr := a.ensureAccount(ctx, platformID, tigerbeetle.CodePlatform, "platform fee"); eErr != nil {
		return eErr
	}
	feeID, err := a.feeLegID(pendingID)
	if err != nil {
		return err
	}
	net := new(big.Int).Sub(gross, fee)
	return linkedErr(a.tb.CreateLinked(ctx, []tigerbeetle.Leg{
		{ID: postID, PendingID: pendingID, Amount: net},
		{ID: feeID, Debit: info.Debit, Credit: platformID, Amount: fee, Ledger: a.ledger, Code: tigerbeetle.CodeSettlement},
	}))
}

// classifyForRefund enforces that the hold was recorded (not held, released, or
// unknown) before a reversal is allowed.
func (a *TigerBeetleAdapter) classifyForRefund(ctx context.Context, pendingID tigerbeetle.ID) error {
	state, postID, err := a.classifyHold(ctx, pendingID, "refund")
	if err != nil {
		return err
	}
	switch state {
	case tigerbeetle.HoldFree:
		return ErrUnknownBillingID
	case tigerbeetle.HoldLive:
		return ErrRefundBeforeRecord
	case tigerbeetle.HoldResolved:
		_, recorded, lErr := a.tb.LookupTransfer(ctx, postID)
		if lErr != nil {
			return fmt.Errorf("billing: refund lookup post: %w", lErr)
		}
		if !recorded {
			return ErrRefundBeforeRecord // voided (released), never recorded
		}
	}
	return nil
}

// reverseRefund resolves the reversal split — recover the posted fee, enforce the
// cumulative cap against the original gross, then apply the proportional reversal.
func (a *TigerBeetleAdapter) reverseRefund(ctx context.Context, r refundReq) error {
	info, ok, err := a.tb.LookupTransfer(ctx, r.pendingID)
	if err != nil {
		return fmt.Errorf("billing: refund lookup pending: %w", err)
	}
	if !ok {
		return ErrUnknownBillingID
	}
	gross := info.Amount
	prior, err := a.tb.SumAccountRefunds(ctx, info.Debit, r.pendingID, tigerbeetle.CodeRefund)
	if err != nil {
		return fmt.Errorf("billing: refund sum: %w", err)
	}
	if new(big.Int).Add(prior, r.rMinor).Cmp(gross) > 0 {
		return ErrRefundExceedsRecord
	}
	feePosted := feeMinor(gross, rateBps(info.UserData128))
	feeRev := new(big.Int).Div(new(big.Int).Mul(feePosted, r.rMinor), gross)
	netRev := new(big.Int).Sub(r.rMinor, feeRev)
	return a.refundReverse(ctx, refundLegs{
		pendingID: r.pendingID, netID: r.netID, feeID: r.feeID,
		agent: info.Debit, owner: info.Credit, netRev: netRev, feeRev: feeRev,
		reason: r.reason,
	})
}

// refundReverse credits the agent back from the owner (net) and, when the reversed fee
// is non-zero, the platform (fee), in one atomic linked batch. Both legs carry the
// billing id in user_data so SumAccountRefunds can total them.
func (a *TigerBeetleAdapter) refundReverse(ctx context.Context, r refundLegs) error {
	legs := []tigerbeetle.Leg{{
		ID: r.netID, Debit: r.owner, Credit: r.agent, Amount: r.netRev,
		Ledger: a.ledger, Code: tigerbeetle.CodeRefund, UserData128: r.pendingID,
		UserData64: tigerbeetle.ReasonToken(r.reason),
	}}
	if r.feeRev.Sign() > 0 {
		platformID, err := a.platformFeeAccount()
		if err != nil {
			return err
		}
		legs = append(legs, tigerbeetle.Leg{
			ID: r.feeID, Debit: platformID, Credit: r.agent, Amount: r.feeRev,
			Ledger: a.ledger, Code: tigerbeetle.CodeRefund, UserData128: r.pendingID,
		})
	}
	return linkedErr(a.tb.CreateLinked(ctx, legs))
}

// refundMinor validates the refund amount (positive, matching currency) and converts it
// to minor units. Any failure maps to ErrInvalidAmount.
func (a *TigerBeetleAdapter) refundMinor(amount Amount) (*big.Int, error) {
	if amount.Currency != a.currency {
		return nil, ErrInvalidAmount
	}
	minor, err := a.toMinor(amount)
	if err != nil || minor.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}
	return minor, nil
}

// feeLegID derives the settlement fee leg's transfer id from the pending. The net leg
// reuses the pending's post id (so ClassifyHold still detects a settled hold); the fee
// leg needs its own id.
func (a *TigerBeetleAdapter) feeLegID(pendingID tigerbeetle.ID) (tigerbeetle.ID, error) {
	id, err := tigerbeetle.TransferID(a.idNS + "fee:" + tigerbeetle.EncodeID(pendingID))
	if err != nil {
		return id, fmt.Errorf("billing: derive fee leg id: %w", err)
	}
	return id, nil
}

// refundLegIDs derives the deterministic net/fee reversal ids for a (billing, key)
// pair, so a replay re-derives the same ids (check-then-act idempotency).
func (a *TigerBeetleAdapter) refundLegIDs(
	pendingID tigerbeetle.ID, key string,
) (netID, feeID tigerbeetle.ID, err error) {
	base := a.idNS + "refund:" + tigerbeetle.EncodeID(pendingID) + ":" + key
	if netID, err = tigerbeetle.TransferID(base + ":net"); err != nil {
		return netID, feeID, fmt.Errorf("billing: derive refund net id: %w", err)
	}
	if feeID, err = tigerbeetle.TransferID(base + ":fee"); err != nil {
		return netID, feeID, fmt.Errorf("billing: derive refund fee id: %w", err)
	}
	return netID, feeID, nil
}

// feeMinor is floor(gross × bps / 10000) in big.Int (avoiding int64 overflow at scale
// 8); the platform absorbs the sub-cent remainder, so net = gross − feeMinor.
func feeMinor(gross *big.Int, bps int) *big.Int {
	fee := new(big.Int).Mul(gross, big.NewInt(int64(bps)))
	return fee.Div(fee, big.NewInt(10000))
}

// rateBps recovers the basis-point rate stamped on a hold's user_data.
func rateBps(userData tigerbeetle.ID) int {
	return int(userData.BigInt().Int64())
}

// linkedErr maps a linked-batch outcome to the adapter's error contract.
func linkedErr(out tigerbeetle.LinkedOutcome, err error) error {
	if err != nil {
		return fmt.Errorf("billing: linked transfer: %w", err)
	}
	switch out {
	case tigerbeetle.LinkedApplied:
		return nil
	case tigerbeetle.LinkedExceedsCredits:
		return ErrInsufficientBalance
	case tigerbeetle.LinkedPendingResolved:
		return ErrUnknownBillingID
	default:
		return fmt.Errorf("billing: unexpected linked outcome %v", out)
	}
}
