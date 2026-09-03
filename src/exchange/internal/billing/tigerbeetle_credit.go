package billing

import (
	"context"
	"errors"
	"fmt"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// errCreditLiquidityCap is the exceeds-credits sentinel Credit hands linkedErr.
// Unreachable by construction: the liquidity account has no debit cap and the
// agent account has no credit cap, so the transfer cannot bounce. Kept distinct
// from ErrInsufficientBalance because the debited party here is platform
// liquidity, not the agent — if this ever surfaces, it must not read as an
// agent-balance denial.
var errCreditLiquidityCap = errors.New("billing: credit exceeds platform liquidity cap")

// Credit grants a one-time credit to the agent's account as a single posted
// transfer from the platform liquidity account. The transfer id is derived
// from the caller's idempotency key alone — TransferID(idNS + key) — which is
// the same derivation the operator funding scripts use for their reserved
// service-welcome label (WelcomeCreditKey), so a service grant and an operator
// prefund that share the key occupy one ledger slot and can never both apply. Idempotency is check-then-act:
// an existing transfer under the id (whatever its amount — the first credit
// wins) is a no-op success, and the create maps a duplicate-id race to
// success the same way.
//
// The liquidity account is created on first use with the platform flag policy
// (History, no DebitsMustNotExceedCredits), so it may go arbitrarily negative:
// it represents money the operator owes the ledger, not a prepaid balance. The
// transfer carries CodeSettlement, matching the code the funding scripts stamp
// on their transfers.
func (a *TigerBeetleAdapter) Credit(
	ctx context.Context, billingRef string, amount Amount, idempotencyKey string,
) (err error) {
	defer func() { err = classifyUnavailable(err) }()
	if err := validateCreditArgs(billingRef, amount, idempotencyKey, a.currency); err != nil {
		return err
	}
	minor, err := a.toMinor(amount)
	if err != nil {
		return err
	}
	transferID, err := tigerbeetle.TransferID(a.idNS + idempotencyKey)
	if err != nil {
		return fmt.Errorf("billing: derive credit id: %w", err)
	}
	agentAcct, err := a.accountID(tigerbeetle.PrefixAgent, billingRef)
	if err != nil {
		return err
	}
	liquidity, err := a.accountID(tigerbeetle.PrefixPlatform, tigerbeetle.PlatformLiquidityID)
	if err != nil {
		return err
	}
	if err := a.ensureAccount(ctx, agentAcct, tigerbeetle.CodeAgent, "agent"); err != nil {
		return err
	}
	if err := a.ensureAccount(ctx, liquidity, tigerbeetle.CodePlatform, "platform liquidity"); err != nil {
		return err
	}
	_, exists, err := a.tb.LookupTransfer(ctx, transferID)
	if err != nil {
		return fmt.Errorf("billing: credit lookup: %w", err)
	}
	if exists {
		return nil // already credited (by a replay or an operator prefund) — no-op
	}
	out, err := a.tb.CreateLinked(ctx, []tigerbeetle.Leg{{
		ID:     transferID,
		Debit:  liquidity,
		Credit: agentAcct,
		Amount: minor,
		Ledger: a.ledger,
		Code:   tigerbeetle.CodeSettlement,
	}})
	if err == nil && out == tigerbeetle.LinkedExistsMismatch {
		// A prefund raced the grant under the shared id with a different
		// amount: the transfer that won the race stands and this single-leg
		// batch was a no-op — first credit wins, whatever its amount.
		return nil
	}
	return linkedErr(out, err, errCreditLiquidityCap)
}
