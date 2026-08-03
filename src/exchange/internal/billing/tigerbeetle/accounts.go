package tigerbeetle

import (
	"context"
	"fmt"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// EnsureAccount lazily creates the account, treating an identical pre-existing
// account as success (idempotent). A ledger-level conflict — the id already
// exists with different fields — returns ErrAccountConflict; any other non-ok
// create status returns ErrCreateAccount. code MUST be non-zero (TigerBeetle
// rejects code 0). ctx is honoured for pre-flight cancellation; the underlying
// tigerbeetle-go call is itself synchronous.
func (c *Client) EnsureAccount(
	ctx context.Context, id tb.Uint128, ledger uint32, code AccountCode, flags tb.AccountFlags,
) error {
	results, err := withDeadline(ctx, c.opTimeout, func() ([]tb.CreateAccountResult, error) {
		return c.inner.CreateAccounts([]tb.Account{{
			ID:     id,
			Ledger: ledger,
			Code:   uint16(code),
			Flags:  flags.ToUint16(),
		}})
	})
	if err != nil {
		return fmt.Errorf("tigerbeetle: create account: %w", err)
	}
	// CreateAccounts returns one result per input account (positional). A single
	// input yields at most one result; an empty slice means it was created.
	if len(results) == 0 {
		return nil
	}
	switch status := results[0].Status; {
	case status == tb.AccountCreated, status == tb.AccountExists:
		return nil
	case isExistsConflict(status):
		return fmt.Errorf("%w: %s", ErrAccountConflict, status)
	default:
		return fmt.Errorf("%w: %s", ErrCreateAccount, status)
	}
}

// LookupAccount returns the account for id and whether it exists. A missing
// account is (zero, false, nil) — not an error — so callers distinguish
// "not created yet" from a transport failure.
func (c *Client) LookupAccount(ctx context.Context, id tb.Uint128) (tb.Account, bool, error) {
	accounts, err := withDeadline(ctx, c.opTimeout, func() ([]tb.Account, error) {
		return c.inner.LookupAccounts([]tb.Uint128{id})
	})
	if err != nil {
		return tb.Account{}, false, fmt.Errorf("tigerbeetle: lookup account: %w", err)
	}
	if len(accounts) == 0 {
		return tb.Account{}, false, nil
	}
	return accounts[0], true, nil
}

// isExistsConflict reports whether the status is an "id exists with a different
// field" result, as opposed to the identical-account AccountExists (an idempotent
// success).
func isExistsConflict(status tb.CreateAccountStatus) bool {
	switch status {
	case tb.AccountExistsWithDifferentFlags,
		tb.AccountExistsWithDifferentUserData128,
		tb.AccountExistsWithDifferentUserData64,
		tb.AccountExistsWithDifferentUserData32,
		tb.AccountExistsWithDifferentLedger,
		tb.AccountExistsWithDifferentCode:
		return true
	default:
		return false
	}
}

// AgentAccountFlags are the flags for a prepaid agent account: debits must not
// exceed credits, so a hold or settlement is rejected once the funded balance is
// exhausted. History is left off — agent balance history is not needed in v1.
func AgentAccountFlags() tb.AccountFlags {
	return tb.AccountFlags{DebitsMustNotExceedCredits: true}
}
