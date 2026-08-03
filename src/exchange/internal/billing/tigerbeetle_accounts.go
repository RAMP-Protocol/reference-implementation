package billing

import (
	"context"
	"fmt"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// Account lifecycle for TigerBeetleAdapter: business-id → ledger-account-id
// derivation and lazy account creation. The transfer lifecycle (Authorize /
// Record / Release / Refund) lives in tigerbeetle_adapter.go and
// tigerbeetle_settle.go.

// EnsureAgentAccount creates the agent's ledger account for a freshly
// registered billing_ref. The account id is derived exactly the way the
// Authorize path derives agent accounts — AccountID(PrefixAgent, ns+ref) — so
// pay/balance calls keyed by the same ref land on this account (ADR-021 D5:
// the ledger hashes the billing_ref text into its account number and stores no
// text). Idempotency is ledger-native: an identical pre-existing account is
// success, and a failed create leaves nothing behind (the single CreateAccounts
// call either lands the account or does not).
func (a *TigerBeetleAdapter) EnsureAgentAccount(ctx context.Context, billingRef string) (err error) {
	defer func() { err = classifyUnavailable(err) }()
	if billingRef == "" {
		return errEmptyBillingRef
	}
	id, err := a.accountID(tigerbeetle.PrefixAgent, billingRef)
	if err != nil {
		return err
	}
	return a.ensureAccount(ctx, id, tigerbeetle.CodeAgent, "agent")
}

// ownerAccount is the resource-owner revenue account the settlement credits. An empty
// resource_owner_id is refused with ErrUnknownPayee rather than settled into a shared
// owner:revenue: bucket: ADR-010 amendment A requires every catalog entry to attest its
// owner and forbids a tenant-id fallback. Attestation is enforced upstream at catalog
// push (migration 000018); a row predating that migration must be backfilled before
// settlement, and until then this guard turns a silent mis-settlement into a loud
// refusal.
func (a *TigerBeetleAdapter) ownerAccount(resourceOwnerID string) (tigerbeetle.ID, error) {
	if resourceOwnerID == "" {
		return tigerbeetle.ID{}, ErrUnknownPayee
	}
	return a.accountID(tigerbeetle.PrefixOwner, tigerbeetle.OwnerRevenuePrefix+resourceOwnerID)
}

func (a *TigerBeetleAdapter) ensureAccounts(ctx context.Context, agentAcct, ownerID tigerbeetle.ID) error {
	if err := a.ensureAccount(ctx, agentAcct, tigerbeetle.CodeAgent, "agent"); err != nil {
		return err
	}
	return a.ensureAccount(ctx, ownerID, tigerbeetle.CodeOwner, "owner")
}

// ensureAccount lazily creates id with the flag policy for its code (agent accounts
// are debit-capped; owner/platform accounts keep history), wrapping any failure with
// the account label. Shared by the agent/owner reservation path and the platform-fee
// settlement path.
func (a *TigerBeetleAdapter) ensureAccount(
	ctx context.Context, id tigerbeetle.ID, code tigerbeetle.AccountCode, label string,
) error {
	if err := a.tb.EnsureAccount(ctx, id, a.ledger, code, tigerbeetle.DefaultFlagsForCode(code)); err != nil {
		return fmt.Errorf("billing: ensure %s account: %w", label, err)
	}
	return nil
}

// platformFeeAccount derives the single platform commission account id the fee leg
// credits: AccountID(PrefixPlatform, platformFeeID). Used by both the settlement
// split and the refund reversal.
func (a *TigerBeetleAdapter) platformFeeAccount() (tigerbeetle.ID, error) {
	return a.accountID(tigerbeetle.PrefixPlatform, tigerbeetle.PlatformFeeID)
}

func (a *TigerBeetleAdapter) accountID(p tigerbeetle.Prefix, businessID string) (tigerbeetle.ID, error) {
	id, err := tigerbeetle.AccountID(p, a.idNS+businessID)
	if err != nil {
		return id, fmt.Errorf("billing: derive account id: %w", err)
	}
	return id, nil
}
