//go:build integration

// Package tbtest holds the shared TigerBeetle integration-test fixtures — real
// ledger funding, settled/pending balance reads, deterministic id builders, and
// the dollars→minor conversion — consumed by BOTH the billing and transport test
// suites so the funding shape lives in one place (Testing Doctrine §7).
//
// It lives under src/exchange/internal/ rather than in internal/testutil because
// it references the CGO tigerbeetle.Client: Go's internal-package rule forbids
// importing that client from the repo-root testutil layer. The CGO-free container
// lifecycle (testutil.SharedTigerBeetle) correctly stays in testutil; these
// client-touching fixtures are its exchange-side complement.
package tbtest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
)

// Ledger is a test handle to one TigerBeetle ledger: the shared client and the
// ledger id. The asset scale is not carried here — it is money.AssetScale,
// deliberately fixed for every deployment. Construct one per suite from the
// package's shared client and reuse it for every funding and balance call.
type Ledger struct {
	Client *tigerbeetle.Client
	ID     uint32 // TigerBeetle ledger id (ISO 4217 numeric)
}

// creditLegs are the resolved endpoints, transfer-id keys, and amount of a single
// settled funding transfer.
type creditLegs struct {
	fundKey, postKey string
	debit, credit    tigerbeetle.ID
	minor            *big.Int
}

// FundAgent seeds a real prepaid balance: it ensures a salted platform:liquidity
// source and the salted agent account, then posts a settled credit of amount into
// the agent via a two-phase transfer. This mirrors the operator's out-of-band
// manual credit (ADR-009 D2) — the only way to create ledger balance, since the
// adapter has no Fund method. salt namespaces every derived id so sibling tests on
// the reset-less shared ledger never collide. A zero amount is a no-op.
//
// It returns an error rather than failing a *testing.T so the conformance adapter
// factory — a closure with no *testing.T in scope — can call it too; test bodies
// use MustFundAgent.
func (l Ledger) FundAgent(ctx context.Context, salt, agentID string, amount *big.Rat) error {
	m, err := money.MinorUnits(amount)
	if err != nil {
		return err
	}
	liq, agent, err := l.fundEndpoints(ctx, salt, agentID)
	if err != nil {
		return err
	}
	if m.Sign() == 0 {
		return nil
	}
	return l.postCredit(ctx, creditLegs{
		fundKey: salt + "fund:" + agentID, postKey: salt + "fundpost:" + agentID,
		debit: liq, credit: agent, minor: m,
	})
}

// fundEndpoints resolves the salted platform:liquidity source and agent
// destination every funding helper posts between — the account setup FundAgent
// and FundAgentWelcome share.
func (l Ledger) fundEndpoints(ctx context.Context, salt, agentID string) (liq, agent tigerbeetle.ID, err error) {
	liq, err = l.ensureAccount(ctx, tigerbeetle.PrefixPlatform, salt+tigerbeetle.PlatformLiquidityID, tigerbeetle.CodePlatform)
	if err != nil {
		return liq, agent, err
	}
	agent, err = l.ensureAccount(ctx, tigerbeetle.PrefixAgent, salt+agentID, tigerbeetle.CodeAgent)
	return liq, agent, err
}

// FundAgentWelcome posts the single-phase liquidity→agent credit the operator
// funding script issues under its reserved service-welcome label: one posted
// transfer whose id is TransferID(salt + billing.WelcomeCreditKey(agentID))
// — the SAME slot the Register flow's default-credit grant derives, so a
// script prefund and the service grant can never both apply. Test stand-in for
// fund-staging-agent.sh with the service-welcome label.
func (l Ledger) FundAgentWelcome(ctx context.Context, salt, agentID string, amount *big.Rat) error {
	minor, err := money.MinorUnits(amount)
	if err != nil {
		return fmt.Errorf("tbtest: welcome fund minor units: %w", err)
	}
	liq, agent, err := l.fundEndpoints(ctx, salt, agentID)
	if err != nil {
		return fmt.Errorf("tbtest: welcome fund: %w", err)
	}
	id, err := tigerbeetle.TransferID(salt + billing.WelcomeCreditKey(agentID))
	if err != nil {
		return fmt.Errorf("tbtest: welcome fund transfer id: %w", err)
	}
	out, err := l.Client.CreateLinked(ctx, []tigerbeetle.Leg{{
		ID:    id,
		Debit: liq, Credit: agent, Amount: minor,
		Ledger: l.ID, Code: tigerbeetle.CodeSettlement,
	}})
	if err != nil {
		return fmt.Errorf("tbtest: welcome fund transfer: %w", err)
	}
	if out != tigerbeetle.LinkedApplied {
		return fmt.Errorf("tbtest: welcome fund transfer: outcome=%v", out)
	}
	return nil
}

// MustFundAgentWelcome is the testing.TB convenience over FundAgentWelcome for
// test bodies, mirroring MustFundAgent's shape over FundAgent.
func (l Ledger) MustFundAgentWelcome(tb testing.TB, salt, agentID, dollars string) {
	tb.Helper()
	if err := l.FundAgentWelcome(context.Background(), salt, agentID, testutil.MustRat(tb, dollars)); err != nil {
		tb.Fatalf("tbtest: welcome fund: %v", err)
	}
}

// MustFundAgent funds the salted agent with dollars (a decimal string) and fails
// the test on any error. The testing.TB convenience over FundAgent for test bodies.
func (l Ledger) MustFundAgent(tb testing.TB, salt, agentID, dollars string) {
	tb.Helper()
	if err := l.FundAgent(context.Background(), salt, agentID, testutil.MustRat(tb, dollars)); err != nil {
		tb.Fatalf("tbtest: fund agent: %v", err)
	}
}

// ensureAccount lazily creates the salted account for (prefix, businessID) with
// the flag policy for its code (agent accounts are debit-capped; owner/platform
// accounts keep history), returning the derived id.
func (l Ledger) ensureAccount(
	ctx context.Context, p tigerbeetle.Prefix, businessID string, code tigerbeetle.AccountCode,
) (tigerbeetle.ID, error) {
	id, err := tigerbeetle.AccountID(p, businessID)
	if err != nil {
		return id, fmt.Errorf("tbtest: %s account id: %w", p, err)
	}
	if err := l.Client.EnsureAccount(ctx, id, l.ID, code, tigerbeetle.DefaultFlagsForCode(code)); err != nil {
		return id, fmt.Errorf("tbtest: ensure %s account: %w", p, err)
	}
	return id, nil
}

// postCredit reserves then posts a settled two-phase transfer moving c.minor from
// c.debit to c.credit.
func (l Ledger) postCredit(ctx context.Context, c creditLegs) error {
	fundID, err := tigerbeetle.TransferID(c.fundKey)
	if err != nil {
		return fmt.Errorf("tbtest: fund id: %w", err)
	}
	pout, err := l.Client.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: fundID, Debit: c.debit, Credit: c.credit, Amount: c.minor, Ledger: l.ID,
	})
	if err != nil {
		return fmt.Errorf("tbtest: fund pending: %w", err)
	}
	if pout != tigerbeetle.PendingCreated {
		return fmt.Errorf("tbtest: fund pending outcome = %v, want PendingCreated", pout)
	}
	postID, err := tigerbeetle.TransferID(c.postKey)
	if err != nil {
		return fmt.Errorf("tbtest: fundpost id: %w", err)
	}
	rout, err := l.Client.PostPending(ctx, tigerbeetle.ResolveParams{ID: postID, PendingID: fundID})
	if err != nil {
		return fmt.Errorf("tbtest: fund post: %w", err)
	}
	if rout != tigerbeetle.ResolveApplied {
		return fmt.Errorf("tbtest: fund post outcome = %v, want ResolveApplied", rout)
	}
	return nil
}

// PostedBalance reads an account's settled balance (credits_posted −
// debits_posted, minor units) straight from the ledger. There is no owner/platform
// read RPC (GetBalance is agent-only; the RevenueReport surface is deferred), so
// this LookupAccount read is an accepted black-box e2e exception (Testing Doctrine
// §9): a full-stack test observing the deployment's datastore. A missing account
// reads 0.
func (l Ledger) PostedBalance(tb testing.TB, id tigerbeetle.ID) int64 {
	tb.Helper()
	acc, ok, err := l.Client.LookupAccount(context.Background(), id)
	if err != nil {
		tb.Fatalf("tbtest: LookupAccount: %v", err)
	}
	if !ok {
		return 0
	}
	return new(big.Int).Sub(acc.CreditsPosted.BigInt(), acc.DebitsPosted.BigInt()).Int64()
}

// PendingBalance reads an account's uncommitted hold total (debits_pending, minor
// units) straight from the ledger — the same black-box e2e exception as
// PostedBalance. It proves a hold was voided: a released hold reads 0; a stranded
// one reads the reserved amount, which PostedBalance (settled only) cannot see. A
// missing account reads 0.
func (l Ledger) PendingBalance(tb testing.TB, id tigerbeetle.ID) int64 {
	tb.Helper()
	acc, ok, err := l.Client.LookupAccount(context.Background(), id)
	if err != nil {
		tb.Fatalf("tbtest: LookupAccount: %v", err)
	}
	if !ok {
		return 0
	}
	return acc.DebitsPending.BigInt().Int64()
}

// TransferUserData64 reads the user_data_64 scalar stamped on a transfer id straight
// from the ledger — the same black-box e2e exception as PostedBalance (Testing
// Doctrine §9). Returns 0 if the transfer does not exist.
func (l Ledger) TransferUserData64(tb testing.TB, id tigerbeetle.ID) uint64 {
	tb.Helper()
	info, ok, err := l.Client.LookupTransfer(context.Background(), id)
	if err != nil {
		tb.Fatalf("tbtest: LookupTransfer: %v", err)
	}
	if !ok {
		return 0
	}
	return info.UserData64
}

// Minor converts a decimal-dollar string to integer minor units at the ledger's
// asset scale, failing the test on a bad string or sub-unit remainder. Used to
// express expected ledger balances in assertions.
func (l Ledger) Minor(tb testing.TB, dollars string) int64 {
	tb.Helper()
	m, err := money.MinorUnits(testutil.MustRat(tb, dollars))
	if err != nil {
		tb.Fatalf("tbtest: %v", err)
	}
	return m.Int64()
}

// AssertOwnerPlatformSplit asserts the settled owner-revenue and platform-fee
// balances for a settlement under salt, in minor units. These two legs have no
// adapter read surface (GetBalance is agent-only; the RevenueReport surface is
// deferred), so this is the shared §9-exception ledger read reused by the billing
// and transport split suites. The account names derive from the same
// tigerbeetle.OwnerRevenuePrefix / PlatformFeeID production uses. The agent leg is
// asserted by each caller through the tier-1 adapter.GetBalance surface, so it is
// deliberately not read here.
func (l Ledger) AssertOwnerPlatformSplit(tb testing.TB, salt, ownerID string, ownerMinor, platformMinor int64) {
	tb.Helper()
	owner := MustAccountID(tb, tigerbeetle.PrefixOwner, salt+tigerbeetle.OwnerRevenuePrefix+ownerID)
	if got := l.PostedBalance(tb, owner); got != ownerMinor {
		tb.Errorf("owner revenue = %d, want %d", got, ownerMinor)
	}
	platform := MustAccountID(tb, tigerbeetle.PrefixPlatform, salt+tigerbeetle.PlatformFeeID)
	if got := l.PostedBalance(tb, platform); got != platformMinor {
		tb.Errorf("platform fee = %d, want %d", got, platformMinor)
	}
}

// MustAccountID derives the deterministic account id for (prefix, businessID) —
// the caller prepends its salt to businessID — failing the test on error.
func MustAccountID(tb testing.TB, p tigerbeetle.Prefix, businessID string) tigerbeetle.ID {
	tb.Helper()
	id, err := tigerbeetle.AccountID(p, businessID)
	if err != nil {
		tb.Fatalf("tbtest: AccountID(%s%s): %v", p, businessID, err)
	}
	return id
}

// MustTransferID derives the deterministic transfer id for key, failing the test
// on error.
func MustTransferID(tb testing.TB, key string) tigerbeetle.ID {
	tb.Helper()
	id, err := tigerbeetle.TransferID(key)
	if err != nil {
		tb.Fatalf("tbtest: TransferID(%s): %v", key, err)
	}
	return id
}

// BootClient dials a shared TigerBeetle cluster (cluster id 0 — the single-replica
// dev/CI cluster) and returns the client plus a close func for a TestMain to defer.
// It centralizes the NewClient boilerplate the client-building TestMains repeat.
func BootClient(address string) (*tigerbeetle.Client, func(), error) {
	c, err := tigerbeetle.NewClient(0, []string{address}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, nil, err
	}
	return c, c.Close, nil
}
