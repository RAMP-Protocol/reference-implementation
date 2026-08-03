//go:build integration

package tigerbeetle_test

import (
	"context"
	"math/big"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// u128 is the balance-field method set (tb.Uint128) reduced to what the assertions
// need, so these tests never name the TigerBeetle client type directly.
type u128 interface{ BigInt() *big.Int }

func amtEq(t *testing.T, got u128, want int64) {
	t.Helper()
	if got.BigInt().Cmp(big.NewInt(want)) != 0 {
		t.Fatalf("amount = %s, want %d", got.BigInt(), want)
	}
}

// twoAccounts creates a debit and a credit account with no balance constraint, so
// a plain post/void moves balances without any funding step.
func twoAccounts(t *testing.T, c *tigerbeetle.Client) (debit, credit tigerbeetle.ID) {
	t.Helper()
	ctx := context.Background()
	salt := sharedTB.Salt(t)
	var err error
	if debit, err = tigerbeetle.AccountID(tigerbeetle.PrefixOwner, salt+"-d"); err != nil {
		t.Fatalf("AccountID debit: %v", err)
	}
	if credit, err = tigerbeetle.AccountID(tigerbeetle.PrefixOwner, salt+"-c"); err != nil {
		t.Fatalf("AccountID credit: %v", err)
	}
	flags := tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeOwner)
	for _, id := range []tigerbeetle.ID{debit, credit} {
		if err := c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeOwner, flags); err != nil {
			t.Fatalf("EnsureAccount: %v", err)
		}
	}
	return debit, credit
}

func mustTransferID(t *testing.T, key string) tigerbeetle.ID {
	t.Helper()
	id, err := tigerbeetle.TransferID(key)
	if err != nil {
		t.Fatalf("TransferID(%q): %v", key, err)
	}
	return id
}

// TestCreatePending_PostSettles: a pending reserves into *_pending; posting moves it
// to *_posted (Testing Doctrine §1/§6, real process).
func TestCreatePending_PostSettles(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	debit, credit := twoAccounts(t, c)
	pid := mustTransferID(t, sharedTB.Salt(t)+"-p")

	out, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: pid, Debit: debit, Credit: credit, Amount: big.NewInt(100), Ledger: testLedger,
	})
	if err != nil || out != tigerbeetle.PendingCreated {
		t.Fatalf("CreatePending = (%v, %v), want PendingCreated", out, err)
	}
	dAcc, _, _ := c.LookupAccount(ctx, debit)
	amtEq(t, dAcc.DebitsPending, 100)
	amtEq(t, dAcc.DebitsPosted, 0)

	rout, err := c.PostPending(ctx, tigerbeetle.ResolveParams{ID: mustTransferID(t, sharedTB.Salt(t)+"-post"), PendingID: pid})
	if err != nil || rout != tigerbeetle.ResolveApplied {
		t.Fatalf("PostPending = (%v, %v), want ResolveApplied", rout, err)
	}
	dAcc, _, _ = c.LookupAccount(ctx, debit)
	cAcc, _, _ := c.LookupAccount(ctx, credit)
	amtEq(t, dAcc.DebitsPending, 0)
	amtEq(t, dAcc.DebitsPosted, 100)
	amtEq(t, cAcc.CreditsPosted, 100)
}

// TestVoidPending_Restores: voiding a pending clears the reservation and leaves
// posted balances untouched.
func TestVoidPending_Restores(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	debit, credit := twoAccounts(t, c)
	pid := mustTransferID(t, sharedTB.Salt(t)+"-p")
	if _, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: pid, Debit: debit, Credit: credit, Amount: big.NewInt(100), Ledger: testLedger,
	}); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	rout, err := c.VoidPending(ctx, tigerbeetle.ResolveParams{ID: mustTransferID(t, sharedTB.Salt(t)+"-void"), PendingID: pid})
	if err != nil || rout != tigerbeetle.ResolveApplied {
		t.Fatalf("VoidPending = (%v, %v), want ResolveApplied", rout, err)
	}
	dAcc, _, _ := c.LookupAccount(ctx, debit)
	amtEq(t, dAcc.DebitsPending, 0)
	amtEq(t, dAcc.DebitsPosted, 0)
}

// TestCreatePending_DuplicateID_Exists: re-creating the same transfer id is the
// ledger-native idempotency guard → PendingExists.
func TestCreatePending_DuplicateID_Exists(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	debit, credit := twoAccounts(t, c)
	pid := mustTransferID(t, sharedTB.Salt(t)+"-dup")
	p := tigerbeetle.PendingTransfer{ID: pid, Debit: debit, Credit: credit, Amount: big.NewInt(50), Ledger: testLedger}
	if _, err := c.CreatePending(ctx, p); err != nil {
		t.Fatalf("CreatePending 1: %v", err)
	}
	out, err := c.CreatePending(ctx, p)
	if err != nil || out != tigerbeetle.PendingExists {
		t.Fatalf("CreatePending 2 = (%v, %v), want PendingExists", out, err)
	}
}

// TestCreatePending_ExceedsCredits (negative, Testing Doctrine §10): a debit against
// an unfunded DebitsMustNotExceedCredits account maps to PendingInsufficientFunds.
func TestCreatePending_ExceedsCredits(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	salt := sharedTB.Salt(t)
	agent, err := tigerbeetle.AccountID(tigerbeetle.PrefixAgent, salt+"-agent")
	if err != nil {
		t.Fatalf("AccountID: %v", err)
	}
	_, credit := twoAccounts(t, c)
	if err := c.EnsureAccount(ctx, agent, testLedger, tigerbeetle.CodeAgent, tigerbeetle.AgentAccountFlags()); err != nil {
		t.Fatalf("EnsureAccount agent: %v", err)
	}
	out, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: mustTransferID(t, salt+"-x"), Debit: agent, Credit: credit, Amount: big.NewInt(1), Ledger: testLedger,
	})
	if err != nil || out != tigerbeetle.PendingInsufficientFunds {
		t.Fatalf("CreatePending (unfunded) = (%v, %v), want PendingInsufficientFunds", out, err)
	}
}

// TestResolve_UnknownPending_NotFound (negative): posting/voiding a pending id that
// was never created maps to ResolveNotFound.
func TestResolve_UnknownPending_NotFound(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	missing := mustTransferID(t, sharedTB.Salt(t)+"-missing")
	post, err := c.PostPending(ctx, tigerbeetle.ResolveParams{ID: mustTransferID(t, sharedTB.Salt(t)+"-p"), PendingID: missing})
	if err != nil || post != tigerbeetle.ResolveNotFound {
		t.Fatalf("PostPending(missing) = (%v, %v), want ResolveNotFound", post, err)
	}
	void, err := c.VoidPending(ctx, tigerbeetle.ResolveParams{ID: mustTransferID(t, sharedTB.Salt(t)+"-v"), PendingID: missing})
	if err != nil || void != tigerbeetle.ResolveNotFound {
		t.Fatalf("VoidPending(missing) = (%v, %v), want ResolveNotFound", void, err)
	}
}

// TestClassifyHold covers the three states the Authorize generation probe depends on.
func TestClassifyHold(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	debit, credit := twoAccounts(t, c)
	salt := sharedTB.Salt(t)
	pid := mustTransferID(t, salt+"-pending")
	postID := mustTransferID(t, salt+"-post")
	voidID := mustTransferID(t, salt+"-void")

	state, err := c.ClassifyHold(ctx, pid, postID, voidID)
	if err != nil || state != tigerbeetle.HoldFree {
		t.Fatalf("ClassifyHold (before create) = (%v, %v), want HoldFree", state, err)
	}
	if _, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: pid, Debit: debit, Credit: credit, Amount: big.NewInt(10), Ledger: testLedger,
	}); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	state, err = c.ClassifyHold(ctx, pid, postID, voidID)
	if err != nil || state != tigerbeetle.HoldLive {
		t.Fatalf("ClassifyHold (live) = (%v, %v), want HoldLive", state, err)
	}
	if _, err := c.PostPending(ctx, tigerbeetle.ResolveParams{ID: postID, PendingID: pid}); err != nil {
		t.Fatalf("PostPending: %v", err)
	}
	state, err = c.ClassifyHold(ctx, pid, postID, voidID)
	if err != nil || state != tigerbeetle.HoldResolved {
		t.Fatalf("ClassifyHold (resolved) = (%v, %v), want HoldResolved", state, err)
	}
}
