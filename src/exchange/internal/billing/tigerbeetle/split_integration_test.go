//go:build integration

package tigerbeetle_test

import (
	"context"
	"math/big"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// ownerAccount ensures one unconstrained (owner-code) account under the test salt, so
// plain transfers move balances without a funding step.
func ownerAccount(t *testing.T, c *tigerbeetle.Client, tag string) tigerbeetle.ID {
	t.Helper()
	id, err := tigerbeetle.AccountID(tigerbeetle.PrefixOwner, sharedTB.Salt(t)+tag)
	if err != nil {
		t.Fatalf("AccountID%s: %v", tag, err)
	}
	if err := c.EnsureAccount(context.Background(), id, testLedger, tigerbeetle.CodeOwner,
		tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeOwner)); err != nil {
		t.Fatalf("EnsureAccount%s: %v", tag, err)
	}
	return id
}

// oneCredit posts a single plain credit transfer src→dst tagged with group/code.
func oneCredit(t *testing.T, c *tigerbeetle.Client, key string, src, dst, group tigerbeetle.ID, amt int64, code tigerbeetle.TransferCode) {
	t.Helper()
	out, err := c.CreateLinked(context.Background(), []tigerbeetle.Leg{{
		ID: mustTransferID(t, key), Debit: src, Credit: dst, Amount: big.NewInt(amt),
		Ledger: testLedger, Code: code, UserData128: group,
	}})
	if err != nil || out != tigerbeetle.LinkedApplied {
		t.Fatalf("oneCredit %s = (%v, %v), want LinkedApplied", key, out, err)
	}
}

// TestCreateLinked_TwoPlainLegs_Commit: a linked pair of plain transfers both commit
// (Testing Doctrine §1/§6, real process).
func TestCreateLinked_TwoPlainLegs_Commit(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	src, a, b := ownerAccount(t, c, "-src"), ownerAccount(t, c, "-a"), ownerAccount(t, c, "-b")
	salt := sharedTB.Salt(t)

	out, err := c.CreateLinked(ctx, []tigerbeetle.Leg{
		{ID: mustTransferID(t, salt+"-l1"), Debit: src, Credit: a, Amount: big.NewInt(70), Ledger: testLedger, Code: tigerbeetle.CodeSettlement},
		{ID: mustTransferID(t, salt+"-l2"), Debit: src, Credit: b, Amount: big.NewInt(30), Ledger: testLedger, Code: tigerbeetle.CodeSettlement},
	})
	if err != nil || out != tigerbeetle.LinkedApplied {
		t.Fatalf("CreateLinked = (%v, %v), want LinkedApplied", out, err)
	}
	aAcc, _, _ := c.LookupAccount(ctx, a)
	bAcc, _, _ := c.LookupAccount(ctx, b)
	amtEq(t, aAcc.CreditsPosted, 70)
	amtEq(t, bAcc.CreditsPosted, 30)
}

// TestCreateLinked_AtomicRollback (negative, Testing Doctrine §10): when the second
// leg fails (an unfunded DebitsMustNotExceedCredits debit), the whole chain rolls
// back and the first leg leaves ZERO movement — the AC2 atomicity guarantee.
func TestCreateLinked_AtomicRollback(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	src, b := ownerAccount(t, c, "-src"), ownerAccount(t, c, "-b")
	salt := sharedTB.Salt(t)
	agent, err := tigerbeetle.AccountID(tigerbeetle.PrefixAgent, salt+"-agent")
	if err != nil {
		t.Fatalf("AccountID agent: %v", err)
	}
	if err := c.EnsureAccount(ctx, agent, testLedger, tigerbeetle.CodeAgent, tigerbeetle.AgentAccountFlags()); err != nil {
		t.Fatalf("EnsureAccount agent: %v", err)
	}

	out, err := c.CreateLinked(ctx, []tigerbeetle.Leg{
		{ID: mustTransferID(t, salt+"-ok"), Debit: src, Credit: b, Amount: big.NewInt(50), Ledger: testLedger, Code: tigerbeetle.CodeSettlement},
		{ID: mustTransferID(t, salt+"-bad"), Debit: agent, Credit: b, Amount: big.NewInt(1), Ledger: testLedger, Code: tigerbeetle.CodeSettlement},
	})
	if err != nil || out != tigerbeetle.LinkedExceedsCredits {
		t.Fatalf("CreateLinked = (%v, %v), want LinkedExceedsCredits", out, err)
	}
	bAcc, _, _ := c.LookupAccount(ctx, b)
	amtEq(t, bAcc.CreditsPosted, 0) // leg 1 rolled back with the failed chain
}

// TestCreateLinked_PostPlusPlain: the settlement-split shape — a partial post-pending
// (posts net, restores the remainder) linked with a plain fee transfer.
func TestCreateLinked_PostPlusPlain(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	src, owner, platform := ownerAccount(t, c, "-src"), ownerAccount(t, c, "-owner"), ownerAccount(t, c, "-plat")
	salt := sharedTB.Salt(t)
	pid := mustTransferID(t, salt+"-p")
	if _, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: pid, Debit: src, Credit: owner, Amount: big.NewInt(100), Ledger: testLedger,
	}); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}

	out, err := c.CreateLinked(ctx, []tigerbeetle.Leg{
		{ID: mustTransferID(t, salt+"-post"), PendingID: pid, Amount: big.NewInt(70)},
		{ID: mustTransferID(t, salt+"-fee"), Debit: src, Credit: platform, Amount: big.NewInt(30), Ledger: testLedger, Code: tigerbeetle.CodeSettlement},
	})
	if err != nil || out != tigerbeetle.LinkedApplied {
		t.Fatalf("CreateLinked = (%v, %v), want LinkedApplied", out, err)
	}
	srcAcc, _, _ := c.LookupAccount(ctx, src)
	ownerAcc, _, _ := c.LookupAccount(ctx, owner)
	platAcc, _, _ := c.LookupAccount(ctx, platform)
	amtEq(t, srcAcc.DebitsPending, 0)
	amtEq(t, srcAcc.DebitsPosted, 100) // 70 posted + 30 plain
	amtEq(t, ownerAcc.CreditsPosted, 70)
	amtEq(t, platAcc.CreditsPosted, 30)
}

// TestLookupTransfer: the full read recovers a hold's amount and the rate carried in
// user_data (what Record needs to compute the fee); an absent id returns ok=false.
func TestLookupTransfer(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	src, dst := ownerAccount(t, c, "-src"), ownerAccount(t, c, "-dst")
	pid := mustTransferID(t, sharedTB.Salt(t)+"-p")
	if _, err := c.CreatePending(ctx, tigerbeetle.PendingTransfer{
		ID: pid, Debit: src, Credit: dst, Amount: big.NewInt(100), Ledger: testLedger,
		UserData128: tigerbeetle.IDFromUint64(250),
	}); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}

	info, ok, err := c.LookupTransfer(ctx, pid)
	if err != nil || !ok {
		t.Fatalf("LookupTransfer = (ok=%v, %v), want ok", ok, err)
	}
	if info.Amount.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("amount = %s, want 100", info.Amount)
	}
	amtEq(t, info.UserData128, 250)
	if info.Credit != dst {
		t.Errorf("credit account mismatch")
	}
	if _, ok, _ := c.LookupTransfer(ctx, mustTransferID(t, sharedTB.Salt(t)+"-missing")); ok {
		t.Errorf("LookupTransfer(missing) ok=true, want false")
	}
}

// TestSumAccountRefunds: the ledger-native refunded-so-far — sums only credit
// transfers to the account carrying the billing group in user_data AND CodeRefund;
// a different group and a different code are both excluded.
func TestSumAccountRefunds(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	src, agent := ownerAccount(t, c, "-src"), ownerAccount(t, c, "-agent")
	salt := sharedTB.Salt(t)
	group := mustTransferID(t, salt+"-billing")
	other := mustTransferID(t, salt+"-otherbilling")

	oneCredit(t, c, salt+"-r1", src, agent, group, 30, tigerbeetle.CodeRefund)
	oneCredit(t, c, salt+"-r2", src, agent, group, 30, tigerbeetle.CodeRefund)
	oneCredit(t, c, salt+"-r3", src, agent, group, 30, tigerbeetle.CodeRefund)
	oneCredit(t, c, salt+"-x", src, agent, other, 99, tigerbeetle.CodeRefund)     // other group → excluded
	oneCredit(t, c, salt+"-s", src, agent, group, 77, tigerbeetle.CodeSettlement) // other code → excluded

	sum, err := c.SumAccountRefunds(ctx, agent, group, tigerbeetle.CodeRefund)
	if err != nil {
		t.Fatalf("SumAccountRefunds: %v", err)
	}
	if sum.Cmp(big.NewInt(90)) != 0 {
		t.Errorf("sum = %s, want 90 (3×30; other group/code excluded)", sum)
	}
}
