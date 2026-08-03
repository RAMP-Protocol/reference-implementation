//go:build integration

package tigerbeetle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// testLedger is the ISO 4217 numeric code for EUR; Phase 1 is single-currency.
const testLedger uint32 = 978

func newTestClient(t *testing.T) *tigerbeetle.Client {
	t.Helper()
	c, err := tigerbeetle.NewClient(0, []string{sharedTB.Address}, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestConnection_SmokeCreateAndLookup drives create + lookup through the
// connection layer against the real process (Testing Doctrine §1/§6): no mock.
func TestConnection_SmokeCreateAndLookup(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	id, err := tigerbeetle.AccountID(tigerbeetle.PrefixOwner, sharedTB.Salt(t)+"-owner")
	if err != nil {
		t.Fatalf("AccountID: %v", err)
	}
	flags := tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeOwner)
	if err := c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeOwner, flags); err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	acc, found, err := c.LookupAccount(ctx, id)
	if err != nil {
		t.Fatalf("LookupAccount: %v", err)
	}
	if !found {
		t.Fatal("account not found after EnsureAccount")
	}
	if acc.Ledger != testLedger {
		t.Fatalf("ledger = %d, want %d", acc.Ledger, testLedger)
	}
	if tigerbeetle.AccountCode(acc.Code) != tigerbeetle.CodeOwner {
		t.Fatalf("code = %d, want %d", acc.Code, tigerbeetle.CodeOwner)
	}
}

// TestEnsureAccount_Idempotent — a second EnsureAccount for the same id is a
// no-op success (identical account -> AccountExists).
func TestEnsureAccount_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	id, err := tigerbeetle.AccountID(tigerbeetle.PrefixAgent, sharedTB.Salt(t)+"-agent")
	if err != nil {
		t.Fatalf("AccountID: %v", err)
	}
	flags := tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeAgent)
	if err := c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeAgent, flags); err != nil {
		t.Fatalf("EnsureAccount (first): %v", err)
	}
	if err := c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeAgent, flags); err != nil {
		t.Fatalf("EnsureAccount (second) should be a no-op success, got %v", err)
	}
}

// TestEnsureAccount_ConflictSurfaced (negative, Testing Doctrine §10) — the same
// id created with a different code returns ErrAccountConflict, and the original
// account is left unchanged.
func TestEnsureAccount_ConflictSurfaced(t *testing.T) {
	ctx := context.Background()
	c := newTestClient(t)
	id, err := tigerbeetle.AccountID(tigerbeetle.PrefixOwner, sharedTB.Salt(t)+"-conflict")
	if err != nil {
		t.Fatalf("AccountID: %v", err)
	}
	if err := c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeOwner,
		tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeOwner)); err != nil {
		t.Fatalf("EnsureAccount (owner): %v", err)
	}
	err = c.EnsureAccount(ctx, id, testLedger, tigerbeetle.CodeAgent,
		tigerbeetle.DefaultFlagsForCode(tigerbeetle.CodeAgent))
	if !errors.Is(err, tigerbeetle.ErrAccountConflict) {
		t.Fatalf("re-create with different code: want ErrAccountConflict, got %v", err)
	}
	acc, found, err := c.LookupAccount(ctx, id)
	if err != nil || !found {
		t.Fatalf("LookupAccount after conflict: found=%v err=%v", found, err)
	}
	if tigerbeetle.AccountCode(acc.Code) != tigerbeetle.CodeOwner {
		t.Fatalf("conflict mutated the account: code = %d, want %d", acc.Code, tigerbeetle.CodeOwner)
	}
}

// TestHealth_OK — the health check passes against the live cluster.
func TestHealth_OK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := newTestClient(t).Health(ctx); err != nil {
		t.Fatalf("Health against live cluster: %v", err)
	}
}

// TestHealth_UnreachableAddress (negative, Testing Doctrine §10) — the health
// check reports ErrUnavailable against a closed address, bounded by ctx.
func TestHealth_UnreachableAddress(t *testing.T) {
	c, err := tigerbeetle.NewClient(0, []string{"127.0.0.1:1"}, testutil.DiscardLogger())
	if err != nil {
		return // unreachable detected at construction is an acceptable outcome
	}
	t.Cleanup(c.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Health(ctx); !errors.Is(err, tigerbeetle.ErrUnavailable) {
		t.Fatalf("Health against closed port: want ErrUnavailable, got %v", err)
	}
}
