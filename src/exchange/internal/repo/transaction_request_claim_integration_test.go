//go:build integration

package repo_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// digest32 returns a 32-byte digest for the given seed, satisfying the
// items_digest CHECK (octet_length = 32) the same way the canonical request-proof digest does.
func digest32(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

// TestTransactionRequestClaim_LifecycleContract pins the repository contract the
// service's request-level idempotency depends on: claim, then read the finalized
// response back. It is a persistence round-trip through the production
// TransactionRepo surface (no raw SQL): the claim table carries no FK, so no
// seeding is needed.
//
// Two behaviors the service relies on and cannot easily reach through the RPC:
//   - a claimed-but-unfinalized row reads back NIL, which is what makes the
//     service fall through to the per-item reconstruction path (the "legacy
//     NULL claim" case — rows written before the response column existed also
//     read back NIL here);
//   - FinalizeRequest is WRITE-ONCE: the first finalize wins (won=true), a
//     second finalize with a different payload does not overwrite (won=false)
//     and the stored payload is unchanged, so the service returns the winner's
//     response rather than a loser's local variant.
func TestTransactionRequestClaim_LifecycleContract(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	transactions := repo.NewTransactionRepo(sqlc.New(pool))

	const agentID = "agent-claim-contract"
	const key = "tx-claim-contract"
	digest := digest32("digest-a")

	// First claim wins and is unfinalized: response reads back nil.
	won, stored, err := transactions.ClaimRequest(ctx, agentID, key, digest)
	if err != nil || !won {
		t.Fatalf("first ClaimRequest: won=%v err=%v, want won=true", won, err)
	}
	if stored != nil {
		t.Fatalf("winning claim returned a stored digest %q, want nil", stored)
	}
	if resp, err := transactions.RequestResponse(ctx, agentID, key); err != nil || resp != nil {
		t.Fatalf("RequestResponse before finalize = (%v, %v), want (nil, nil) — the legacy/unfinalized fallback signal", resp, err)
	}

	// A second claim under the same (agent, key) loses and reports the stored digest.
	won, stored, err = transactions.ClaimRequest(ctx, agentID, key, digest32("digest-b"))
	if err != nil {
		t.Fatalf("second ClaimRequest: %v", err)
	}
	if won {
		t.Fatal("second ClaimRequest won, want lost (the key is already claimed)")
	}
	if !bytes.Equal(stored, digest) {
		t.Fatalf("lost claim returned digest %q, want the first %q", stored, digest)
	}

	// First finalize wins; the response reads back.
	payload := []byte("winner-response")
	won, err = transactions.FinalizeRequest(ctx, agentID, key, payload)
	if err != nil || !won {
		t.Fatalf("first FinalizeRequest: won=%v err=%v, want won=true", won, err)
	}
	if got, err := transactions.RequestResponse(ctx, agentID, key); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("RequestResponse after finalize = (%q, %v), want the winner payload %q", got, err, payload)
	}

	// Second finalize with a DIFFERENT payload does not overwrite (write-once).
	won, err = transactions.FinalizeRequest(ctx, agentID, key, []byte("loser-response"))
	if err != nil {
		t.Fatalf("second FinalizeRequest: %v", err)
	}
	if won {
		t.Fatal("second FinalizeRequest won, want lost (write-once)")
	}
	if got, err := transactions.RequestResponse(ctx, agentID, key); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("RequestResponse after losing finalize = (%q, %v), want the unchanged winner payload %q", got, err, payload)
	}
}

// TestTransactionRequestClaim_ScopedByAgent proves the claim is keyed by
// (agent_id, idempotency_key): two different agents claim the same key value
// independently, and each reads back its own finalized response.
func TestTransactionRequestClaim_ScopedByAgent(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	transactions := repo.NewTransactionRepo(sqlc.New(pool))

	const key = "tx-shared-key-value"
	for _, agentID := range []string{"agent-x", "agent-y"} {
		won, _, err := transactions.ClaimRequest(ctx, agentID, key, digest32("d"))
		if err != nil || !won {
			t.Fatalf("ClaimRequest(%s): won=%v err=%v, want won=true (independent per agent)", agentID, won, err)
		}
		won, err = transactions.FinalizeRequest(ctx, agentID, key, []byte(agentID+"-resp"))
		if err != nil || !won {
			t.Fatalf("FinalizeRequest(%s): won=%v err=%v", agentID, won, err)
		}
	}
	for _, agentID := range []string{"agent-x", "agent-y"} {
		got, err := transactions.RequestResponse(ctx, agentID, key)
		if err != nil || string(got) != agentID+"-resp" {
			t.Fatalf("RequestResponse(%s) = (%q, %v), want its own response", agentID, got, err)
		}
	}
}
