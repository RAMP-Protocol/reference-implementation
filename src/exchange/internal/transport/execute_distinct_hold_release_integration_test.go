//go:build integration

package transport_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestExecuteTransaction_ConcurrentDuplicateLoserReleasesDistinctHold pins the
// OTHER arm of releaseDuplicateLossHold: the late duplicate that authorizes a
// DISTINCT hold (not the winner's shared one) and must RELEASE it after losing
// the per-item UNIQUE insert. The sibling shared-hold test only exercises the
// keep-the-shared-hold arm; restoring an unconditional keep here would strand the
// duplicate's funds, and this test turns RED (Release count 0) if that arm stops
// releasing.
//
// Reaching the distinct hold needs a precise interleave, arranged with two
// coordinated billing hooks and no production change:
//
//  1. The winner (A) wins the claim, authorizes hold Ha, and BLOCKS right after
//     Authorize — before it persists — so its row is not yet visible.
//  2. The loser (B) loses the claim, waits out the real finalized-response bound
//     (~3s), times out, and probes the transaction_log — finding NOTHING, because
//     A has not persisted. B therefore proceeds toward its own execution.
//  3. When B reaches its Authorize, it releases A. A now persists (row committed
//     under Ha), Records (which FREES the live-hold dedup key for the derived
//     key), and finalizes.
//  4. Once A has Recorded, B is released. B authorizes the SAME derived key, but
//     the dedup key is gone, so it gets a DISTINCT fresh hold Hb. B persists,
//     loses the UNIQUE insert to A's committed row, and releaseDuplicateLossHold
//     sees Hb != the row's Ha, so it RELEASES Hb.
//
// Assertions: two Authorize attempts, exactly one Record (A's Ha), exactly one
// Release (B's distinct Hb), one committed row, one charge, both callers served
// the same original response.
func TestExecuteTransaction_ConcurrentDuplicateLoserReleasesDistinctHold(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/distinct-hold-release", "0.05")
	offer := discoverOffer(t, h, uri)

	var authBefore, authAfter atomic.Int32
	aProceed := make(chan struct{}) // closed by B's Authorize → lets A persist+record
	bProceed := make(chan struct{}) // closed once A has Recorded → lets B authorize

	rec.mu.Lock()
	// The winner blocks AFTER its Authorize (hold Ha exists, not yet persisted)
	// until the loser reaches its own Authorize.
	rec.afterAuthorize = func(context.Context) {
		if authAfter.Add(1) == 1 {
			<-aProceed
		}
	}
	// The loser, on reaching Authorize, releases the winner, then waits until the
	// winner has Recorded (freeing the dedup key) so its own Authorize opens a
	// distinct hold.
	rec.beforeAuthorize = func(context.Context) {
		if authBefore.Add(1) == 2 {
			close(aProceed)
			<-bProceed
		}
	}
	rec.mu.Unlock()

	// Watcher: release the loser's Authorize once the winner has Recorded.
	go func() {
		for i := 0; i < 500; i++ {
			if rec.recordCallCount() >= 1 {
				close(bProceed)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(bProceed) // safety: never deadlock; the assertions catch a bad interleave
	}()

	requester := newRequester("agent-test", "agent.example")
	mkReq := func() *rampv1.TransactionRequest {
		return &rampv1.TransactionRequest{
			Ver:            helpers.ProtocolVersion,
			IdempotencyKey: "tx-distinct-hold-release",
			Requester:      requester,
			Items: []*rampv1.TransactionItem{
				{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, "tx-distinct-hold-release")},
			},
		}
	}

	type result struct {
		resp *connect.Response[rampv1.TransactionResponse]
		err  error
	}
	winnerDone := make(chan result, 1)
	go func() {
		resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
		winnerDone <- result{resp, err}
	}()

	// Wait until the winner has claimed and is blocked in afterAuthorize, so the
	// loser is guaranteed to lose the claim and enter the wait path.
	waitForAuthorizeCount(t, rec, 1)

	loserResp, loserErr := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
	if loserErr != nil {
		t.Fatalf("loser (distinct-hold path) must recover the winner's response, not fail: %v", loserErr)
	}
	winner := <-winnerDone
	if winner.err != nil {
		t.Fatalf("winner must succeed: %v", winner.err)
	}

	if !proto.Equal(winner.resp.Msg, loserResp.Msg) {
		t.Fatalf("winner and loser received different responses:\n win=%v\n los=%v", winner.resp.Msg, loserResp.Msg)
	}
	if got := rec.authorizeCallCount(); got != 2 {
		t.Errorf("Authorize calls = %d, want 2 (winner + loser each authorized)", got)
	}
	if got := rec.recordCallCount(); got != 1 {
		t.Errorf("Record calls = %d, want 1 (only the winner settled its hold)", got)
	}
	if got := rec.releaseCallCount(); got != 1 {
		t.Errorf("Release calls = %d, want 1 (the loser must release its DISTINCT hold)", got)
	}
	// The one release was the loser's distinct hold, not the winner's settled one.
	if rel, ok := rec.lastReleaseCall(); ok {
		if committed, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey("tx-distinct-hold-release", offer)); err == nil {
			if rel.BillingID == committed.BillingID {
				t.Errorf("released the winner's settled hold %q; want the loser's distinct hold", rel.BillingID)
			}
		}
	}
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey("tx-distinct-hold-release", offer)); err != nil {
		t.Fatalf("exactly one persisted transaction expected: %v", err)
	}
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (charged exactly once; the distinct hold was released)", bal.Value.FloatString(4))
	}
}
