//go:build integration

package transport_test

import (
	"context"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
)

// A retry whose original committed every item but has not finalized its claim.
//
// The claim row and the transaction rows are written at different points: the
// claim is taken at admission, each item's row commits during execution, and the
// finalized response is stored last. Between the last item's commit and that
// store, the claim carries a NULL response while every row the response would be
// rebuilt from is already readable. A process that stops in that window leaves
// the claim NULL forever, so a retry that waits for a finalizer waits for
// something nobody is going to write.
//
// Round-trip honesty: both legs drive the public ExecuteTransaction RPC. The
// original is pinned inside the window by blocking the billing adapter's Record,
// which the service calls after the row commits and before it finalizes.

// lostClaimWaitBudget is the wall-clock limit the retry must answer within.
// The bounded wait is finalizedWaitPolls * finalizedPollInterval, about three
// seconds; probing the rows first answers in the time of two reads. The budget
// sits well below the wait and far above the reads, so it separates the two
// without pinning either constant.
const lostClaimWaitBudget = 1500 * time.Millisecond

// TestExecuteTransaction_CommittedRowsAnswerRetryWithoutWaiting pins the source
// order a claim loser reads: the persisted rows are probed BEFORE the bounded
// wait for a finalized response.
//
// The original is held inside the commit-to-finalize window, so its claim
// carries no response and never will while it is held. The retry loses that
// claim on the same digest and must rebuild the original from the committed
// rows at once. Reading the rows only after the wait expires makes this test
// take the full bound and fail on the budget, which is the regression it exists
// to catch.
func TestExecuteTransaction_CommittedRowsAnswerRetryWithoutWaiting(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/lost-claim-probe", "0.05")
	offer := discoverOffer(t, h, uri)

	// Hold the FIRST request inside Record: its transaction row has committed and
	// its response has not been finalized onto the claim. atRecord reports that
	// the window is open; release closes it. The retry's own Record — if it ever
	// reached billing, which it must not — runs unblocked.
	var once sync.Once
	atRecord := make(chan struct{})
	release := make(chan struct{})
	rec.mu.Lock()
	rec.beforeRecord = func(context.Context) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(atRecord)
			<-release
		}
	}
	rec.mu.Unlock()

	const idem = "tx-lost-claim-probe"
	requester := newRequester("agent-test", "agent.example")
	mkReq := func() *rampv1.TransactionRequest {
		req := &rampv1.TransactionRequest{
			Ver:            helpers.ProtocolVersion,
			IdempotencyKey: idem,
			Requester:      requester,
			Items: []*rampv1.TransactionItem{
				{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
			},
		}
		req.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, req)
		return req
	}

	type result struct {
		resp *connect.Response[rampv1.TransactionResponse]
		err  error
	}
	originalDone := make(chan result, 1)
	go func() {
		resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
		originalDone <- result{resp, err}
	}()
	<-atRecord

	started := time.Now()
	retry, retryErr := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
	elapsed := time.Since(started)
	if retryErr != nil {
		t.Fatalf("retry against an unfinalized claim must be answered, not fail: %v", retryErr)
	}
	if elapsed > lostClaimWaitBudget {
		t.Errorf("retry took %s, want under %s — it waited out the bound for a finalized "+
			"response instead of rebuilding the original from the committed rows",
			elapsed.Round(time.Millisecond), lostClaimWaitBudget)
	}

	// The retry rebuilt the original rather than executing: the item carries the
	// signed URL the original minted, and billing saw exactly one Authorize.
	item := singleResultItem(t, retry)
	if item.GetRetrievalEndpoint() == "" {
		t.Error("rebuilt response carries no retrieval endpoint")
	}
	if got := rec.authorizeCallCount(); got != 1 {
		t.Errorf("Authorize calls = %d, want 1 (the retry must not re-execute)", got)
	}

	close(release)
	original := <-originalDone
	if original.err != nil {
		t.Fatalf("original must complete: %v", original.err)
	}
	// The rebuild and the response the original finalized are the same message.
	// They are built by the same function over the same rows and thumbprint, so a
	// difference here means one of those two inputs diverged.
	if !proto.Equal(original.resp.Msg, retry.Msg) {
		t.Fatalf("rebuilt response differs from the original:\n original=%v\n retry=%v",
			original.resp.Msg, retry.Msg)
	}
	if got := rec.recordCallCount(); got != 1 {
		t.Errorf("Record calls = %d, want 1", got)
	}
	if got := rec.releaseCallCount(); got != 0 {
		t.Errorf("Release calls = %d, want 0", got)
	}
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (charged exactly once)", bal.Value.FloatString(4))
	}
}
