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

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Finalized request-level replay.
//
// The finalized TransactionResponse — denials included — persists write-once
// on the request claim before the RPC returns. An exact retry is served that
// payload verbatim instead of re-executing, which is what makes replay hold
// for the shapes the per-item rows cannot cover: an all-denied request (zero
// rows) and a mixed success/denial batch (a partial row set). The same stored
// response is what the loser of a concurrent duplicate waits for, so both
// callers of an identical request receive the one original result and the
// shared billing hold is never released out from under the winner.
//
// Round-trip honesty: every leg drives the public RPCs. Re-execution absence
// is observed on the recording billing adapter (call counts) and through
// repo.TransactionRepo (documented tier-2 fallback — no public
// transaction-read RPC exists yet).

// authorizeCallCount mirrors recordCallCount/releaseCallCount for Authorize.
func (r *recordingAdapter) authorizeCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.authorizeKeys)
}

// waitForAuthorizeCount blocks until the adapter has recorded at least n
// Authorize calls, so a test can proceed once a concurrent request is known to
// be inside (or past) Authorize. Bounded so a wiring mistake fails loudly
// rather than hanging.
func waitForAuthorizeCount(t *testing.T, rec *recordingAdapter, n int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if rec.authorizeCallCount() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d Authorize calls (saw %d)", n, rec.authorizeCallCount())
}

// TestExecuteTransaction_AllDeniedRetryReplaysOriginalDenial drives a request
// whose sole item is denied for insufficient balance, then retries it exactly.
// The retry must be served the ORIGINAL denial response with zero billing
// calls — before the finalized-response store, an all-denied request left no
// durable row, so a resent key re-executed and could charge once conditions
// changed (e.g. after a top-up).
func TestExecuteTransaction_AllDeniedRetryReplaysOriginalDenial(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/denied-replay", "50.00") // balance is 10.00
	offer := discoverOffer(t, h, uri)

	const idem = "tx-denied-replay"
	first, err := executeSingleItem(t, h, idem, offer)
	assertItemDenied(t, first, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
	callsAfterFirst := rec.authorizeCallCount()

	second, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("exact retry of an all-denied request must be answered, not fail: %v", err)
	}
	if !proto.Equal(first.Msg, second.Msg) {
		t.Fatalf("retry response differs from the original:\n first=%v\nsecond=%v", first.Msg, second.Msg)
	}
	// The retry re-executed nothing: no new Authorize, no row, no charge.
	if got := rec.authorizeCallCount(); got != callsAfterFirst {
		t.Errorf("retry made %d new Authorize calls, want 0 (must replay, not re-execute)", got-callsAfterFirst)
	}
	assertNoTransaction(t, h, derivedTxKey(idem, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteTransaction_MixedBatchRetryReplaysOriginal drives a two-item
// batch where one item succeeds and one is denied, then retries it exactly.
// Before the finalized-response store the retry hit the partial-replay refusal
// (only the successful item had a row) and got AlreadyExists; now it must be
// served the original mixed response with zero new billing calls.
func TestExecuteTransaction_MixedBatchRetryReplaysOriginal(t *testing.T) {
	h, rec := newRecordingHarness(t)
	cheapURI := seedResourceWithRate(t, h, "/articles/mixed-cheap", "0.05")
	direURI := seedResourceWithRate(t, h, "/articles/mixed-dire", "50.00")
	cheap := discoverOffer(t, h, cheapURI)
	dire := discoverOffer(t, h, direURI)

	const reqKey = "tx-mixed-replay"
	requester := agentRequester("agent-test")
	itemFor := func(o *rampv1.Offer) *rampv1.TransactionItem {
		return &rampv1.TransactionItem{
			Offer:           o,
			AgentAcceptance: signAcceptanceFor(t, h.callerPriv, o, requester, reqKey),
		}
	}

	first, err := executeItems(t, h, reqKey, itemFor(cheap), itemFor(dire))
	if err != nil {
		t.Fatalf("mixed batch must succeed at the request level: %v", err)
	}
	items := first.Msg.GetItems()
	if len(items) != 2 || items[0].GetRetrievalEndpoint() == "" ||
		items[1].GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Fatalf("premise: want success item + insufficient-balance denial, got %v", items)
	}
	authAfterFirst, recAfterFirst := rec.authorizeCallCount(), rec.recordCallCount()

	second, err := executeItems(t, h, reqKey, itemFor(cheap), itemFor(dire))
	if err != nil {
		t.Fatalf("exact retry of a mixed batch must return the original response, not an error: %v", err)
	}
	if !proto.Equal(first.Msg, second.Msg) {
		t.Fatalf("retry response differs from the original:\n first=%v\nsecond=%v", first.Msg, second.Msg)
	}
	if a, r := rec.authorizeCallCount(), rec.recordCallCount(); a != authAfterFirst || r != recAfterFirst {
		t.Errorf("retry touched billing (authorize %d->%d, record %d->%d), want replay with no calls",
			authAfterFirst, a, recAfterFirst, r)
	}
	// Exactly the successful item persisted; the denied one never grew a row.
	txRepo := repo.NewTransactionRepo(h.queries)
	if _, err := txRepo.ByIdempotencyKey(h.ctx, derivedTxKey(reqKey, cheap)); err != nil {
		t.Fatalf("successful item's row must survive the retry: %v", err)
	}
	assertNoTransaction(t, h, derivedTxKey(reqKey, dire))
}

// TestExecuteTransaction_ConcurrentDuplicateBothReceiveOriginal sends the SAME
// request from two goroutines at once. The claim winner executes; the loser
// waits for the finalized response and serves it. Both callers must receive
// the one original response, exactly one Authorize and one Record happen, the
// shared billing hold is never released (Authorize is idempotent on the hold
// key, so a release by the loser would strip the winner's charge), exactly one
// row persists, and the balance moves once.
func TestExecuteTransaction_ConcurrentDuplicateBothReceiveOriginal(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/concurrent-dup", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-concurrent-dup"
	requester := newRequester("agent-test", "agent.example")
	base := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
		},
	}
	base.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, base)
	reqs := []*rampv1.TransactionRequest{base, proto.Clone(base).(*rampv1.TransactionRequest)}

	var wg sync.WaitGroup
	resps := make([]*connect.Response[rampv1.TransactionResponse], 2)
	errs := make([]error, 2)
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(reqs[i]))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent caller %d failed: %v (both must receive the original response)", i, err)
		}
	}
	if !proto.Equal(resps[0].Msg, resps[1].Msg) {
		t.Fatalf("concurrent callers received different responses:\n a=%v\n b=%v", resps[0].Msg, resps[1].Msg)
	}
	if resps[0].Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("original response carries no retrieval endpoint")
	}
	if got := rec.authorizeCallCount(); got != 1 {
		t.Errorf("Authorize calls = %d, want 1 (the loser must not enter billing)", got)
	}
	if got := rec.recordCallCount(); got != 1 {
		t.Errorf("Record calls = %d, want 1", got)
	}
	if got := rec.releaseCallCount(); got != 0 {
		t.Errorf("Release calls = %d, want 0 (the shared hold must never be released)", got)
	}
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(idem, offer)); err != nil {
		t.Fatalf("exactly one persisted transaction expected: %v", err)
	}
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want := mustBillingAmount(t, "9.95", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (charged exactly once)", bal.Value.FloatString(4))
	}
}

// TestExecuteTransaction_ConcurrentDuplicateLoserKeepsSharedHold drives the
// residual race the claim-wait cannot cover: the loser must slip PAST the wait
// and reach the duplicate-persist branch, so the fix that keeps the shared
// hold there is exercised (not left at 0% coverage where a restored
// unconditional Release would go unnoticed).
//
// Determinism without a production knob: a blocking hook AFTER the winner's
// first Authorize pins it once its hold EXISTS but before it persists. The
// second request loses the claim, waits the real bound (~3s), times out with
// no finalized response, falls through to execution, authorizes (idempotent on
// the still-live hold key → the SAME hold id), persists first, Records, and
// finalizes. The winner is then released, takes the per-item UNIQUE loss, and
// must KEEP that shared hold (it is the one the loser committed against) and
// recover the loser's now-stored response.
//
// Assertions: two Authorize attempts resolving to ONE hold, exactly one
// Record, ZERO Release, one row, one charge, both callers served the same
// response. Restoring the old unconditional Release turns this RED (Release
// count 1, and the committed transaction's charge stripped).
func TestExecuteTransaction_ConcurrentDuplicateLoserKeepsSharedHold(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/concurrent-dup-race", "0.05")
	offer := discoverOffer(t, h, uri)

	// Release the winner's Authorize block once the loser has had time to lose
	// the claim, wait out the bound, and commit its own row + finalize. A single
	// gate fires on the first Authorize only; the loser's Authorize (the second)
	// runs unblocked.
	var once sync.Once
	release := make(chan struct{})
	rec.mu.Lock()
	rec.afterAuthorize = func(context.Context) {
		first := false
		once.Do(func() { first = true })
		if first {
			<-release
		}
	}
	rec.mu.Unlock()

	const idem = "tx-concurrent-dup-race"
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
	winnerDone := make(chan result, 1)
	go func() {
		resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
		winnerDone <- result{resp, err}
	}()

	// Wait until the winner is blocked inside Authorize (its key recorded), so
	// the loser is guaranteed to lose the claim and enter the wait path.
	waitForAuthorizeCount(t, rec, 1)

	loserResp, loserErr := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(mkReq()))
	if loserErr != nil {
		t.Fatalf("loser (fell through the wait) must succeed: %v", loserErr)
	}
	close(release)
	winner := <-winnerDone
	if winner.err != nil {
		t.Fatalf("winner must recover the loser's committed response, not fail: %v", winner.err)
	}

	if !proto.Equal(winner.resp.Msg, loserResp.Msg) {
		t.Fatalf("winner and loser received different responses:\n win=%v\n los=%v", winner.resp.Msg, loserResp.Msg)
	}
	if got := rec.authorizeCallCount(); got != 2 {
		t.Errorf("Authorize calls = %d, want 2 (both requests authorized; the loser took the wait path)", got)
	}
	if got := rec.recordCallCount(); got != 1 {
		t.Errorf("Record calls = %d, want 1 (one hold settled)", got)
	}
	if got := rec.releaseCallCount(); got != 0 {
		t.Errorf("Release calls = %d, want 0 (the winner must keep the hold the loser committed against)", got)
	}
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(idem, offer)); err != nil {
		t.Fatalf("exactly one persisted transaction expected: %v", err)
	}
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (charged exactly once)", bal.Value.FloatString(4))
	}
}

// TestExecuteTransaction_AllDeniedReplayAfterRestart proves the all-denied
// finalized response is DURABLE and is a REPLAY, not a re-execution: a second
// Exchange server sharing no in-process state (only the Postgres pool) serves the
// ORIGINAL denial on an exact retry even after the balance is topped up so that a
// re-execution would now SUCCEED. The divergence is the point — if the restarted
// server re-executed instead of replaying, the retry would mint a signed URL and
// charge; because it replays the durable claim response, it returns the original
// insufficient-balance denial.
func TestExecuteTransaction_AllDeniedReplayAfterRestart(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/denied-restart", "50.00") // balance 10.00
	offer := discoverOffer(t, h, uri)

	const idem = "tx-denied-restart"
	first, err := executeSingleItem(t, h, idem, offer)
	assertItemDenied(t, first, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)

	// Top up the balance so a RE-EXECUTION of the same request would now succeed
	// (50.00 charge against 10.00+100.00). A durable replay must ignore this and
	// return the original denial; only a re-execution would produce a signed URL.
	if err := h.billing.Credit(h.ctx, h.billingRef, mustBillingAmount(t, "100.00", "USD"), "topup-denied-restart"); err != nil {
		t.Fatalf("credit top-up: %v", err)
	}
	balBeforeReplay, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after top-up: %v", err)
	}

	requester := newRequester("agent-test", "agent.example")
	replayReq := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
		},
	}
	replayReq.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, replayReq)
	second, err := restartedExchangeClient(t, h).ExecuteTransaction(h.ctx, connect.NewRequest(replayReq))
	if err != nil {
		t.Fatalf("restarted server must replay the durable denial, not fail: %v", err)
	}
	if !proto.Equal(first.Msg, second.Msg) {
		t.Fatalf("restart replay differs from the original:\n first=%v\nsecond=%v", first.Msg, second.Msg)
	}
	// Explicit: the replayed item is still the denial, with no signed URL a
	// re-execution would have minted after the top-up.
	replayed := second.Msg.GetItems()[0]
	if replayed.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Fatalf("restart retry denial_reason = %v, want the replayed INSUFFICIENT_BALANCE "+
			"(a re-execution after the top-up would have succeeded)", replayed.GetDenialReason())
	}
	if replayed.GetRetrievalEndpoint() != "" {
		t.Fatalf("restart retry minted a retrieval endpoint %q — it re-executed against the "+
			"topped-up balance instead of replaying the denial", replayed.GetRetrievalEndpoint())
	}
	balAfterReplay, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after replay: %v", err)
	}
	if balAfterReplay.Value.Cmp(balBeforeReplay.Value) != 0 {
		t.Fatalf("balance moved on restarted replay: %s -> %s",
			balBeforeReplay.Value.FloatString(4), balAfterReplay.Value.FloatString(4))
	}
	assertNoTransaction(t, h, derivedTxKey(idem, offer))
}
