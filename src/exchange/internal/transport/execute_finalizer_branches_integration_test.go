//go:build integration

package transport_test

import (
	"context"
	"sync"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// TestFinalizeBatchResponse_ConcurrentAllDeniedLoserReturnsStoredWinner drives
// the real write-once finalizer race through the public RPC. The first request
// wins the claim but pauses after Authorize denies it; the exact duplicate waits
// out admission, independently reaches the same denial, and finalizes first.
func TestFinalizeBatchResponse_ConcurrentAllDeniedLoserReturnsStoredWinner(t *testing.T) {
	h, rec := newRecordingHarness(t)
	offer := discoverOffer(t, h,
		seedResourceWithRate(t, h, "/articles/finalize-concurrent-denied", "50.00"))

	var once sync.Once
	releaseFirst := make(chan struct{})
	rec.mu.Lock()
	rec.afterAuthorize = func(context.Context) {
		first := false
		once.Do(func() { first = true })
		if first {
			<-releaseFirst
		}
	}
	rec.mu.Unlock()

	const key = "tx-finalize-concurrent-denied"
	type result struct {
		resp *connect.Response[rampv1.TransactionResponse]
		err  error
	}
	firstDone := make(chan result, 1)
	go func() {
		resp, err := executeSingleItem(t, h, key, offer)
		firstDone <- result{resp: resp, err: err}
	}()

	waitForAuthorizeCount(t, rec, 1)
	second, err := executeSingleItem(t, h, key, offer)
	if err != nil {
		t.Fatalf("concurrent finalizer winner: %v", err)
	}
	close(releaseFirst)
	first := <-firstDone
	if first.err != nil {
		t.Fatalf("lost finalizer must return the stored winner: %v", first.err)
	}
	if !proto.Equal(first.resp.Msg, second.Msg) {
		t.Fatalf("lost finalizer response differs from durable winner:\n first=%v\nsecond=%v",
			first.resp.Msg, second.Msg)
	}
	assertItemDenied(t, first.resp, nil, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
	if got := rec.authorizeCallCount(); got != 2 {
		t.Errorf("Authorize calls = %d, want 2", got)
	}
	if got := rec.recordCallCount(); got != 0 {
		t.Errorf("Record calls = %d, want 0", got)
	}
	assertNoTransaction(t, h, derivedTxKey(key, offer))
	assertBalanceUnchanged(t, h)
}
