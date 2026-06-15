//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// ---- recording adapter ----------------------------------------------------

// recordingAdapter wraps a billing.Adapter and records every Authorize /
// Record / Release / Refund invocation (including the idempotency key) so tests
// can assert call counts and lifecycle-key threading. It is NOT a mock of an
// external API — every call is forwarded to the inner adapter so all balance
// semantics remain correct.
type recordingAdapter struct {
	inner         billing.Adapter
	mu            sync.Mutex
	authorizeKeys []string
	recordCalls   []recordCall
	releaseCalls  []releaseCall
	refundCalls   []refundCall
	// failRecord, when non-nil, is returned by Record instead of forwarding.
	failRecord error
}

type recordCall struct {
	BillingID string
	Qty       int64
	Key       string
}

type releaseCall struct {
	BillingID string
	Key       string
}

type refundCall struct {
	BillingID string
	Amount    billing.Amount
	Reason    string
	Key       string
}

func newRecordingAdapter(inner billing.Adapter) *recordingAdapter {
	return &recordingAdapter{inner: inner}
}

func (r *recordingAdapter) Authorize(ctx context.Context, req billing.AuthorizeRequest) (billing.AuthorizeResult, error) {
	r.mu.Lock()
	r.authorizeKeys = append(r.authorizeKeys, req.IdempotencyKey)
	r.mu.Unlock()
	return r.inner.Authorize(ctx, req)
}

func (r *recordingAdapter) Record(ctx context.Context, billingID string, qty int64, key string) error {
	r.mu.Lock()
	r.recordCalls = append(r.recordCalls, recordCall{BillingID: billingID, Qty: qty, Key: key})
	fail := r.failRecord
	r.mu.Unlock()
	if fail != nil {
		return fail
	}
	return r.inner.Record(ctx, billingID, qty, key)
}

func (r *recordingAdapter) Release(ctx context.Context, billingID string, key string) error {
	r.mu.Lock()
	r.releaseCalls = append(r.releaseCalls, releaseCall{BillingID: billingID, Key: key})
	r.mu.Unlock()
	return r.inner.Release(ctx, billingID, key)
}

func (r *recordingAdapter) Refund(ctx context.Context, billingID string, amount billing.Amount, reason, key string) error {
	r.mu.Lock()
	r.refundCalls = append(r.refundCalls, refundCall{BillingID: billingID, Amount: amount, Reason: reason, Key: key})
	r.mu.Unlock()
	return r.inner.Refund(ctx, billingID, amount, reason, key)
}

func (r *recordingAdapter) GetBalance(ctx context.Context, agentID string) (billing.Amount, error) {
	return r.inner.GetBalance(ctx, agentID)
}

func (r *recordingAdapter) GetQuota(ctx context.Context, agentID string) (int64, error) {
	return r.inner.GetQuota(ctx, agentID)
}

func (r *recordingAdapter) recordCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.recordCalls)
}

func (r *recordingAdapter) releaseCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.releaseCalls)
}

func (r *recordingAdapter) lastRecordCall() (recordCall, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.recordCalls) == 0 {
		return recordCall{}, false
	}
	return r.recordCalls[len(r.recordCalls)-1], true
}

func (r *recordingAdapter) lastAuthorizeKey() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.authorizeKeys) == 0 {
		return "", false
	}
	return r.authorizeKeys[len(r.authorizeKeys)-1], true
}

func (r *recordingAdapter) lastReleaseCall() (releaseCall, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.releaseCalls) == 0 {
		return releaseCall{}, false
	}
	return r.releaseCalls[len(r.releaseCalls)-1], true
}

// ---- harness + failure doubles ---------------------------------------------

// newRecordingHarness builds a testHarness whose server is backed by a
// recordingAdapter wrapping a 10 USD InMemoryAdapter, so tests can observe
// Record/Release calls while balance semantics stay real. Delegates the
// bring-up to the shared newTestHarnessWith (Testing Doctrine #7).
func newRecordingHarness(t *testing.T) (*testHarness, *recordingAdapter) {
	t.Helper()
	return newRecordingHarnessWith(t, harnessOptions{})
}

// newRecordingHarnessWith is newRecordingHarness with extra harness options
// (e.g. a failing txRunner or keystore to drive the ExecuteTransaction hot-path
// failure branches). The inner/server adapters are always the
// recording pair; callers must not set opts.inner / opts.server.
func newRecordingHarnessWith(t *testing.T, opts harnessOptions) (*testHarness, *recordingAdapter) {
	t.Helper()
	inner := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{
			"agent-test": mustBillingAmount(t, "10.00", "USD"),
		},
	})
	rec := newRecordingAdapter(inner)
	opts.inner = inner
	opts.server = rec
	return newTestHarnessWith(t, opts), rec
}

// failTxRunner is a db.TxRunner whose WithTx always fails, driving the
// persist-failure branch of ExecuteTransaction.
type failTxRunner struct{}

func (failTxRunner) WithTx(_ context.Context, _ func(pgx.Tx) error) error {
	return errors.New("persist boom")
}

// failKeyStore is a signing.KeyStore that always errors, driving the
// URL-sign-failure branch of ExecuteTransaction.
type failKeyStore struct{}

func (failKeyStore) Ed25519(string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return nil, nil, errors.New("keystore unavailable")
}

func (failKeyStore) RSA(string) (*rsa.PrivateKey, error) {
	return nil, errors.New("keystore unavailable")
}

// ---- tests -----------------------------------------------------------------

// TestExecuteTransaction_RecordsOnExecute asserts that billing.Record is called
// exactly once during ExecuteTransaction, with the estimated quantity from the
// offer, and that the balance is debited accordingly. The pre-task-05 design
// (docs/design/design-exchange.md §ExecuteTransaction:555-569) is restored:
// money commitment happens at Execute, not at ReportUsage.
func TestExecuteTransaction_RecordsOnExecute(t *testing.T) {
	h, rec := newRecordingHarness(t)
	_, billingID := executeTransactionFor(t, h, 100)

	if n := rec.recordCallCount(); n != 1 {
		t.Errorf("Record called %d time(s); want exactly 1", n)
	}
	call, ok := rec.lastRecordCall()
	if !ok {
		t.Fatal("Record was not called during ExecuteTransaction")
	}
	if call.BillingID != billingID {
		t.Errorf("Record billingID = %q, want %q", call.BillingID, billingID)
	}
	if call.Qty != 100 {
		t.Errorf("Record qty = %d, want 100 (estimated)", call.Qty)
	}

	// 10.00 - 0.05 * 100 = 5.00 (default fixture unit cost is 0.05/USD).
	bal, err := h.billing.GetBalance(h.ctx, "agent-test")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want, _ := billing.NewAmount("5.00", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after Execute = %s; want 5.00", bal.Value.FloatString(4))
	}

	// Release must NOT be called on the success path.
	if n := rec.releaseCallCount(); n != 0 {
		t.Errorf("Release called %d time(s) on success path; want 0", n)
	}
}

// TestExecuteTransaction_RecordFailureLogsButSucceeds verifies the best-effort
// stance documented in design-exchange.md:564 ("Log but don't fail —
// transaction is already committed."). A Record failure must not fail the
// request; the agent still gets the signed URL.
func TestExecuteTransaction_RecordFailureLogsButSucceeds(t *testing.T) {
	h, rec := newRecordingHarness(t)

	rec.mu.Lock()
	rec.failRecord = errors.New("billing provider unavailable")
	rec.mu.Unlock()

	tx, billingID := executeTransactionFor(t, h, 50)
	if tx == "" || billingID == "" {
		t.Fatal("execute returned empty tx/billing id despite best-effort semantics")
	}
	if n := rec.recordCallCount(); n != 1 {
		t.Errorf("Record called %d time(s); want exactly 1", n)
	}
	// Release must not be triggered just because Record failed — the
	// transaction is committed and the agent owns the URL.
	if n := rec.releaseCallCount(); n != 0 {
		t.Errorf("Release called %d time(s) after Record failure; want 0", n)
	}
}

// TestReportUsage_DoesNotCallBilling asserts that ReportUsage never invokes
// the billing adapter (per design-exchange.md §ReportUsage:765-810). Money
// commitment was at Execute; the report is a pure audit write.
func TestReportUsage_DoesNotCallBilling(t *testing.T) {
	h, rec := newRecordingHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	// Reset the Record/Release counters so we only observe ReportUsage's calls.
	rec.mu.Lock()
	recordCountAfterExecute := len(rec.recordCalls)
	releaseCountAfterExecute := len(rec.releaseCalls)
	rec.mu.Unlock()

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-audit",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 80},
	}))
	if err != nil {
		t.Fatalf("report: %v", err)
	}

	if got := rec.recordCallCount(); got != recordCountAfterExecute {
		t.Errorf("Record was called %d additional time(s) during ReportUsage; want 0",
			got-recordCountAfterExecute)
	}
	if got := rec.releaseCallCount(); got != releaseCountAfterExecute {
		t.Errorf("Release was called %d additional time(s) during ReportUsage; want 0",
			got-releaseCountAfterExecute)
	}
}

// TestReportUsage_ConcurrentSecondGetsFailedPrecondition sends two concurrent
// ReportUsage calls for the same transaction under -race. Exactly one must
// fail with connect.CodeFailedPrecondition (state guard miss → repo sentinel
// → KindFailedPrecondition). The billing adapter is not called for either —
// money commitment is at Execute, not Report.
func TestReportUsage_ConcurrentSecondGetsFailedPrecondition(t *testing.T) {
	h, rec := newRecordingHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	rec.mu.Lock()
	recordCountAfterExecute := len(rec.recordCalls)
	releaseCountAfterExecute := len(rec.releaseCalls)
	rec.mu.Unlock()

	var wg sync.WaitGroup
	var failedPrecondCount, otherErrCount, okCount atomic.Int32
	// Distinct source-report IDs so v1.1's (transaction_id, source_report_id)
	// idempotency probe does NOT short-circuit the second call as a replay.
	// Both reports then race to settle the SAME obligation, exercising the
	// PENDING-state guard — the loser must get FailedPrecondition.
	reportIDs := [2]string{"r-concurrent-0", "r-concurrent-1"}
	for i := range 2 {
		wg.Add(1)
		go func(reportID string) {
			defer wg.Done()
			_, e := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
				Ver:           "1.0",
				Id:            reportID,
				TransactionId: txID,
				BillingId:     billingID,
				Usage:         &rampv1.Usage{ConsumedQuantity: 100},
			}))
			if e == nil {
				okCount.Add(1)
				return
			}
			var ce *connect.Error
			if ceAs(e, &ce) && ce.Code() == connect.CodeFailedPrecondition {
				failedPrecondCount.Add(1)
				return
			}
			otherErrCount.Add(1)
		}(reportIDs[i])
	}
	wg.Wait()

	if okCount.Load() != 1 {
		t.Errorf("expected exactly one OK from concurrent reports, got %d", okCount.Load())
	}
	if failedPrecondCount.Load() != 1 {
		t.Errorf("expected exactly one FailedPrecondition from the loser, got %d (other errors: %d)",
			failedPrecondCount.Load(), otherErrCount.Load())
	}
	if got := rec.recordCallCount(); got != recordCountAfterExecute {
		t.Errorf("Record was called %d additional time(s) during ReportUsage; want 0",
			got-recordCountAfterExecute)
	}
	if got := rec.releaseCallCount(); got != releaseCountAfterExecute {
		t.Errorf("Release was called %d additional time(s) during ReportUsage; want 0",
			got-releaseCountAfterExecute)
	}
}

// TestExecuteTransaction_ZeroEstimateChargesOneUnit verifies end-to-end:
// an offer with estimated_quantity=0 settles the reserved amount
// (unitCost × clamped-1), NOT unitCost × 0. Pre-fix, Record recomputed the
// charge from the raw 0 and debited nothing — the agent got a billable URL for
// free.
func TestExecuteTransaction_ZeroEstimateChargesOneUnit(t *testing.T) {
	h, rec := newRecordingHarness(t)
	executeTransactionFor(t, h, 0) // zero-estimate offer

	if n := rec.recordCallCount(); n != 1 {
		t.Errorf("Record called %d time(s); want 1", n)
	}
	// Default fixture unit cost is 0.05/USD; the zero estimate clamps to 1
	// unit at Authorize, so the settled charge is 0.05: 10.00 - 0.05 = 9.95.
	bal, err := h.billing.GetBalance(h.ctx, "agent-test")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want, _ := billing.NewAmount("9.95", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after zero-estimate Execute = %s; want 9.95 (charged unitCost*1, not *0)",
			bal.Value.FloatString(4))
	}
}

// assertReleasedOnExecuteFailure drives a single ExecuteTransaction against the
// recording harness, expects it to fail on the named hot-path step, and asserts
// the post-Authorize reservation was released exactly once, Record was never
// reached, and the balance is restored to the 10 USD seed. Shared by the two
// release-on-failure tests.
func assertReleasedOnExecuteFailure(t *testing.T, h *testHarness, rec *recordingAdapter, step string) {
	t.Helper()
	offer := pushDiscoverOffer(t, h, 100)
	if _, err := executeOfferRaw(t, h, offer); err == nil {
		t.Fatalf("expected ExecuteTransaction to fail on %s", step)
	}
	if n := rec.releaseCallCount(); n != 1 {
		t.Errorf("Release called %d time(s) on %s failure; want 1", n, step)
	}
	if n := rec.recordCallCount(); n != 0 {
		t.Errorf("Record called %d time(s); want 0 (never reached after %s failure)", n, step)
	}
	// Retry-safety wiring: the same non-empty lifecycle key (= tx_request.id)
	// must flow into Authorize and Release, so the adapter frees the live-hold
	// key and a same-id retry re-authorizes fresh. The adapter-side mechanism
	// is pinned by adapter_conformance_test.go's Authorize-after-Release case.
	authKey, _ := rec.lastAuthorizeKey()
	rel, ok := rec.lastReleaseCall()
	if !ok || rel.Key == "" || rel.Key != authKey {
		t.Errorf("Release key = %q, want non-empty and == Authorize key %q", rel.Key, authKey)
	}
	bal, err := h.billing.GetBalance(h.ctx, "agent-test")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want, _ := billing.NewAmount("10.00", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after released %s failure = %s; want 10.00 (reservation released)",
			step, bal.Value.FloatString(4))
	}
}

// TestExecuteTransaction_ReleaseOnPersistFailure forces persistTransaction to
// fail (injected failing TxRunner) and asserts the reservation is released.
func TestExecuteTransaction_ReleaseOnPersistFailure(t *testing.T) {
	h, rec := newRecordingHarnessWith(t, harnessOptions{txRunner: failTxRunner{}})
	assertReleasedOnExecuteFailure(t, h, rec, "persist")
}

// TestExecuteTransaction_ReleaseOnURLSignFailure forces mintSignedURL to fail
// (injected failing keystore) and asserts the reservation is released
func TestExecuteTransaction_ReleaseOnURLSignFailure(t *testing.T) {
	h, rec := newRecordingHarnessWith(t, harnessOptions{keystore: failKeyStore{}})
	assertReleasedOnExecuteFailure(t, h, rec, "URL signing")
}

// TestExecuteTransaction_ThreadsIdempotencyKeyOnSuccess asserts the billing
// lifecycle key (= tx_request.id) is threaded identically into Authorize and
// Record on the success path. With the release path covered by
// assertReleasedOnExecuteFailure and the adapter-side free-on-resolve covered
// by adapter_conformance_test.go, this pins the retry-safety property: one
// consistent key flows through the lifecycle and is freed on resolve, so a
// same-id retry after a hot-path failure re-authorizes fresh and charges.
func TestExecuteTransaction_ThreadsIdempotencyKeyOnSuccess(t *testing.T) {
	h, rec := newRecordingHarness(t)
	executeTransactionFor(t, h, 100)

	authKey, ok := rec.lastAuthorizeKey()
	if !ok || authKey == "" {
		t.Fatalf("Authorize key not captured / empty: %q ok=%v", authKey, ok)
	}
	call, ok := rec.lastRecordCall()
	if !ok {
		t.Fatal("Record not called on success path")
	}
	if call.Key != authKey {
		t.Errorf("Record key = %q, want %q (same as Authorize)", call.Key, authKey)
	}
}
