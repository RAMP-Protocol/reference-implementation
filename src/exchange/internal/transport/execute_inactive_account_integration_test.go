//go:build integration

package transport_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// SoR active-flag gate on the paid path: a registered account the
// operator switched off in the system of record is denied in-body with
// DENIAL_REASON_BILLING_REF_INACTIVE before any money is reserved; free content
// never consults the flag; the flag is read through the production 30-second
// cache, so an operator's change converges within one lifetime and the SoR is
// asked at most once per lifetime per account. SoR read errors on the hot path
// fail open (ADR-021 Follow-up): the transaction proceeds with a warning log.

// sorControl decorates the in-memory SoR to model the system of record from
// the OUTSIDE, the way its real backend (a separate database today, a CRM
// later) behaves: tests flip an account's active flag the way the operator
// would, inject read failures (a SoR outage), and count how often the Exchange
// actually asks. The SoR backend is an external dependency, so this adapter
// boundary is the sanctioned place for a controllable fixture.
type sorControl struct {
	inner *sor.InMemoryAdapter

	mu            sync.Mutex
	isActiveCalls int
	isActiveErr   error // non-nil → IsActive fails with this error
}

func newSorControl() *sorControl { return &sorControl{inner: sor.NewInMemoryAdapter()} }

func (c *sorControl) OnRegister(ctx context.Context, req sor.OnRegisterRequest) (sor.Account, error) {
	return c.inner.OnRegister(ctx, req)
}

func (c *sorControl) IsActive(ctx context.Context, billingRef string) (bool, error) {
	c.mu.Lock()
	c.isActiveCalls++
	failErr := c.isActiveErr
	c.mu.Unlock()
	if failErr != nil {
		return false, failErr
	}
	return c.inner.IsActive(ctx, billingRef)
}

// failWith makes every subsequent IsActive return err (nil restores normal
// reads) — the SoR outage switch.
func (c *sorControl) failWith(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isActiveErr = err
}

// callCount reports how many IsActive reads actually reached the SoR.
func (c *sorControl) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isActiveCalls
}

// setActive is the operator's out-of-band switch: it changes the flag at the
// source, exactly as an operator edits the account inside the SoR.
func (c *sorControl) setActive(t *testing.T, billingRef string, active bool) {
	t.Helper()
	if err := c.inner.SetActive(billingRef, active); err != nil {
		t.Fatalf("SetActive(%q, %v): %v", billingRef, active, err)
	}
}

// assertPaidItemDeniedNoSideEffects drives one paid item and asserts the full
// deny-before-Authorize post-condition shared by every billing-ref denial case:
// the item is denied in-body with DENIAL_REASON_BILLING_REF_INACTIVE and
// NOTHING happened on the side — no transaction_log row (same tier-2 repo read
// the sibling negative tests use — no public transaction-read RPC yet), no
// balance movement, and no billing hold.
// caseLabel names the denied case in failure messages.
func assertPaidItemDeniedNoSideEffects(
	t *testing.T, h *testHarness, rec *recordingAdapter, idem string, offer *rampv1.Offer, caseLabel string,
) {
	t.Helper()
	resp, err := executeSingleItem(t, h, idem, offer)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_BILLING_REF_INACTIVE)
	assertNoTransaction(t, h, derivedTxKey(idem, offer))
	assertBalanceUnchanged(t, h)
	assertNoBillingHold(t, rec, caseLabel)
}

// assertItemSucceeded guards against a silent in-body denial: a denied item
// arrives as HTTP 200 / nil err (see assertItemDenied), so err == nil alone
// does not prove success — only the minted transaction_id does. label names
// the transaction in the failure message.
func assertItemSucceeded(t *testing.T, resp *connect.Response[rampv1.TransactionResponse], label string) {
	t.Helper()
	if item := singleResultItem(t, resp); item.GetTransactionId() == "" {
		t.Fatalf("%s was denied in-body (reason=%v); want success", label, item.GetDenialReason())
	}
}

// TestExecuteTransaction_DeactivatedAccountPaidDenied drives a PAID transaction
// from a registered account the operator switched off. The item is denied
// in-body with DENIAL_REASON_BILLING_REF_INACTIVE, no transaction row is
// persisted, the balance is untouched, and Authorize is never reached — the
// gate runs before any money is reserved. The harness wires the SoR without
// the cache, so the operator's change is visible immediately.
func TestExecuteTransaction_DeactivatedAccountPaidDenied(t *testing.T) {
	ctrl := newSorControl()
	h, rec := newRecordingHarnessWith(t, harnessOptions{sor: ctrl})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	ctrl.setActive(t, h.billingRef, false)

	assertPaidItemDeniedNoSideEffects(t, h, rec, "tx-deactivated-paid", offer, "a deactivated account")
}

// TestExecuteTransaction_DeactivatedAccountFreeSucceeds proves free content is
// unaffected by deactivation: the free path bypasses billing entirely, so the
// active flag is never consulted and the resource is still served.
func TestExecuteTransaction_DeactivatedAccountFreeSucceeds(t *testing.T) {
	ctrl := newSorControl()
	h, rec := newRecordingHarnessWith(t, harnessOptions{sor: ctrl})
	offer := pushDiscoverTermOffer(t, h, "/articles/free-inactive", seedFreeTerm())

	ctrl.setActive(t, h.billingRef, false)
	readsBefore := ctrl.callCount()

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer for a deactivated account: %v", err)
	}
	if itemSignedURL(t, resp) == "" {
		t.Error("free path for a deactivated account returned no signed URL")
	}
	// The billing adapter saw nothing AND the SoR was never asked: the free
	// bypass runs before the active-flag gate.
	assertBillingLifecycle(t, rec, false, 0, 0)
	if got := ctrl.callCount(); got != readsBefore {
		t.Errorf("free path read the SoR %d time(s); want 0 (never reaches billing)", got-readsBefore)
	}
}

// TestExecuteTransaction_ActiveFlagCacheLifecycle exercises the gate through
// the PRODUCTION cache wiring (sor.CachingAdapter, default 30s TTL) on a
// deterministic clock:
//
//  1. paid transactions inside one cache lifetime share a single SoR read (the
//     first one reads and caches; the rest are served from the cache);
//  2. the operator's deactivation converges within one lifetime — stale
//     "active" is served until the entry expires, then the account is denied;
//  3. reactivation converges within one more lifetime, with no restart.
func TestExecuteTransaction_ActiveFlagCacheLifecycle(t *testing.T) {
	det := clock.NewDeterministic(time.Now().UTC())
	ctrl := newSorControl()
	cached := sor.NewCachingAdapter(ctrl, sor.DefaultCacheTTL, det)
	h := newTestHarnessWith(t, harnessOptions{clk: det, sor: cached})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	// First registration takes the flag straight from OnRegister (no IsActive),
	// so the cache is empty here and the FIRST paid transaction performs the
	// lifetime's single SoR read.
	baseline := ctrl.callCount()

	// Two paid transactions inside the first lifetime cost exactly ONE SoR read
	// between them (AC: at most one read per lifetime per account).
	resp1, err := executeOfferRawWithID(t, h, offer, "tx-cached-1")
	if err != nil {
		t.Fatalf("paid transaction #1 while active: %v", err)
	}
	assertItemSucceeded(t, resp1, "paid transaction #1 while active")
	// The operator switches the account off mid-lifetime; the stale cached
	// "active" is served until the entry expires, so this one still succeeds.
	ctrl.setActive(t, h.billingRef, false)
	resp2, err := executeOfferRawWithID(t, h, offer, "tx-cached-2")
	if err != nil {
		t.Fatalf("paid transaction #2 within the same cache lifetime: %v", err)
	}
	assertItemSucceeded(t, resp2, "paid transaction #2 within the same cache lifetime")
	if got := ctrl.callCount() - baseline; got != 1 {
		t.Errorf("SoR read %d time(s) on the hot path within one cache lifetime; want exactly 1", got)
	}

	// One lifetime later the deactivation is visible: denied, nothing persisted.
	det.Advance(sor.DefaultCacheTTL + time.Second)
	const deniedKey = "tx-deactivated-cached"
	resp, err := executeSingleItem(t, h, deniedKey, offer)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_BILLING_REF_INACTIVE)
	assertNoTransaction(t, h, derivedTxKey(deniedKey, offer))

	// The operator switches it back on: one more lifetime later, paid
	// transactions work again — no restart, no cache flush.
	ctrl.setActive(t, h.billingRef, true)
	det.Advance(sor.DefaultCacheTTL + time.Second)
	reResp, err := executeOfferRawWithID(t, h, offer, "tx-reactivated")
	if err != nil {
		t.Fatalf("paid transaction after reactivation: %v", err)
	}
	assertItemSucceeded(t, reResp, "paid transaction after reactivation")
}

// TestExecuteTransaction_SorErrorFailsOpen pins the documented error policy
// (ADR-021 Follow-up): a TRANSIENT SoR read failure on the hot path lets the
// paid transaction proceed — the ledger still gates spending — and the failure
// is loud (a warning log line), never silent.
func TestExecuteTransaction_SorErrorFailsOpen(t *testing.T) {
	ctrl := newSorControl()
	buf := &safeBuffer{}
	h := newTestHarnessWith(t, harnessOptions{
		sor:    ctrl,
		logger: slog.New(slog.NewJSONHandler(buf, nil)),
	})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	ctrl.failWith(errors.New("sor is down"))

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("paid transaction during a SoR outage: %v (fail open: must proceed)", err)
	}
	assertItemSucceeded(t, resp, "paid transaction during a SoR outage (fail open)")
	if !strings.Contains(buf.String(), "sor_active_check_failed") {
		t.Error("no sor_active_check_failed warning logged; fail-open must be loud")
	}
	// The charge landed normally: the ledger balance check still ran.
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want := mustBillingAmount(t, "9.95", "USD") // 10.00 seed − 0.05 seedCatalog price
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after fail-open charge = %s, want 9.95", bal.Value.FloatString(4))
	}
}

// TestExecuteTransaction_SorAccountMissingDenied pins the fail-CLOSED half of
// the error policy: an account the SoR definitively does not know (a registered
// agents row pointing at a ref the SoR lost) is denied like an inactive one —
// a definitive answer is not an outage, so it never falls into the fail-open
// branch.
func TestExecuteTransaction_SorAccountMissingDenied(t *testing.T) {
	ctrl := newSorControl()
	h, rec := newRecordingHarnessWith(t, harnessOptions{sor: ctrl})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	ctrl.failWith(sor.ErrAccountNotFound)

	assertPaidItemDeniedNoSideEffects(t, h, rec, "tx-sor-missing", offer, "a SoR-unknown account")
}
