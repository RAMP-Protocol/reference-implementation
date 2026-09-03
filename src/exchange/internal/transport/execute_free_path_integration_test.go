//go:build integration

package transport_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// These tests pin the free-resource path (ADR-009 D2): an offer whose selected
// term prices at unit_cost == 0 (PRICING_MODEL_FREE) engages NONE of the billing
// lifecycle — no Authorize, no Record, no Release, no reservation handle — while
// the transaction is still recorded and the signed delivery URL is still issued.
//
// Fixtures ingest a FREE LicenseTerm through the public PushResources surface
// (term-derived pricing makes the term the sole price source, so a zero-cost
// offer is expressible end-to-end) and observe billing-lifecycle calls via the
// recordingAdapter shared with billing_ordering_integration_test. Persistence is
// read through the production repository surface (repo.TransactionRepo, the
// Tier-2 documented fallback — there is no public transaction-read RPC),
// keyed on the DERIVED per-item key the items[]
// batch path writes (idempotency_key+":"+offer_id), never the raw sqlc
// Querier (Testing Doctrine §9).

// loadFreePathTx reads the persisted transaction_log row for a single-item
// execute via the production TransactionRepo, keyed on the derived per-item
// persistence key the batch path writes (derivedTxKey).
func loadFreePathTx(t *testing.T, h *testHarness, offer *rampv1.Offer, idem string) repo.TransactionRecord {
	t.Helper()
	key := derivedTxKey(idem, offer)
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, key)
	if err != nil {
		t.Fatalf("TransactionRepo.ByIdempotencyKey(%q): %v", key, err)
	}
	return rec
}

// assertSignedURLHash verifies the persisted signed_url_hash is the SHA-256 of
// the signed URL actually returned to the agent (signing.SignedURL.Hash =
// sha256(full URL)), pinning write-before-sign integrity on the free path.
func assertSignedURLHash(t *testing.T, gotHash []byte, signedURL string) {
	t.Helper()
	want := sha256.Sum256([]byte(signedURL))
	if !bytes.Equal(gotHash, want[:]) {
		t.Error("persisted signed_url_hash != sha256(returned URL)")
	}
}

// TestExecuteTransaction_ZeroCostSkipsBilling is the free-resource-path
// acceptance: a unit_cost == 0 offer, ingested and discovered through the public
// surface, executes with no billing lifecycle, persists billing_id NULL (empty on
// the repo surface; ADR-009 D5), omits the wire billing_id, and still returns a
// signed URL.
func TestExecuteTransaction_ZeroCostSkipsBilling(t *testing.T) {
	h, rec := newRecordingHarness(t)
	offer := pushDiscoverTermOffer(t, h, "/articles/free", seedFreeTerm())
	if got := offer.GetPricing().GetModel(); got != rampv1.PricingModel_PRICING_MODEL_FREE {
		t.Fatalf("discovered offer pricing model = %v, want FREE", got)
	}

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	item := singleResultItem(t, resp)

	// Signed URL still issued, with an expiry.
	signedURL := itemSignedURL(t, resp)
	if item.GetExpiresAt() == nil {
		t.Error("expires_at not set on the zero-cost item")
	}

	// Wire billing_id omitted — mirrors the persisted NULL (ADR-009 D5). On the
	// items[] path the per-item billing_id is a proto3 no-presence string, so the
	// free path surfaces it as empty.
	if got := item.GetBillingId(); got != "" {
		t.Errorf("wire billing_id present (%q) on the free path; want omitted", got)
	}

	// Persisted billing_id empty + signed-URL hash matches, via the repo surface.
	logged := loadFreePathTx(t, h, offer, "tx-"+t.Name())
	if logged.BillingID != "" {
		t.Errorf("persisted billing_id = %q, want empty on the free path (ADR-009 D2/D5)", logged.BillingID)
	}
	assertSignedURLHash(t, logged.SignedURLHash, signedURL)

	// The billing adapter saw nothing (ADR-009 D2).
	assertBillingLifecycle(t, rec, false, 0, 0)
}

// TestExecuteTransaction_PaidPathUnchanged is the contrast: a priced (PER_UNIT)
// offer through the same harness runs the full lifecycle — Authorize + Record
// once, no Release on success — and persists a non-empty billing_id surfaced on
// the wire item. Pins that the free-path guard left the paid path untouched.
func TestExecuteTransaction_PaidPathUnchanged(t *testing.T) {
	h, rec := newRecordingHarness(t)
	offer := pushDiscoverTermOffer(t, h, "/articles/paid", seedPricedTerm())
	if got := offer.GetPricing().GetModel(); got == rampv1.PricingModel_PRICING_MODEL_FREE {
		t.Fatalf("discovered offer pricing model = FREE, want a priced term")
	}

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute paid offer: %v", err)
	}
	item := singleResultItem(t, resp)
	signedURL := itemSignedURL(t, resp)

	if item.GetBillingId() == "" {
		t.Error("wire billing_id absent on the paid path; want the reservation handle")
	}
	// The persisted handle equals the wire handle EXACTLY (not merely both
	// non-empty — a swapped/truncated persist would pass that), and the persisted
	// signed_url_hash matches the returned URL, for parity with the free sibling's
	// write-before-sign assertion.
	logged := loadFreePathTx(t, h, offer, "tx-"+t.Name())
	if logged.BillingID != item.GetBillingId() {
		t.Errorf("persisted billing_id = %q, want == wire billing_id %q", logged.BillingID, item.GetBillingId())
	}
	assertSignedURLHash(t, logged.SignedURLHash, signedURL)

	assertBillingLifecycle(t, rec, true, 1, 0)
}

// TestExecuteTransaction_FreePathReleaseGuard pins the releaseHold
// hasNoReservation short-circuit (ADR-009 D2): a zero-cost transaction that
// fails on the persist hot path reaches releaseHold with an empty billingID,
// which must return without touching the adapter — no reservation was ever
// taken, so no Release. Asserting the specific persist failure code (Internal)
// pins that execution actually reached persist — the guard's entry path — rather
// than an earlier failure that would also leave Release uncalled.
func TestExecuteTransaction_FreePathReleaseGuard(t *testing.T) {
	runner := &failTxRunner{}
	h, rec := newRecordingHarnessWith(t, harnessOptions{txRunnerWrap: runner.wrap})
	runner.arm()
	offer := pushDiscoverTermOffer(t, h, "/articles/free", seedFreeTerm())

	_, err := executeOfferRaw(t, h, offer)
	assertConnectCode(t, err, connect.CodeInternal)

	// Authorize never ran (free) and Release short-circuited (no reservation
	// handle); if the guard were removed, releaseHold("") would call Release and
	// this would report releaseCallCount == 1.
	assertBillingLifecycle(t, rec, false, 0, 0)
}

// TestExecuteTransaction_ZeroRatePerUnitSkipsBilling proves the bypass is keyed
// off the price (unit_cost == 0), NOT the pricing model: a PER_UNIT term at rate
// 0.00 projects unit_cost 0 and takes the same free path — no billing lifecycle,
// empty billing_id — even though its model is PER_UNIT, not FREE. Guards against
// a later "make the bypass model-based" refactor silently changing money behavior.
func TestExecuteTransaction_ZeroRatePerUnitSkipsBilling(t *testing.T) {
	h, rec := newRecordingHarness(t)
	offer := pushDiscoverTermOffer(t, h, "/articles/perunit-zero", seedZeroRatePerUnitTerm())
	if got := offer.GetPricing().GetModel(); got != rampv1.PricingModel_PRICING_MODEL_PER_UNIT {
		t.Fatalf("discovered offer pricing model = %v, want PER_UNIT (proves price-based bypass)", got)
	}

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute zero-rate PER_UNIT offer: %v", err)
	}
	item := singleResultItem(t, resp)
	if got := item.GetBillingId(); got != "" {
		t.Errorf("wire billing_id present (%q) on a zero-rate PER_UNIT offer; want omitted", got)
	}
	if logged := loadFreePathTx(t, h, offer, "tx-"+t.Name()); logged.BillingID != "" {
		t.Errorf("persisted billing_id = %q, want empty on the zero-rate path", logged.BillingID)
	}
	assertBillingLifecycle(t, rec, false, 0, 0)
}

// TestExecuteTransaction_MixedFreePaidBatch pins the per-item billing decision
// inside a single batch: one PAID and one FREE item (both USD) execute in one
// request, and only the paid item runs the billing lifecycle. Authorize + Record
// fire once (paid), Release never (both succeed), and only the paid row persists
// a non-empty billing_id — the free item's row stays NULL.
func TestExecuteTransaction_MixedFreePaidBatch(t *testing.T) {
	h, rec := newRecordingHarness(t)
	paid, free := seedFreePaidUSD(t, h)
	const idem = "tx-mixed-free-paid"

	msg := execTwoItemBatch(t, h, paid, free, idem)
	if n := len(msg.GetItems()); n != 2 {
		t.Fatalf("batch returned %d items, want 2", n)
	}

	// Exactly one Record (the paid item), no Release (both succeeded).
	assertBillingLifecycle(t, rec, true, 1, 0)

	// Per-item persisted billing_id, keyed on each item's derived per-item key:
	// paid non-empty, free empty.
	if paidRow := loadFreePathTx(t, h, paid, idem); paidRow.BillingID == "" {
		t.Error("paid item persisted an empty billing_id; want the reservation handle")
	}
	if freeRow := loadFreePathTx(t, h, free, idem); freeRow.BillingID != "" {
		t.Errorf("free item persisted billing_id = %q, want empty", freeRow.BillingID)
	}
}
