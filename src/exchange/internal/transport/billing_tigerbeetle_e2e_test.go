//go:build integration

package transport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tbtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Full-surface E2E for the TigerBeetle billing backend. Every money-moving
// scenario drives the writes through ExecuteTransaction / ReportUsage against a
// real Exchange + real TigerBeetle + real Postgres (no mocks — Testing Doctrine
// §1/§6/§9). Two facts of the landed lifecycle shape these tests:
//
//   - Record (and the settlement split) run INSIDE ExecuteTransaction (best-effort
//     after persist); ReportUsage does not touch billing. So the ledger effect
//     completes at Execute and ReportUsage is asserted to be ledger-neutral.
//   - v1 exposes no public refund/dispute RPC (deferred). The Refund and
//     refund-before-record cases are driven at the adapter surface — a documented
//     §9 exception — while the settle they act on still runs through the RPCs.
//
// The adapter is salt-namespaced (IDNamespace) per test so its accounts never
// collide with a sibling's on the append-only ledger (there is no per-test reset).

const (
	e2eTBLedger   uint32 = 840 // ISO 4217 USD — matches the harness's USD-priced offers
	e2eTBCurrency        = "USD"
	e2eAssetScale        = 8
	// e2eOwnerID is the resource_owner_id the harness manifest attests (see
	// newAllowAllManifestCache). The agent leg is keyed on the harness's
	// billing_ref, read via h.billingRef, not a fixed agent id.
	e2eOwnerID = harnessResourceOwner
	// e2eFeeBps is a non-zero commission so the split produces a real platform:fee
	// leg; at bps 0 the split collapses to a single owner credit (see the design doc).
	e2eFeeBps = 1000 // 10%
)

// newTBAdapter builds a salt-namespaced TigerBeetleAdapter over the shared
// package cluster. IDNamespace isolates this test's accounts/transfers from
// siblings on the reset-less ledger.
func newTBAdapter(salt string) *billing.TigerBeetleAdapter {
	return billing.NewTigerBeetleAdapter(billing.TigerBeetleOptions{
		Client:      tbClient,
		Ledger:      e2eTBLedger,
		Currency:    e2eTBCurrency,
		AssetScale:  e2eAssetScale,
		HoldTimeout: time.Minute,
		IDNamespace: salt,
	})
}

// newTBHarness wires a transport harness whose billing adapter is a real
// TigerBeetleAdapter (salt) and sets the tenant commission to feeBps. opts lets a
// caller drive a hot-path failure (e.g. a failing txRunner); opts.server is
// overridden with the TB adapter. Returns the harness and the adapter (the latter
// so the refund case can drive the no-public-RPC surface directly).
func newTBHarness(t *testing.T, salt string, feeBps int, opts harnessOptions) (*testHarness, *billing.TigerBeetleAdapter) {
	t.Helper()
	adapter := newTBAdapter(salt)
	opts.server = adapter
	h := newTestHarnessWith(t, opts)
	if feeBps > 0 {
		if _, err := h.queries.SetTenantFeeRateBps(h.ctx, sqlc.SetTenantFeeRateBpsParams{
			TenantID:   h.tenantID,
			FeeRateBps: int32(feeBps),
		}); err != nil {
			t.Fatalf("set tenant fee: %v", err)
		}
	}
	return h, adapter
}

// tbLedger is the transport package's shared TigerBeetle test handle, bound to
// the E2E ledger + asset scale. Funding and balance reads route through it (the
// shape lives in tbtest, shared with the billing suite).
func tbLedger() tbtest.Ledger {
	return tbtest.Ledger{Client: tbClient, ID: e2eTBLedger, Scale: e2eAssetScale}
}

// fundTBAgent seeds a real prepaid balance for the salted agent — the operator's
// out-of-band manual credit (ADR-009 D2), the only way to seed a ledger balance
// (there is no Fund method on the adapter).
func fundTBAgent(t *testing.T, salt, agentID, dollars string) {
	t.Helper()
	tbLedger().MustFundAgent(t, salt, agentID, dollars)
}

// tbPosted reads a salted account's settled balance (credits_posted −
// debits_posted, minor units) directly from the ledger — an accepted
// Testing-Doctrine §9 black-box e2e read (the eventual public home is the future
// RevenueReport surface; no protocol read surface is added here). Missing reads 0.
func tbPosted(t *testing.T, prefix tigerbeetle.Prefix, salt, businessID string) int64 {
	t.Helper()
	return tbLedger().PostedBalance(t, tbtest.MustAccountID(t, prefix, salt+businessID))
}

// assertSplitBalances asserts the agent / owner:revenue / platform:fee settled
// balances (decimal dollars) for the salted namespace. The agent leg is keyed on
// the harness's billing_ref (the charge lands on the ref-keyed account,
// not the agent id), read through h — a method receiver keeps the argument list
// within the per-function cap. The owner and platform legs go through the shared
// §9-exception read on tbtest.Ledger (AssertOwnerPlatformSplit) — the same assertion
// the billing split suite uses, keyed by the exported tigerbeetle account-name
// constants production uses. The agent leg stays a §9 ledger read here: switching it
// to the tier-1 adapter.GetBalance surface (as the billing suite does) would force
// every caller to retain the adapter handle; the billing suite already exercises that path.
func (h *testHarness) assertSplitBalances(t *testing.T, salt, agent, owner, fee string) {
	t.Helper()
	led := tbLedger()
	assertPosted(t, tigerbeetle.PrefixAgent, salt, h.billingRef, agent)
	led.AssertOwnerPlatformSplit(t, salt, e2eOwnerID, led.Minor(t, owner), led.Minor(t, fee))
}

func assertPosted(t *testing.T, prefix tigerbeetle.Prefix, salt, businessID, wantDollars string) {
	t.Helper()
	got := tbPosted(t, prefix, salt, businessID)
	want := tbLedger().Minor(t, wantDollars)
	if got != want {
		t.Errorf("%s%s posted = %d, want %d (%s)", prefix, businessID, got, want, wantDollars)
	}
}

// TestTigerBeetleE2E_SettlementSplit drives ExecuteTransaction at a non-zero
// commission and asserts the two-posting split on the real ledger, then confirms
// ReportUsage completes the protocol round-trip without moving the ledger.
func TestTigerBeetleE2E_SettlementSplit(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, e2eFeeBps, harnessOptions{})
	fundTBAgent(t, salt, h.billingRef, "10.00")

	txID, billingID := executeTransactionFor(t, h, 20) // gross = 0.05 × 20 = 1.00

	// Split completes at ExecuteTransaction: agent −1.00, owner +0.90, platform +0.10.
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")
	owner := tbPosted(t, tigerbeetle.PrefixOwner, salt, tigerbeetle.OwnerRevenuePrefix+e2eOwnerID)
	fee := tbPosted(t, tigerbeetle.PrefixPlatform, salt, tigerbeetle.PlatformFeeID)
	if got, want := owner+fee, tbLedger().Minor(t, "1.00"); got != want {
		t.Errorf("net+fee = %d, want gross %d", got, want)
	}

	// ReportUsage completes the round-trip but must be ledger-neutral.
	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-1", TransactionId: txID, BillingId: billingID,
		Usage: &rampv1.Usage{ConsumedQuantity: 20},
	})); err != nil {
		t.Fatalf("report usage: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")
}

// TestTigerBeetleE2E_HoldRelease forces a persist failure after Authorize so the
// service releases the hold; the agent balance must be fully restored with no net
// postings.
func TestTigerBeetleE2E_HoldRelease(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, e2eFeeBps, harnessOptions{txRunner: failTxRunner{}})
	fundTBAgent(t, salt, h.billingRef, "10.00")

	offer := pushDiscoverOffer(t, h, 20)
	if _, err := executeOfferRaw(t, h, offer); err == nil {
		t.Fatal("expected persist-failure error, got nil")
	}
	h.assertSplitBalances(t, salt, "10.00", "0.00", "0.00")
	// The settled balances above read the same whether or not the hold was voided
	// (they exclude debits_pending), so assert the hold is actually gone: an
	// unreleased hold would pin the 1.00 gross in the agent's debits_pending until
	// the ~6-min timeout, invisible to the settled-balance check.
	if p := tbLedger().PendingBalance(t, tbtest.MustAccountID(t, tigerbeetle.PrefixAgent, salt+h.billingRef)); p != 0 {
		t.Errorf("agent debits_pending = %d, want 0 (hold not voided on persist failure)", p)
	}
}

// TestTigerBeetleE2E_PerOwnerFeeOverride drives a per-(tenant, resource_owner)
// commission override through ExecuteTransaction and asserts the on-ledger split
// reflects the override rate, not the tenant default. The override (25%) is seeded
// distinct from the tenant default (10%), so a settlement that ignored the override
// would post the wrong split (0.90 / 0.10) and fail here. ADR-010 amendment B: the
// effective rate is resolved at Authorize and frozen on the hold.
func TestTigerBeetleE2E_PerOwnerFeeOverride(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, e2eFeeBps, harnessOptions{}) // tenant default 10%
	if err := repo.NewFeeOverrideRepo(h.queries).Set(h.ctx, h.tenantID, e2eOwnerID, 2500); err != nil {
		t.Fatalf("seed fee override: %v", err)
	}
	fundTBAgent(t, salt, h.billingRef, "10.00")

	executeTransactionFor(t, h, 20) // gross = 0.05 × 20 = 1.00

	// Override 25%: agent −1.00, owner +0.75, platform +0.25 (the tenant default
	// would settle 0.90 / 0.10).
	h.assertSplitBalances(t, salt, "9.00", "0.75", "0.25")
}

// TestTigerBeetleE2E_RateFrozenAtAuthorize proves ADR-010 amendment B's freeze: the
// commission is resolved at Authorize and carried on the hold, so mutating the
// (tenant, resource_owner) override AFTER Authorize but BEFORE Record must NOT change
// the settled split. A recordingAdapter's beforeRecord hook jams the override to 50%
// between the two calls; the on-ledger split must still reflect the Authorize-time 10%.
// A service that re-resolved the rate at Record would post 0.50 / 0.50 and fail here.
func TestTigerBeetleE2E_RateFrozenAtAuthorize(t *testing.T) {
	salt := sharedTB.Salt(t)
	rec := newRecordingAdapter(newTBAdapter(salt))
	h := newTestHarnessWith(t, harnessOptions{server: rec})
	if _, err := h.queries.SetTenantFeeRateBps(h.ctx, sqlc.SetTenantFeeRateBpsParams{
		TenantID: h.tenantID, FeeRateBps: e2eFeeBps, // tenant default 10%
	}); err != nil {
		t.Fatalf("set tenant fee: %v", err)
	}
	fundTBAgent(t, salt, h.billingRef, "10.00")
	// Jam the override to 50% between Authorize and Record; the frozen 10% must win.
	rec.mu.Lock()
	rec.beforeRecord = func() {
		if err := repo.NewFeeOverrideRepo(h.queries).Set(h.ctx, h.tenantID, e2eOwnerID, 5000); err != nil {
			t.Errorf("mutate override in beforeRecord: %v", err)
		}
	}
	rec.mu.Unlock()

	executeTransactionFor(t, h, 20) // gross = 0.05 × 20 = 1.00 at the Authorize-time 10%

	// Frozen 10%: agent −1.00, owner +0.90, platform +0.10.
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")
}

// TestTigerBeetleE2E_Refund settles a charge through the RPCs, then reverses it at
// the adapter surface (no public refund RPC in v1). ADR-010 D4 worked example:
// $1.00 @ 10%, refund $0.30 → agent 9.30, owner 0.63, platform 0.07.
func TestTigerBeetleE2E_Refund(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, adapter := newTBHarness(t, salt, e2eFeeBps, harnessOptions{})
	fundTBAgent(t, salt, h.billingRef, "10.00")

	_, billingID := executeTransactionFor(t, h, 20)
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")

	if err := adapter.Refund(h.ctx, billingID, mustBillingAmount(t, "0.30", "USD"), "dispute", "kr-1"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	h.assertSplitBalances(t, salt, "9.30", "0.63", "0.07")

	// The refund's net leg carries a token of the reason on user_data_64 — a
	// verifiable, PII-free audit trace (parity with the in-memory RefundLog). The
	// leg id is reconstructed exactly as the adapter derives it; reading it back is
	// the sanctioned §9 black-box ledger read.
	netLegID := tbtest.MustTransferID(t, salt+"refund:"+billingID+":kr-1:net")
	if got, want := tbLedger().TransferUserData64(t, netLegID), tigerbeetle.ReasonToken("dispute"); got != want {
		t.Errorf("refund net leg user_data_64 = %d, want %d (reason token)", got, want)
	}
}

// TestTigerBeetleE2E_Idempotency retries the same idempotency_key and asserts
// exactly one set of postings (no double charge).
func TestTigerBeetleE2E_Idempotency(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, e2eFeeBps, harnessOptions{})
	fundTBAgent(t, salt, h.billingRef, "10.00")

	offer := pushDiscoverOffer(t, h, 20)
	first, err := executeOfferRawWithID(t, h, offer, "tx-idem")
	if err != nil {
		t.Fatalf("execute #1: %v", err)
	}
	firstItem := singleResultItem(t, first)
	// A duplicate idempotency_key is served by the durable replay path: the
	// stored original result comes back verbatim (ramp.proto idempotency
	// conformance — replay is a success, not an error) and billing is never
	// re-touched, so the ledger keeps exactly one set of postings — no double
	// charge. (The adapter's own ledger-native idempotency is separately
	// covered by the billing conformance suite.)
	replay, err := executeOfferRawWithID(t, h, offer, "tx-idem")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	replayItem := singleResultItem(t, replay)
	if replayItem.GetTransactionId() != firstItem.GetTransactionId() {
		t.Errorf("replay transaction_id = %q, want original %q",
			replayItem.GetTransactionId(), firstItem.GetTransactionId())
	}
	if replayItem.GetBillingId() != firstItem.GetBillingId() {
		t.Errorf("replay billing_id = %q, want original %q",
			replayItem.GetBillingId(), firstItem.GetBillingId())
	}
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")
}

// TestTigerBeetleE2E_InsufficientBalance drives ExecuteTransaction for an agent
// funded below the charge: the item is denied in-body (HTTP 200,
// denial_reason=INSUFFICIENT_BALANCE, no retrieval_endpoint — the per-item
// batch denial shape) and the ledger does not move.
func TestTigerBeetleE2E_InsufficientBalance(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, e2eFeeBps, harnessOptions{})
	fundTBAgent(t, salt, h.billingRef, "0.50") // < gross 1.00

	offer := pushDiscoverOffer(t, h, 20)
	resp, err := executeOfferRaw(t, h, offer)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
	h.assertSplitBalances(t, salt, "0.50", "0.00", "0.00")
}

// TestTigerBeetleE2E_RefundBeforeRecord drives a hold-only Authorize and then a
// Refund at the adapter surface (no public refund RPC): the adapter rejects with
// ErrRefundBeforeRecord and no split postings land.
func TestTigerBeetleE2E_RefundBeforeRecord(t *testing.T) {
	salt := sharedTB.Salt(t)
	adapter := newTBAdapter(salt)
	// Adapter-direct test (no harness, no Register): the funded account and the
	// Authorize account key just have to agree, so both use the same ref.
	const ref = defaultCallerBillingRef
	fundTBAgent(t, salt, ref, "10.00")
	ctx := context.Background()

	res, err := adapter.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: ref, UnitCost: mustBillingAmount(t, "1.00", "USD"), Quantity: 1,
		IdempotencyKey: "rbr", ResourceOwnerID: e2eOwnerID, FeeRateBps: e2eFeeBps,
	})
	if err != nil || !res.Approved {
		t.Fatalf("authorize = (%+v, %v), want approved", res, err)
	}
	err = adapter.Refund(ctx, res.BillingID, mustBillingAmount(t, "0.50", "USD"), "x", "rbr-refund")
	if !errors.Is(err, billing.ErrRefundBeforeRecord) {
		t.Fatalf("refund-before-record err = %v, want ErrRefundBeforeRecord", err)
	}
	tbLedger().AssertOwnerPlatformSplit(t, salt, e2eOwnerID, 0, 0)
}
