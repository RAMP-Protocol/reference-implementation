//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Stateless presented-offer redemption.
//
// These tests pin the NEW execute contract decided for stateless offer redemption:
// the Exchange verifies the PRESENTED reflected Offer's signature over the exact
// presented bytes (expires_at INCLUDED) via helpers.VerifyPresentedOffer —
// no reconstruct-from-catalog — AND
//
//   - enforces the offer's signed expires_at against the service clock
//     (DENIAL_REASON_OFFER_EXPIRED);
//   - binds delivery/pricing to the catalog row the SIGNED Identity.canonical_url
//     names (offer_id is an opaque per-offer UUID and carries no resource
//     semantics — see execute_canonical_binding_integration_test.go);
//   - charges the SIGNED offer.pricing, not a recompute from the live catalog
//     (MEDIUM1 — agent pays what it signed; catalog drift is the publisher's
//     problem).
//
// Round-trip honesty: every leg drives the full transport→service→repo→DB stack
// through the public Connect-Go RPCs (CatalogService.PushResources →
// ExchangeService.DiscoverResources → ExchangeService.ExecuteTransaction).
// Side-effect ABSENCE is observed through the production read surfaces only:
// repo.TransactionRepo.ByID (the documented tier-2 fallback — no public
// transaction-read RPC exists yet) and the billing adapter's GetBalance. No raw sqlc / SQL / second DB connection
// (Testing Doctrine §9). Negative legs assert BOTH the connect.Code AND the
// absence of the delivery URL / billing debit / transaction row (§10).

// seedResourceWithRate pushes a single catalog entry under the harness tenant at
// the given path with an unrestricted PER_UNIT term priced at rate. It mirrors
// seedCatalog/seedPricedTerm but lets a test seed two distinct resources at two
// distinct prices (the A↔B binding + signed-price cases). Returns the canonical
// URI so the caller can discover it.
func seedResourceWithRate(t *testing.T, h *testHarness, path, rate string) string {
	t.Helper()
	unit := "accesses"
	if _, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, "agent-test", []*rampv1.ResourceEntry{{
		Domain: h.tenantDomain,
		Path:   path,
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
				Rate:     rate,
				Currency: "USD",
				Unit:     &unit,
			},
		}},
	}}))); err != nil {
		t.Fatalf("push %s @ %s: %v", path, rate, err)
	}
	return "https://" + h.tenantDomain + path
}

// executeSingleItem drives ExecuteTransaction with a single items[] entry: the
// presented offer + a body acceptance signed by the default agent-test caller
// key over the GENUINE presented bytes. Negative legs that tamper the offer
// after signing still produce a valid acceptance over the tampered bytes (the
// agent "accepts" what it sends), so the rejection comes from the
// offer-signature / binding guards under test, not from a missing acceptance.
func executeSingleItem(
	t *testing.T, h *testHarness, txID string, presented *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	return executeSingleItemWithRequestID(t, h, txID, presented, "")
}

// executeSingleItemWithRequestID is executeSingleItem with an X-Request-ID on the
// envelope, for the correlation tests whose subject rides on the request headers
// rather than in the body. An empty requestID sets no header at all, which is the
// distinct case of a caller that supplies none.
func executeSingleItemWithRequestID(
	t *testing.T, h *testHarness, txID string, presented *rampv1.Offer, requestID string,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	requester := newRequester("agent-test", "agent.example")
	txReq := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: txID,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: presented, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, presented, requester, txID)},
		},
	}
	txReq.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, txReq)
	req := connect.NewRequest(txReq)
	if requestID != "" {
		req.Header().Set(helpers.RequestIDHeader, requestID)
	}
	return h.exchangeClient.ExecuteTransaction(h.ctx, req)
}

// executeItems drives ExecuteTransaction for pre-built items under one shared
// request key, for tests that must control an item's acceptance (omit it, sign it
// with the wrong key, sign over a tampered offer) — the one axis executeSingleItem
// fixes by always minting a valid acceptance for the caller.
func executeItems(
	t *testing.T, h *testHarness, reqKey string, items ...*rampv1.TransactionItem,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	req := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: reqKey,
		Requester:      agentRequester("agent-test"),
		Items:          items,
	}
	req.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, req)
	return h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(req))
}

func signRequestAcceptanceFor(
	t *testing.T, priv ed25519.PrivateKey, req *rampv1.TransactionRequest,
) *rampv1.AgentRequestAcceptance {
	t.Helper()
	acceptance, err := helpers.SignRequestAcceptance(priv, req)
	if err != nil {
		t.Fatalf("SignRequestAcceptance: %v", err)
	}
	return acceptance
}

// derivedTxKey is the per-item persistence/billing key the batch path writes
// (idempotency_key+":"+offer_id). Side-effect lookups after a
// successful single-item execute MUST use this key — the bare request key never
// reaches transaction_log.idempotency_key on the items[] path.
func derivedTxKey(txID string, offer *rampv1.Offer) string {
	return txID + ":" + offer.GetOfferId()
}

// singleResultItem asserts the batch response carries exactly one item and
// returns it, for N=1 migrations that read the per-item result fields the
// top-level TransactionResponse no longer carries.
func singleResultItem(t *testing.T, resp *connect.Response[rampv1.TransactionResponse]) *rampv1.TransactionResultItem {
	t.Helper()
	items := resp.Msg.GetItems()
	if len(items) != 1 {
		t.Fatalf("response carried %d items, want 1", len(items))
	}
	return items[0]
}

// itemSignedURL pulls the signed delivery URL from a single-item batch result,
// asserting it is present (the in-body analogue of extractSignedURL for the
// items-only contract).
func itemSignedURL(t *testing.T, resp *connect.Response[rampv1.TransactionResponse]) string {
	t.Helper()
	it := singleResultItem(t, resp)
	if it.GetRetrievalEndpoint() == "" {
		t.Fatal("retrieval_endpoint missing from the single batch item")
	}
	return it.GetRetrievalEndpoint()
}

// assertItemDenied asserts a single-item batch SUCCEEDED at the request level
// (HTTP 200, nil err) but the lone item carries the expected denial_reason and
// NO retrieval_endpoint — the in-body per-item denial shape for denial-map kinds
// (SIGNATURE_INVALID / OFFER_EXPIRED / INSUFFICIENT_BALANCE) after the C4
// items-only collapse (Flag #1 resolution).
func assertItemDenied(
	t *testing.T, resp *connect.Response[rampv1.TransactionResponse], err error, want rampv1.DenialReason,
) {
	t.Helper()
	if err != nil {
		t.Fatalf("single-item denial must surface in-body (HTTP 200), got connect error: %v", err)
	}
	it := singleResultItem(t, resp)
	if got := it.GetDenialReason(); got != want {
		t.Errorf("item denial_reason = %v, want %v", got, want)
	}
	if it.GetRetrievalEndpoint() != "" {
		t.Errorf("denied item must not carry a retrieval_endpoint, got %q", it.GetRetrievalEndpoint())
	}
}

// assertNoTransaction asserts that no transaction_log row exists for idempotencyKey,
// proving a rejected Execute persisted no side effect. Read through the
// production repository surface (Testing Doctrine §9 tier-2; no public
// transaction-read RPC exists yet).
func assertNoTransaction(t *testing.T, h *testHarness, idempotencyKey string) {
	t.Helper()
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, idempotencyKey); !errors.Is(err, repo.ErrTransactionNotFound) {
		t.Fatalf("ByIdempotencyKey(%q) after rejected Execute = %v, want ErrTransactionNotFound (no side effect)", idempotencyKey, err)
	}
}

// assertBalanceUnchanged asserts the agent-test balance is still the 10.00 USD
// seed, proving a rejected Execute reserved/charged nothing.
func assertBalanceUnchanged(t *testing.T, h *testHarness) {
	t.Helper()
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want := mustBillingAmount(t, "10.00", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Fatalf("balance after rejected Execute = %s; want 10.00 (no billing side effect)", bal.Value.FloatString(4))
	}
}

// TestExecuteTransaction_PresentedOfferAccepted is the happy path for the
// presented-offer contract: a genuinely discovered, exchange-signed offer
// reflected unchanged onto TransactionRequest.offer is accepted, a signed
// delivery URL is minted, and the transaction is persisted (observable by
// idempotency_key through the production repo surface). This pins that the new
// VerifyPresentedOffer path accepts the offer the discovery path signed.
func TestExecuteTransaction_PresentedOfferAccepted(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/accept", "0.05")
	offer := discoverOffer(t, h, uri)

	const txID = "tx-presented-accept"
	resp, err := executeSingleItem(t, h, txID, offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := itemSignedURL(t, resp); got == "" {
		t.Fatal("accepted transaction returned no retrieval_endpoint")
	}
	// Persisted side effect observed through the production read surface. The
	// items[] path persists under the DERIVED key idempotency_key:offer_id, not
	// the bare request key.
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey after accepted Execute: %v", err)
	}
	if rec.TransactionID == "" {
		t.Error("persisted transaction has empty transaction_id")
	}
}

// TestExecuteTransaction_TamperedOfferPriceRejected pins the presented-bytes
// invariant: a genuinely discovered offer whose signed Pricing.Rate is mutated
// AFTER discovery (a different price than the Exchange signed) must be rejected
// — the signature no longer covers the presented bytes. Verification runs over
// the PRESENTED offer bytes (helpers.VerifyPresentedOffer), so the mutated rate
// breaks the signature and the item is denied.
func TestExecuteTransaction_TamperedOfferPriceRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/tamper", "0.05")
	offer := discoverOffer(t, h, uri)

	tampered, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	// Bump the signed rate: the agent tries to pay a price the Exchange never
	// signed. The signature was computed over rate "0.05".
	tampered.GetPricing().Rate = "0.01"

	const txID = "tx-tampered-price"
	resp, err := executeSingleItem(t, h, txID, tampered)
	// After the C4 items-only collapse, a SIGNATURE_INVALID denial (a denial-map
	// kind) surfaces in-body as the item's denial_reason on an HTTP-200 batch, not
	// as a connect error (Flag #1 resolution). Strength is preserved: rejection +
	// no transaction + no billing side effect.
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(txID, tampered))
	assertBalanceUnchanged(t, h)
}

// TestExecuteTransaction_ExpiredOfferRejected pins the expiry gate this atom
// introduces (DECISIONS MEDIUM2 — in scope, no deferral). An offer minted at
// discovery carries expires_at = now+OfferTTL (default 5m). Advancing the
// service's deterministic clock past that TTL must make the SAME genuinely
// signed offer rejected on freshness grounds. Today no expiry is enforced —
// the stale offer is accepted — so this fails RED until VerifyPresentedOffer's
// expiry check (consulting s.clk.Now()) lands. Per DECISIONS LOW1 the denial
// reason is the distinct DENIAL_REASON_OFFER_EXPIRED, NOT SIGNATURE_INVALID.
func TestExecuteTransaction_ExpiredOfferRejected(t *testing.T) {
	det := clock.NewDeterministic(time.Now().UTC())
	h := newTestHarnessWithClock(t, det)
	uri := seedResourceWithRate(t, h, "/articles/expire", "0.05")
	offer := discoverOffer(t, h, uri)

	// Default OfferTTL is 5m (ExchangeConfig.withDefaults); jump well past it so
	// the signed expires_at is strictly in the past relative to the service clock.
	det.Advance(10 * time.Minute)

	const txID = "tx-expired-offer"
	resp, err := executeSingleItem(t, h, txID, offer)
	// OFFER_EXPIRED is a denial-map kind → in-body per-item denial after the C4
	// collapse (Flag #1). LOW1: the reason stays distinct from SIGNATURE_INVALID.
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED)
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteTransaction_SignedPriceHonoredOnCatalogDrift pins the user pricing
// decision (DECISIONS MEDIUM1): billing reads the price from the VERIFIED
// presented offer, NOT a recompute from the live catalog. An offer is discovered
// at price X; the catalog term is then re-pushed at a DIFFERENT price Y; the
// ORIGINAL signed offer (price X) is executed and must be billed X. Today
// billing derives pricing from the current catalog snapshot (selectedPricing on
// the live entry), so after the drift the agent is charged Y — this fails RED
// until billing reads offer.GetPricing() from the presented offer.
//
// Observed through both public surfaces: the wire Cost on the response AND the
// billing balance debit. X = 0.05, Y = 0.50; est qty defaults to 1, so the
// signed-price charge is 0.05 (balance 9.95), while a catalog recompute would
// charge 0.50 (balance 9.50).
func TestExecuteTransaction_SignedPriceHonoredOnCatalogDrift(t *testing.T) {
	h := newTestHarness(t)
	const path = "/articles/drift"
	uri := seedResourceWithRate(t, h, path, "0.05") // price X
	offer := discoverOffer(t, h, uri)
	if got := offer.GetPricing().GetRate(); got != "0.05" {
		t.Fatalf("discovered offer rate = %q, want signed X 0.05", got)
	}

	// Publisher raises the price AFTER the agent holds a signed offer. A fresh
	// discover would now yield Y; the held offer still carries X.
	_ = seedResourceWithRate(t, h, path, "0.50") // re-push same resource at price Y

	const txID = "tx-signed-price"
	resp, err := executeSingleItem(t, h, txID, offer)
	if err != nil {
		t.Fatalf("execute signed offer after catalog drift: %v", err)
	}

	// Wire surface: the charged unit_cost must equal the SIGNED X, not Y. After
	// the C4 collapse the cost rides on the single batch item, not the top-level
	// response.
	item := singleResultItem(t, resp)
	if got := item.GetCost().GetUnitCost(); got != money(t, 0.05) {
		t.Errorf("Cost.unit_cost = %q, want signed X %q (not catalog Y 0.50)", got, money(t, 0.05))
	}
	if got := item.GetCost().GetAmount(); got != money(t, 0.05) {
		t.Errorf("Cost.amount = %q, want signed X %q (qty 1)", got, money(t, 0.05))
	}

	// Billing surface: balance debited by X (0.05) → 9.95, not by Y (0.50) → 9.50.
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	wantX := mustBillingAmount(t, "9.95", "USD")
	wantY := mustBillingAmount(t, "9.50", "USD")
	if bal.Value.Cmp(wantX.Value) != 0 {
		t.Errorf("balance after Execute = %s; want 9.95 (charged signed X 0.05). "+
			"A balance of %s would mean billing recomputed from the drifted catalog price Y.",
			bal.Value.FloatString(4), wantY.Value.FloatString(4))
	}

	// Persisted unit_cost mirrors the signed X (production repo surface, tier-2).
	// The items[] path persists under the DERIVED key.
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey: %v", err)
	}
	gotPersisted := mustBillingAmount(t, rec.UnitCostDecimal, rec.Currency)
	if gotPersisted.Value.Cmp(mustBillingAmount(t, "0.05", "USD").Value) != 0 {
		t.Errorf("persisted unit_cost = %q, want signed X 0.05", rec.UnitCostDecimal)
	}
}
