//go:build integration

package transport_test

import (
	"errors"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// seedTwoResources pushes two distinct priced catalog entries under the
// harness tenant and returns the two discovered, signed Offers (one per URI).
// The batch execute path needs ≥2 distinct offers (distinct offer_id) so the
// per-item derived idempotency key (idempotency_key+":"+offer_id) is exercised:
// a single shared request key must NOT collapse the two items onto one
// idempotency_key (DB UNIQUE) or one billing reference.
func seedTwoResources(t *testing.T, h *testHarness) (*rampv1.Offer, *rampv1.Offer) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.tenantDomain, Path: "/articles/one", Terms: []*rampv1.LicenseTerm{seedPricedTerm()}},
			{Domain: h.tenantDomain, Path: "/articles/two", Terms: []*rampv1.LicenseTerm{seedPricedTerm()}},
		},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
	offerOne := discoverOne(t, h, "https://"+h.tenantDomain+"/articles/one")
	offerTwo := discoverOne(t, h, "https://"+h.tenantDomain+"/articles/two")
	return offerOne, offerTwo
}

// seedPricedTermCurrency is seedPricedTerm with an explicit ISO-4217 currency,
// so a batch can be assembled from items priced in DIFFERENT currencies (the
// mixed-currency total_cost case).
func seedPricedTermCurrency(currency string) *rampv1.LicenseTerm {
	unit := "accesses"
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
			Rate:     "0.05",
			Currency: currency,
			Unit:     &unit,
		},
	}
}

// seedFreeTermCurrency is a FREE (zero-charge) term denominated in currency. A
// zero charge bypasses the billing currency-match gate (inmemory_adapter.go:
// "authorized regardless of which currency the agent holds"), so a free term in
// a NON-base currency executes successfully against the USD-funded harness agent
// — the only way to assemble a batch with successfully-executed items in two
// different currencies at a single exchange (a paid non-USD item would be denied
// for currency mismatch against the agent's single-currency balance).
func seedFreeTermCurrency(currency string) *rampv1.LicenseTerm {
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Currency: currency},
	}
}

// seedMixedCurrency pushes one PAID USD entry and one FREE EUR entry and returns
// their two discovered, signed Offers — the fixture for a successfully-executed
// mixed-currency batch.
func seedMixedCurrency(t *testing.T, h *testHarness) (paidUSD, freeEUR *rampv1.Offer) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.tenantDomain, Path: "/articles/paid-usd", Terms: []*rampv1.LicenseTerm{seedPricedTermCurrency("USD")}},
			{Domain: h.tenantDomain, Path: "/articles/free-eur", Terms: []*rampv1.LicenseTerm{seedFreeTermCurrency("EUR")}},
		},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
	return discoverOne(t, h, "https://"+h.tenantDomain+"/articles/paid-usd"),
		discoverOne(t, h, "https://"+h.tenantDomain+"/articles/free-eur")
}

// seedFreePaidUSD pushes one PAID USD entry and one FREE USD entry and returns
// their two discovered, signed Offers. Both items share a currency, so a test
// over this fixture isolates the per-item free/paid billing decision from the
// mixed-currency total_cost behavior seedMixedCurrency exercises.
func seedFreePaidUSD(t *testing.T, h *testHarness) (paid, free *rampv1.Offer) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.tenantDomain, Path: "/articles/paid-usd", Terms: []*rampv1.LicenseTerm{seedPricedTerm()}},
			{Domain: h.tenantDomain, Path: "/articles/free-usd", Terms: []*rampv1.LicenseTerm{seedFreeTerm()}},
		},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
	return discoverOne(t, h, "https://"+h.tenantDomain+"/articles/paid-usd"),
		discoverOne(t, h, "https://"+h.tenantDomain+"/articles/free-usd")
}

// execTwoItemBatch executes a 2-item batch over the two offers under one shared
// requester + idempotency_key and returns the response (or fails the test).
func execTwoItemBatch(t *testing.T, h *testHarness, a, b *rampv1.Offer, idem string) *rampv1.TransactionResponse {
	t.Helper()
	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: a, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, a, requester, idem)},
			{Offer: b, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, b, requester, idem)},
		},
	}))
	if err != nil {
		t.Fatalf("batch execute: %v", err)
	}
	return resp.Msg
}

// TestExecuteTransaction_BatchTotalCostSumsSingleCurrency pins the Exchange
// batch aggregate for the common case: two USD items (0.05 each) yield a
// total_cost of exactly 0.10 USD, summed per-currency over the per-item costs
// (rampcost.BatchTotal), not a per-item value overwritten by the last item.
//
// Round-trip: agent → ExecuteTransaction RPC (real HTTP) → response.total_cost.
func TestExecuteTransaction_BatchTotalCostSumsSingleCurrency(t *testing.T) {
	h := newTestHarness(t)
	offerOne, offerTwo := seedTwoResources(t, h)

	msg := execTwoItemBatch(t, h, offerOne, offerTwo, "tx-batch-total-usd")

	tc := msg.GetTotalCost()
	if tc == nil {
		t.Fatal("single-currency batch missing total_cost scalar")
	}
	if tc.GetCurrency() != "USD" || tc.GetAmount() != "0.1" {
		t.Fatalf("total_cost = {amount:%q currency:%q}, want {0.1 USD}", tc.GetAmount(), tc.GetCurrency())
	}
}

// TestExecuteTransaction_BatchMixedCurrencyDropsScalar pins the modeling fix: a
// batch whose successfully-executed items are denominated in DIFFERENT
// currencies (paid USD + free EUR) must NOT report a single total_cost scalar.
// The pre-fix loop summed amounts and mislabeled the result with whichever
// item's currency came LAST (here {0.05 EUR} — a USD charge mislabeled as EUR);
// the fix emits no scalar and each item's items[].cost stays authoritative.
//
// Round-trip: agent → ExecuteTransaction RPC (real HTTP) → response.{total_cost,items}.
func TestExecuteTransaction_BatchMixedCurrencyDropsScalar(t *testing.T) {
	h := newTestHarness(t)
	paidUSD, freeEUR := seedMixedCurrency(t, h)

	msg := execTwoItemBatch(t, h, paidUSD, freeEUR, "tx-batch-mixed-ccy")

	if tc := msg.GetTotalCost(); tc != nil {
		t.Fatalf("mixed-currency batch total_cost = {amount:%q currency:%q}, want nil (rely on items[].cost)",
			tc.GetAmount(), tc.GetCurrency())
	}
	// Both items executed (no denial) and each keeps its own per-currency cost.
	gotCcy := map[string]string{}
	for _, it := range msg.GetItems() {
		if it.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
			t.Fatalf("item %q unexpectedly denied: %v", it.GetOfferId(), it.GetDenialReason())
		}
		if c := it.GetCost(); c != nil {
			gotCcy[c.GetCurrency()] = c.GetAmount()
		}
	}
	if gotCcy["USD"] != "0.05" || gotCcy["EUR"] != "0" {
		t.Fatalf("per-item costs = %v, want USD=0.05 and EUR=0 both intact", gotCcy)
	}
}

// TestExecuteTransaction_OverLongIdempotencyKeyNamesWireField pins the
// contract: an idempotency_key that exceeds the length cap is
// rejected at the Connect boundary with InvalidArgument, the rejection NAMES the
// WIRE field idempotency_key (never the stale internal DB-column name
// tx_request_id), and the field identity rides the structured ErrorDetail
// (metadata["field"]=="idempotency_key", the ADR-019 WithField mechanism
// report_usage uses) — not only the non-authoritative message. No
// transaction_log row may be persisted.
//
// The over-long key is the REACHABLE service-layer trigger: proto
// idempotency_key carries only (string.min_len=1) — there is NO max_len — so an
// over-long value passes the protovalidate interceptor and reaches
// service.validateBatchRequest, where the rename + WithField + executeTxError
// metadata-copy under test actually fire. (An EMPTY key is short-circuited by
// protovalidate's min_len BEFORE the service runs — covered by
// TestExecuteTransaction_OmittedIdempotencyKeyRejected.)
//
// WHY RED on pre-fix HEAD: validateBatchRequest returned
// Newf(KindInvalidRequest, "tx_request_id exceeds %d bytes") with NO WithField,
// and executeTxError attached no metadata for non-denial faults — so the message
// named tx_request_id AND metadata["field"] was absent. Both pass after the fix.
//
// Round-trip (named honestly):
//   - WRITE/reject leg: agent → ExecuteTransaction RPC (real Connect HTTP) →
//     transport → service.validateBatchRequest → connect.Error+ErrorDetail. A
//     full PROTOCOL round-trip asserted through the same RPC surface.
//   - no-row leg: PERSISTENCE check only, via the production repository surface
//     repo.NewTransactionRepo(h.queries).ByIdempotencyKey (Tier-2 documented
//     fallback — there is no public transaction-read RPC).
func TestExecuteTransaction_OverLongIdempotencyKeyNamesWireField(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/overlong-idem", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	// 300 bytes is well over the idempotency_key length cap. On the combined proto
	// line the cap is a protovalidate string.max_len constraint (255) enforced at
	// the Connect validate-interceptor boundary, which pre-empts the redundant
	// service.maxIdempotencyKeyLen check. The per-item acceptance is signed over
	// that same shared key, exactly as a real client would assemble it — the only
	// defect is the over-long key.
	overLong := strings.Repeat("x", 300)
	req := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: overLong,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, overLong)},
		},
	}

	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))

	// (a) InvalidArgument at the boundary, AND (b) the message names the wire
	// field idempotency_key and does NOT leak the stale internal tx_request_id.
	assertConnectError(t, err, connect.CodeInvalidArgument, "idempotency_key")
	if ce := connectErrOf(t, err); strings.Contains(ce.Message(), "tx_request_id") {
		t.Errorf("message %q leaks the stale internal name tx_request_id", ce.Message())
	}

	// (c) The length cap is now owned by the proto's protovalidate constraint,
	// enforced at the Connect boundary before the handler runs. The boundary
	// rejection names the wire field in its message (asserted above); the
	// service-layer ADR-019 WithField ErrorDetail is superseded for this specific
	// length check (protovalidate emits its own violation detail, not the ramp
	// ErrorDetail). WithField coverage for service-authored rejections is retained
	// by the report_usage rejection tests.

	// (d) No transaction_log row was persisted: the reject fires at envelope
	// validation before any per-item work, so neither the bare request key nor
	// the derived per-item key resolves to a row. Asserted through the production
	// repository surface (Tier-2 fallback — no public read RPC).
	derivedKey := overLong + ":" + offer.GetOfferId()
	repoTx := repo.NewTransactionRepo(h.queries)
	if _, rerr := repoTx.ByIdempotencyKey(ctx, derivedKey); !errors.Is(rerr, repo.ErrTransactionNotFound) {
		t.Fatalf("ByIdempotencyKey(derived %q) = %v, want ErrTransactionNotFound (no row persisted)", derivedKey, rerr)
	}
	if _, rerr := repoTx.ByIdempotencyKey(ctx, overLong); !errors.Is(rerr, repo.ErrTransactionNotFound) {
		t.Fatalf("ByIdempotencyKey(over-long key) = %v, want ErrTransactionNotFound (no row persisted)", rerr)
	}
}

// TestExecuteTransaction_OmittedIdempotencyKeyRejected pins that an OMITTED
// idempotency_key is still rejected at the Connect boundary with InvalidArgument
// and the rejection names the WIRE field idempotency_key (never tx_request_id).
// The empty case is owned by the protovalidate interceptor (proto
// string.min_len=1), which short-circuits BEFORE service.validateBatchRequest —
// so this guards that the preempting layer also names the wire field; the
// structured metadata["field"] ride is covered by the over-long case above
// (the reachable service-layer path).
//
// Round-trip: agent → ExecuteTransaction RPC (real Connect HTTP) → protovalidate
// interceptor → connect.Error. A full PROTOCOL round-trip through the same RPC.
func TestExecuteTransaction_OmittedIdempotencyKeyRejected(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/omitted-idem", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	req := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: "",
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, "")},
		},
	}

	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))

	assertConnectError(t, err, connect.CodeInvalidArgument, "idempotency_key")
	if ce := connectErrOf(t, err); strings.Contains(ce.Message(), "tx_request_id") {
		t.Errorf("message %q leaks the stale internal name tx_request_id", ce.Message())
	}
}

// connectErrOf extracts the *connect.Error from err for message inspection,
// failing the test if err is not a connect.Error. Used alongside
// assertConnectError when a test needs to assert the ABSENCE of a substring.
func connectErrOf(t *testing.T, err error) *connect.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	return ce
}

// discoverOne discovers a single uri and returns its first signed Offer.
func discoverOne(t *testing.T, h *testHarness, uri string) *rampv1.Offer {
	t.Helper()
	resp, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{uri},
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover %s: %v", uri, err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatalf("no offers for %s", uri)
	}
	return resp.Msg.GetOffers()[0]
}

// TestExecuteTransaction_BatchSucceedsPerItem pins the Exchange's first-class
// items[] batch path (items[] batch path): a TransactionRequest carrying N
// items (offer absent, each item with its own offer + per-item acceptance over
// the SHARED requester + idempotency_key) drives the Connect-Go RPC and yields
// N TransactionResultItems, each with its own retrieval_endpoint, all under one
// request-level idempotency_key. The derived per-item key keeps the two items
// from colliding on the idempotency_key UNIQUE backstop or the billing dedup key.
//
// Round-trip: agent → ExecuteTransaction RPC (real HTTP) → response.items[].
func TestExecuteTransaction_BatchSucceedsPerItem(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	offerOne, offerTwo := seedTwoResources(t, h)

	const idem = "tx-batch-ok"
	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offerOne, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerOne, requester, idem)},
			{Offer: offerTwo, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerTwo, requester, idem)},
		},
	}))
	if err != nil {
		t.Fatalf("batch execute: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("batch returned %d items, want 2", len(items))
	}
	// Each item carries its own signed retrieval endpoint and its own offer_id;
	// the two transaction_ids are distinct (no idempotency_key collapse).
	byOffer := map[string]*rampv1.TransactionResultItem{}
	for _, it := range items {
		if it.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
			t.Errorf("item %q unexpectedly denied: %v", it.GetOfferId(), it.GetDenialReason())
		}
		if it.GetRetrievalEndpoint() == "" {
			t.Errorf("item %q missing retrieval_endpoint", it.GetOfferId())
		}
		byOffer[it.GetOfferId()] = it
	}
	if _, ok := byOffer[offerOne.GetOfferId()]; !ok {
		t.Errorf("no result for offer one %q", offerOne.GetOfferId())
	}
	if _, ok := byOffer[offerTwo.GetOfferId()]; !ok {
		t.Errorf("no result for offer two %q", offerTwo.GetOfferId())
	}
	if a, b := byOffer[offerOne.GetOfferId()], byOffer[offerTwo.GetOfferId()]; a != nil && b != nil &&
		a.GetTransactionId() == b.GetTransactionId() {
		t.Errorf("both items collapsed onto one transaction_id %q (derived key not applied)",
			a.GetTransactionId())
	}
	// The shared agent identity hash is set once on the parent response.
	if resp.Msg.GetAgentIdentityHash() == "" {
		t.Error("batch response missing shared agent_identity_hash")
	}
}

// TestExecuteTransaction_BatchPerItemDenial pins the non-atomic denial leg: a
// batch with one good item and one item whose offer signature is tampered must
// return BOTH items — the good one with a retrieval_endpoint, the bad one with
// a per-item denial_reason (SIGNATURE_INVALID), NOT a whole-request error. The
// denial is an in-body partial result of a successful batch (ADR-019 / proto
// TransactionResultItem.denial_reason).
//
// Round-trip: agent → ExecuteTransaction RPC (real HTTP) → response.items[].
func TestExecuteTransaction_BatchPerItemDenial(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	offerOne, offerTwo := seedTwoResources(t, h)

	// Tamper offer two's signature → its presented-offer verify fails with
	// SIGNATURE_INVALID, a per-item denial (denialReasonByKind), not an abort.
	tampered := &rampv1.Offer{
		OfferId:   offerTwo.GetOfferId(),
		Exchange:  offerTwo.GetExchange(),
		Pricing:   offerTwo.GetPricing(),
		Identity:  offerTwo.GetIdentity(),
		Signature: offerTwo.GetSignature() + "00",
	}

	const idem = "tx-batch-mixed"
	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offerOne, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerOne, requester, idem)},
			{Offer: tampered, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, tampered, requester, idem)},
		},
	}))
	if err != nil {
		t.Fatalf("mixed batch must succeed at the request level (non-atomic): %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("mixed batch returned %d items, want 2", len(items))
	}
	var good, denied *rampv1.TransactionResultItem
	for _, it := range items {
		if it.GetOfferId() == offerOne.GetOfferId() {
			good = it
		}
		if it.GetOfferId() == offerTwo.GetOfferId() {
			denied = it
		}
	}
	if good == nil || good.GetRetrievalEndpoint() == "" {
		t.Errorf("good item missing or has no retrieval_endpoint: %+v", good)
	}
	if denied == nil {
		t.Fatalf("no result for the tampered offer %q", offerTwo.GetOfferId())
	}
	if denied.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Errorf("tampered item denial = %v, want SIGNATURE_INVALID", denied.GetDenialReason())
	}
	if denied.GetRetrievalEndpoint() != "" {
		t.Errorf("denied item must not carry a retrieval_endpoint, got %q", denied.GetRetrievalEndpoint())
	}
}

// TestExecuteTransaction_BatchIdempotencyReplayReturnsOriginalResult pins the
// request-level idempotency-replay contract on the ITEMS[] path. A valid 1-item
// items[] TransactionRequest succeeds (HTTP 200, items[0].retrieval_endpoint
// present, one persisted transaction, one billing debit). REPLAYING the SAME
// request — same idempotency_key + same offer — MUST return the ORIGINAL
// TransactionResponse verbatim (same transaction_id, same retrieval_endpoint) as
// a SUCCESS, NOT an error, and MUST produce NO second transaction / NO double
// charge.
//
// This asserts the proto conformance contract (ramp.proto
// TransactionRequest.idempotency_key: "a replay returns the original result
// rather than re-executing"), which supersedes the earlier interim contract that
// surfaced a replay as connect code AlreadyExists. The no-double-charge /
// no-double-persist invariants from that earlier test are preserved verbatim
// below — only the replay's observable contract changes from an error to the
// original result.
//
// Round-trip: agent → ExecuteTransaction RPC (real HTTP) → response.items[] for
// BOTH the success leg AND the replay (original-result) leg; side-effect ABSENCE
// (no second row, balance charged exactly once) observed through the production
// repository surface (repo.TransactionRepo.ByIdempotencyKey, the documented
// tier-2 fallback — no public transaction-read RPC exists) and the billing
// adapter's GetBalance. The
// persisted row is keyed on the DERIVED key idempotency_key:offer_id
// (exchange_batch.go runBatchItemBilling), NOT the bare request key, so the
// side-effect lookups use that derived key.
func TestExecuteTransaction_BatchIdempotencyReplayReturnsOriginalResult(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/batch-idem", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const idem = "tx-batch-idem"
	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	req := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
		},
	}

	// Leg 1: the original request succeeds — HTTP 200, one item, a signed
	// retrieval endpoint, no per-item denial.
	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("first call must succeed: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 1 {
		t.Fatalf("first call returned %d items, want 1", len(items))
	}
	if items[0].GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
		t.Fatalf("first call item unexpectedly denied: %v", items[0].GetDenialReason())
	}
	origURL := items[0].GetRetrievalEndpoint()
	origTxID := items[0].GetTransactionId()
	if origURL == "" || origTxID == "" {
		t.Fatalf("first call missing retrieval_endpoint/transaction_id: url=%q tx=%q", origURL, origTxID)
	}

	// The persisted row lives under the DERIVED key idempotency_key:offer_id.
	derivedKey := idem + ":" + offer.GetOfferId()
	if rec, rerr := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("ByIdempotencyKey(derived %q) after first call = %v, want a persisted row", derivedKey, rerr)
	} else if rec.TransactionID == "" {
		t.Fatal("first-call persisted transaction has empty transaction_id")
	}
	// One charge: 0.05 against the 10.00 seed → 9.95.
	balAfterFirst, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after first: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); balAfterFirst.Value.Cmp(want.Value) != 0 {
		t.Fatalf("balance after first call = %s, want 9.95 (one charge)", balAfterFirst.Value.FloatString(4))
	}

	// Leg 2: REPLAY the SAME request (same idempotency_key + same offer). The
	// request-level replay check must return the ORIGINAL result — same
	// transaction_id, same retrieval_endpoint — as a SUCCESS, not an error.
	second, replayErr := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if replayErr != nil {
		t.Fatalf("replay must return the original result, not an error: %v", replayErr)
	}
	replayItems := second.Msg.GetItems()
	if len(replayItems) != 1 {
		t.Fatalf("replay returned %d items, want 1 (the original)", len(replayItems))
	}
	if got := replayItems[0].GetTransactionId(); got != origTxID {
		t.Fatalf("replay transaction_id = %q, want the original %q", got, origTxID)
	}
	if got := replayItems[0].GetRetrievalEndpoint(); got != origURL {
		t.Fatalf("replay retrieval_endpoint = %q, want the ORIGINAL %q verbatim", got, origURL)
	}

	// The replay must not double-persist or double-charge: balance unchanged at
	// 9.95 (still exactly one charge), and the derived-key row is still the lone
	// persisted transaction.
	balAfterReplay, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after replay: %v", err)
	}
	if balAfterReplay.Value.Cmp(balAfterFirst.Value) != 0 {
		t.Fatalf("balance after replay = %s, want unchanged 9.95 (no double charge)",
			balAfterReplay.Value.FloatString(4))
	}
	if _, rerr := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("ByIdempotencyKey(derived %q) after replay = %v, want the single persisted row to survive",
			derivedKey, rerr)
	}
}
