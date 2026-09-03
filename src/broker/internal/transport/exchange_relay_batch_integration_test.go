//go:build integration

package transport_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// batchItem names one entry the broker batch body carries: an offer_id and the
// exchange domain it routes to. The test builder turns these into a
// TransactionItem with a real per-item acceptance over the SHARED requester +
// idempotency_key (Core Invariant: the broker forwards what the agent signed
// byte-identical).
type batchItem struct {
	offerID  string
	exchange string
}

// batchRequestFor builds a batch TransactionRequest (offer absent, items[] set)
// spanning the given items. Every item's AgentAcceptance is signed with the
// agent key over the SHARED requester + idempotency_key (helpers.
// SignOfferAcceptance), so the per-exchange sub-requests the broker fans out
// carry acceptances that still verify at each Exchange. idem is the request-
// level idempotency_key, shared across all items.
//
// It stops short of the request-level complete-set proof so a test that needs
// one can sign over the finished set; batchBodyFor is the shape without it.
func (e relayTestEnv) batchRequestFor(
	t *testing.T, idem string, items []batchItem,
) *rampv1.TransactionRequest {
	t.Helper()
	requester := &rampv1.Requester{
		Id:     e.agentKID,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	txItems := make([]*rampv1.TransactionItem, 0, len(items))
	for _, bi := range items {
		offer := &rampv1.Offer{
			OfferId:   bi.offerID,
			Exchange:  bi.exchange,
			Signature: "sig-" + bi.offerID,
		}
		sig, err := helpers.SignOfferAcceptance(e.agentPriv, offer, requester, idem)
		if err != nil {
			t.Fatalf("SignOfferAcceptance(%s): %v", bi.offerID, err)
		}
		txItems = append(txItems, &rampv1.TransactionItem{
			Offer: offer,
			AgentAcceptance: &rampv1.AgentAcceptance{
				Signature:          sig,
				SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
			},
		})
	}
	return &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items:          txItems,
	}
}

// marshalBatchBody renders a batch request in the wire spelling an agent posts.
func marshalBatchBody(t *testing.T, req *rampv1.TransactionRequest) []byte {
	t.Helper()
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(req)
	if err != nil {
		t.Fatalf("marshal batch TransactionRequest: %v", err)
	}
	return body
}

// batchBodyFor is batchRequestFor rendered to the wire.
func (e relayTestEnv) batchBodyFor(t *testing.T, idem string, items []batchItem) []byte {
	t.Helper()
	return marshalBatchBody(t, e.batchRequestFor(t, idem, items))
}

// readBatchResponse reads a relay response, asserts 200, and returns the FULL
// merged TransactionResponse — so the batch-level aggregate (TotalCost) is
// observable through the SAME public relay surface the agent reads, never via
// internal state (Testing Doctrine 9).
func readBatchResponse(t *testing.T, resp *http.Response) *rampv1.TransactionResponse {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch relay failed: %d %s", resp.StatusCode, body)
	}
	var txResp rampv1.TransactionResponse
	if err := protojson.Unmarshal(body, &txResp); err != nil {
		t.Fatalf("parse TransactionResponse: %v", err)
	}
	return &txResp
}

// readBatchItems reads a relay response, asserts 200, and returns the merged
// TransactionResponse.items[].
func readBatchItems(t *testing.T, resp *http.Response) []*rampv1.TransactionResultItem {
	t.Helper()
	return readBatchResponse(t, resp).GetItems()
}

// registerSecondExchange stands up exchange #2 with its own well-known manifest
// and registers it in the broker's trust registry, returning its mock, the
// headers and body it is sent, and its domain. The capture is exchange #2's
// counterpart to relayTestEnv.captured, which holds exchange #1's — a fan-out
// test that reads what ONE exchange received can only tell the two apart by
// reading both.
func registerSecondExchange(
	t *testing.T, env relayTestEnv,
) (*mockExchange, *capturedHeaders, string) {
	t.Helper()
	mock2, captured2, exchange2URL := startCapturingExchange(t)
	mock2.signedURL = "https://cdn.example/signed?from=ex2"
	exchange2Dom := strings.TrimPrefix(exchange2URL, "http://")
	if _, err := env.exchangeRepo.UpsertFromBootstrap(context.Background(), repo.Exchange{
		ID:                "mp-" + exchange2Dom,
		Domain:            exchange2Dom,
		Endpoint:          exchange2URL,
		TrustLevel:        "VERIFIED",
		SupportedProfiles: []string{"ramp-news-v1"},
		Priority:          10,
	}); err != nil {
		t.Fatalf("seed exchange2: %v", err)
	}
	return mock2, captured2, exchange2Dom
}

// TestExchangeRelay_BatchFansOutByOfferExchange pins the S4 batch path: a SINGLE
// batch body whose items span TWO registered exchanges is grouped by
// items[i].offer.exchange, fanned out as ONE broker-signed sub-request per
// exchange, and the per-exchange items[] are merged back into one
// TransactionResponse.items[] in ORIGINAL item order.
//
// Round-trip legs (named honestly):
//   - agent → broker route (real HTTP): ONE sig1 over the whole batch body.
//   - broker → each Exchange (real HTTP): ONE broker-signed sub-request per
//     exchange, each carrying that group's items.
//   - assertions read the broker's HTTP response (merged items[]) + each mock
//     exchange's call count + the upstream transport signatures.
func TestExchangeRelay_BatchFansOutByOfferExchange(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	mock2, _, exchange2Dom := registerSecondExchange(t, env)

	// Interleave the offers across exchanges so "original item order" is a real
	// constraint (item 0 → ex1, item 1 → ex2, item 2 → ex1).
	const idem = "tx-batch-fanout"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: exchange2Dom},
		{offerID: "offer-c", exchange: env.exchangeDom},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	results := readBatchItems(t, resp)

	// Each exchange received EXACTLY ONE broker-signed sub-request (fan-out is
	// one sub-request per distinct exchange, not one per item).
	if env.mockExch.executeCalls != 1 {
		t.Errorf("exchange #1 ExecuteTransaction calls = %d, want 1", env.mockExch.executeCalls)
	}
	if mock2.executeCalls != 1 {
		t.Errorf("exchange #2 ExecuteTransaction calls = %d, want 1", mock2.executeCalls)
	}
	assertSingleBrokerSig(t, env.captured, env.brokerKID)

	// Merged items[] preserve ORIGINAL order: a, b, c.
	if len(results) != 3 {
		t.Fatalf("merged items = %d, want 3", len(results))
	}
	wantOrder := []string{"offer-a", "offer-b", "offer-c"}
	for i, w := range wantOrder {
		if results[i].GetOfferId() != w {
			t.Errorf("item[%d] offer_id = %q, want %q (original order not preserved)",
				i, results[i].GetOfferId(), w)
		}
	}
	// Each item's signed URL came from the exchange it routed to.
	for _, it := range results {
		if it.GetRetrievalEndpoint() == "" {
			t.Errorf("item %q missing retrieval_endpoint", it.GetOfferId())
		}
	}
}

// TestExchangeRelay_BatchFansOutByOfferExchange_SameCurrencyTotalCostSums pins
// the budget-correctness fix (batch fan-out Core Invariant): when a single batch fans
// out to TWO same-currency exchanges, the merged TransactionResponse.TotalCost
// MUST be the EXACT decimal sum of BOTH groups' per-group subtotals, in the
// shared currency — NOT a latched single group's subtotal.
//
// RED on HEAD: fanOutBatch (exchange_relay_batch.go:174-176) does
// `if totalCost == nil { totalCost = resp.GetTotalCost() }`, latching the FIRST
// non-empty group's total and never accumulating the second. With ex1 quoting
// 2 items @ 2.50 (=5.00) and ex2 quoting 1 item @ 2.50 (=2.50), today's merged
// TotalCost reports one group's subtotal (5.00 or 2.50 depending on iteration),
// never the true 7.50.
//
// Round-trip legs (named honestly):
//   - agent → broker route (real HTTP): ONE sig over the whole batch body.
//   - broker → each Exchange (real HTTP): ONE broker-signed sub-request per
//     exchange; each mock returns a per-group TotalCost + per-item Cost.
//   - assertion reads the broker's HTTP response TotalCost (the merged
//     aggregate) — the SAME public surface the agent reads.
func TestExchangeRelay_BatchFansOutByOfferExchange_SameCurrencyTotalCostSums(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	// Both exchanges quote the SAME currency so a scalar total is well-defined.
	env.mockExch.itemCostAmount = 2.50
	env.mockExch.itemCostCurrency = "USD"
	mock2, _, exchange2Dom := registerSecondExchange(t, env)
	mock2.itemCostAmount = 2.50
	mock2.itemCostCurrency = "USD"

	const idem = "tx-batch-samecur"
	// ex1 gets 2 items (subtotal 5.00), ex2 gets 1 item (subtotal 2.50). True
	// whole-batch total = 7.50; a latch reports only 5.00 or 2.50.
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: exchange2Dom},
		{offerID: "offer-c", exchange: env.exchangeDom},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	txResp := readBatchResponse(t, resp)

	// Keep the existing cardinality + order guarantees green.
	results := txResp.GetItems()
	if len(results) != 3 {
		t.Fatalf("merged items = %d, want 3", len(results))
	}
	wantOrder := []string{"offer-a", "offer-b", "offer-c"}
	for i, w := range wantOrder {
		if results[i].GetOfferId() != w {
			t.Errorf("item[%d] offer_id = %q, want %q (order)", i, results[i].GetOfferId(), w)
		}
	}

	// THE FIX: merged TotalCost is the EXACT decimal sum of both groups.
	total := txResp.GetTotalCost()
	if total == nil {
		t.Fatalf("merged TotalCost is nil; want a single-currency aggregate of 7.50 USD")
	}
	if total.GetCurrency() != "USD" {
		t.Errorf("merged TotalCost.Currency = %q, want USD", total.GetCurrency())
	}
	got, err := helpers.ParseMoney(total.GetAmount())
	if err != nil {
		t.Fatalf("parse merged TotalCost.Amount %q: %v", total.GetAmount(), err)
	}
	// 2 items @ 2.50 (ex1) + 1 item @ 2.50 (ex2) = 7.50.
	want := decimal.RequireFromString("7.50")
	if !got.Equal(want) {
		t.Errorf("merged TotalCost.Amount = %s, want %s (broker latched one group's "+
			"subtotal instead of accumulating both)", got, want)
	}

	// Per-item Cost survives intact (a fix that corrects the total by corrupting
	// per-item cost must also fail).
	for _, it := range results {
		ic := it.GetCost()
		if ic == nil || ic.GetCurrency() != "USD" {
			t.Errorf("item %q missing/wrong per-item Cost: %+v", it.GetOfferId(), ic)
			continue
		}
		amt, perr := helpers.ParseMoney(ic.GetAmount())
		if perr != nil || !amt.Equal(decimal.RequireFromString("2.50")) {
			t.Errorf("item %q Cost.Amount = %q, want 2.50", it.GetOfferId(), ic.GetAmount())
		}
	}
}

// TestExchangeRelay_BatchFansOutByOfferExchange_CrossCurrencyDropsScalar pins the
// Option-A cross-currency rule: when a single batch fans out to
// TWO exchanges quoting DIFFERENT currencies, a single scalar TotalCost is
// meaningless, so the merged response MUST emit NO scalar (nil TotalCost) and
// rely on items[].cost — which MUST remain intact per item.
//
// RED on HEAD: fanOutBatch latches the first non-empty group's TotalCost, so
// today the merged response carries one currency's subtotal mislabeled as the
// whole-batch total (non-nil), never the honest nil.
func TestExchangeRelay_BatchFansOutByOfferExchange_CrossCurrencyDropsScalar(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	env.mockExch.itemCostAmount = 2.50
	env.mockExch.itemCostCurrency = "USD"
	mock2, _, exchange2Dom := registerSecondExchange(t, env)
	mock2.itemCostAmount = 3.00
	mock2.itemCostCurrency = "EUR"

	const idem = "tx-batch-crosscur"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom}, // USD 2.50
		{offerID: "offer-b", exchange: exchange2Dom},    // EUR 3.00
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	txResp := readBatchResponse(t, resp)

	results := txResp.GetItems()
	if len(results) != 2 {
		t.Fatalf("merged items = %d, want 2", len(results))
	}

	// THE FIX: a mixed-currency batch emits NO scalar TotalCost (Option A) — a
	// summed-across-currencies scalar would be a silent data-integrity defect.
	if total := txResp.GetTotalCost(); total != nil {
		t.Errorf("cross-currency merged TotalCost = %+v, want nil (a single scalar "+
			"across USD+EUR is meaningless; rely on items[].cost)", total)
	}

	// items[].cost is the authoritative per-item charge and MUST be intact, each
	// in its own exchange's currency.
	wantCur := map[string]string{"offer-a": "USD", "offer-b": "EUR"}
	wantAmt := map[string]string{"offer-a": "2.50", "offer-b": "3.00"}
	for _, it := range results {
		id := it.GetOfferId()
		ic := it.GetCost()
		if ic == nil {
			t.Errorf("item %q missing per-item Cost", id)
			continue
		}
		if ic.GetCurrency() != wantCur[id] {
			t.Errorf("item %q Cost.Currency = %q, want %q", id, ic.GetCurrency(), wantCur[id])
		}
		amt, perr := helpers.ParseMoney(ic.GetAmount())
		if perr != nil || !amt.Equal(decimal.RequireFromString(wantAmt[id])) {
			t.Errorf("item %q Cost.Amount = %q, want %s", id, ic.GetAmount(), wantAmt[id])
		}
	}
}

// TestExchangeRelay_BatchPartialFailure pins the non-atomic property: when one
// exchange denies an item (in-body per-item denial) while the other succeeds,
// the whole request still returns 200 with a MIXED items[] — the denied item
// carries denial_reason, the others carry retrieval_endpoints.
func TestExchangeRelay_BatchPartialFailure(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	mock2, _, exchange2Dom := registerSecondExchange(t, env)
	// Exchange #2 denies its item.
	mock2.denyOfferIDs = map[string]bool{"offer-b": true}

	const idem = "tx-batch-partial"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: exchange2Dom},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	results := readBatchItems(t, resp)
	if len(results) != 2 {
		t.Fatalf("merged items = %d, want 2", len(results))
	}
	byID := map[string]*rampv1.TransactionResultItem{}
	for _, it := range results {
		byID[it.GetOfferId()] = it
	}
	if good := byID["offer-a"]; good == nil || good.GetRetrievalEndpoint() == "" {
		t.Errorf("offer-a should have succeeded with a retrieval_endpoint: %+v", good)
	}
	if denied := byID["offer-b"]; denied == nil ||
		denied.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Errorf("offer-b should carry a SIGNATURE_INVALID denial: %+v", denied)
	}
}

// TestExchangeRelay_BatchRejectsUnregisteredExchange pins the trust gate as a
// whole-request admission gate: if ANY item's offer.exchange is unregistered,
// the WHOLE request is rejected (400) BEFORE any fan-out — zero side effects on
// the trusted exchange.
func TestExchangeRelay_BatchRejectsUnregisteredExchange(t *testing.T) {
	env := newRelayTestEnv(t)

	const idem = "tx-batch-untrusted"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: "rogue.exchange.example"},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("untrusted-item batch: status = %d, want 400; body=%s", resp.StatusCode, b)
	}
	// Zero fan-out: the trusted exchange must NOT have been called.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("exchange #1 was called %d times despite an untrusted item, want 0 (no fan-out)",
			env.mockExch.executeCalls)
	}
}
