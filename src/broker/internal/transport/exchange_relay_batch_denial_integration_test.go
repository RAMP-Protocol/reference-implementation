//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// resultsByOfferID indexes a merged batch response by offer_id so a test can
// assert per-item outcomes without depending on slice position (order is pinned
// separately).
func resultsByOfferID(items []*rampv1.TransactionResultItem) map[string]*rampv1.TransactionResultItem {
	byID := make(map[string]*rampv1.TransactionResultItem, len(items))
	for _, it := range items {
		byID[it.GetOfferId()] = it
	}
	return byID
}

// TestExchangeRelay_BatchWholeGroupFailureSynthesisesDenials pins the
// negative path the batch-denial dedup left uncovered: when an entire exchange group's fan-out
// call FAILS at the transport layer (the exchange is unreachable / returns a
// transport-class error), the broker synthesises a per-item
// CONTENT_UNAVAILABLE denial for every offer_id in that group
// (collectGroupDenials) rather than dropping the unreachable exchange's items.
// The property is non-atomic: a sibling exchange that succeeds still delivers
// its items in the SAME merged response.
//
// Round-trip legs (named honestly):
//   - agent → broker relay route (real HTTP): ONE sig1 over the whole batch body.
//   - broker → ex1 (real HTTP): succeeds, returns a signed retrieval endpoint.
//   - broker → ex2 (real HTTP): fails the whole call (CodeUnavailable).
//   - assertions read the broker's merged HTTP response items[] (public surface)
//     plus ex1's call count (proving non-atomic delivery).
func TestExchangeRelay_BatchWholeGroupFailureSynthesisesDenials(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	mock2, exchange2Dom := registerSecondExchange(t, env)
	// Exchange #2's entire fan-out call fails at the transport layer.
	mock2.failExecute = true

	// Interleave so original order is a real constraint: a→ex1, b→ex2, c→ex2.
	const idem = "tx-batch-wholegroup-fail"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: exchange2Dom},
		{offerID: "offer-c", exchange: exchange2Dom},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	// A whole-group upstream failure is non-fatal to the request: still 200 with
	// the failed group's items back-filled as denials.
	results := readBatchItems(t, resp)

	// Cardinality + original order preserved despite ex2's failure.
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

	byID := resultsByOfferID(results)
	// ex1's item delivered (non-atomic: a sibling group's failure must not block it).
	if a := byID["offer-a"]; a == nil || a.GetRetrievalEndpoint() == "" {
		t.Errorf("offer-a should have a retrieval_endpoint from ex1: %+v", a)
	}
	// Every offer in the failed group is synthesised as CONTENT_UNAVAILABLE.
	for _, id := range []string{"offer-b", "offer-c"} {
		d := byID[id]
		if d == nil {
			t.Fatalf("%s missing from merged response", id)
		}
		if d.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_CONTENT_UNAVAILABLE {
			t.Errorf("%s denial_reason = %v, want CONTENT_UNAVAILABLE", id, d.GetDenialReason())
		}
		if d.GetRetrievalEndpoint() != "" {
			t.Errorf("%s should carry no retrieval_endpoint on a synthesised denial", id)
		}
	}
	// Non-atomic delivery proof: ex1 was still called exactly once.
	if env.mockExch.executeCalls != 1 {
		t.Errorf("exchange #1 ExecuteTransaction calls = %d, want 1 (sibling failure must not skip it)",
			env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_BatchBackFillsMissingItems pins the second uncovered
// synthesis path: when an exchange returns SUCCESSFULLY but with FEWER items
// than it was sent, the broker back-fills the missing offer_id with a
// CONTENT_UNAVAILABLE denial (mergeBatchResults) so the merged response
// cardinality always matches the request — the agent never silently loses an
// item it asked for.
//
// Round-trip legs (named honestly):
//   - agent → broker relay route (real HTTP): ONE sig1 over the 2-item body.
//   - broker → ex1 (real HTTP): returns ONLY offer-a (offer-b omitted).
//   - assertions read the broker's merged HTTP response items[] (public surface).
func TestExchangeRelay_BatchBackFillsMissingItems(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"
	// ex1 silently drops offer-b from its response (returns fewer items than sent).
	env.mockExch.omitOfferIDs = map[string]bool{"offer-b": true}

	const idem = "tx-batch-backfill"
	items := []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: env.exchangeDom},
	}
	body := env.batchBodyFor(t, idem, items)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	results := readBatchItems(t, resp)

	// Cardinality matches the request even though the exchange returned 1 item.
	if len(results) != 2 {
		t.Fatalf("merged items = %d, want 2 (missing item not back-filled)", len(results))
	}
	if results[0].GetOfferId() != "offer-a" || results[1].GetOfferId() != "offer-b" {
		t.Errorf("merged order = [%q,%q], want [offer-a,offer-b]",
			results[0].GetOfferId(), results[1].GetOfferId())
	}

	byID := resultsByOfferID(results)
	if a := byID["offer-a"]; a == nil || a.GetRetrievalEndpoint() == "" {
		t.Errorf("offer-a should have a retrieval_endpoint: %+v", a)
	}
	b := byID["offer-b"]
	if b == nil {
		t.Fatalf("offer-b missing from merged response (should be back-filled)")
	}
	if b.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_CONTENT_UNAVAILABLE {
		t.Errorf("offer-b denial_reason = %v, want CONTENT_UNAVAILABLE (back-fill)", b.GetDenialReason())
	}
	if b.GetRetrievalEndpoint() != "" {
		t.Errorf("offer-b should carry no retrieval_endpoint on a back-filled denial")
	}
}
