//go:build integration

package transport_test

import (
	"net/http"
	"testing"
)

// TestExchangeRelay_RejectsDuplicateOfferIDs pins the broker's ingress
// duplicate-offer scan: a TransactionRequest carrying two items with the same
// offer_id is an invalid envelope, rejected whole at the relay boundary before
// ResolveGroups or any fan-out. Without the scan the duplicates only fail
// inside their own exchange group after decomposition (the Exchange's
// InvalidArgument comes back as an in-body CONTENT_UNAVAILABLE), while a
// distinct item routed to another exchange still executes — a malformed
// envelope with partial side effects. The broker scan is fail-fast ingress
// validation only; the Exchange's envelope validation remains authoritative.
//
// Round-trip legs (named honestly):
//   - agent → broker relay route (real HTTP), one signed body per subtest.
//   - the broker handler owns the rejection — NO broker → Exchange leg occurs,
//     asserted via both mock exchanges' call counts staying zero.
//   - assertions read the broker's HTTP response (400 + typed ErrorDetail
//     metadata) through the same public surface.
//
// Unique-offer batches staying unchanged is pinned by the existing fan-out
// suite (TestExchangeRelay_BatchFansOutByOfferExchange and siblings).
func TestExchangeRelay_RejectsDuplicateOfferIDs(t *testing.T) {
	env := newRelayTestEnv(t)
	mock2, _, exchange2Dom := registerSecondExchange(t, env)

	send := func(t *testing.T, idem string, items []batchItem) *http.Response {
		t.Helper()
		resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, env.batchBodyFor(t, idem, items)))
		if err != nil {
			t.Fatalf("send duplicate-offer request: %v", err)
		}
		return resp
	}

	// Duplicates inside ONE exchange group, plus a distinct item routed to the
	// OTHER exchange — the partial-side-effect shape the scan exists to prevent.
	t.Run("same_group", func(t *testing.T) {
		resp := send(t, "tx-dup-same-group", []batchItem{
			{offerID: "offer-dup", exchange: env.exchangeDom},
			{offerID: "offer-dup", exchange: env.exchangeDom},
			{offerID: "offer-distinct", exchange: exchange2Dom},
		})
		detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
		assertRelayErrorField(t, detail, "field", "items.offer.offer_id")
		assertRelayErrorField(t, detail, "item_index", "1")
	})

	// The same offer_id claimed toward TWO different exchanges: still one
	// request-level duplicate, still rejected whole.
	t.Run("across_groups", func(t *testing.T) {
		resp := send(t, "tx-dup-across-groups", []batchItem{
			{offerID: "offer-dup-x", exchange: env.exchangeDom},
			{offerID: "offer-dup-x", exchange: exchange2Dom},
			{offerID: "offer-distinct-x", exchange: env.exchangeDom},
		})
		detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
		assertRelayErrorField(t, detail, "field", "items.offer.offer_id")
		assertRelayErrorField(t, detail, "item_index", "1")
	})

	// Zero fan-out across both subtests: neither exchange — including the one
	// that would have received the distinct third item — was ever called.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("exchange 1 was called %d times for duplicate-offer requests, want 0", env.mockExch.executeCalls)
	}
	if mock2.executeCalls != 0 {
		t.Errorf("exchange 2 was called %d times for duplicate-offer requests, want 0", mock2.executeCalls)
	}
}
