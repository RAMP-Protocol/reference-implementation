//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// TestExchangeRelay_ReplaySameIdempotencyKeyReturnsOriginalResult pins the
// proto idempotency conformance (ramp.proto TransactionRequest.idempotency_key:
// "a replay returns the ORIGINAL result rather than re-executing") at the BROKER
// RELAY route — the explicit broker-side complement to the Exchange-surface
// verification of the same property.
//
// The Broker has NO own transaction-idempotency layer: it relays the
// agent-signed request to the offer's Exchange and surfaces whatever the
// Exchange returns. Conformance is therefore TRANSITIVE — this test confirms the
// broker route is TRANSPARENT to a replay: driven twice with the SAME
// idempotency_key, the second call returns the ORIGINAL result (same offer_id +
// transaction_id + retrieval_endpoint) as a 200 SUCCESS, never an AlreadyExists
// error and never a mangled/dropped result.
//
// Why this is non-trivial against the deterministic mock Exchange (whose result
// is a pure function of idempotency_key + offer_id, i.e. a faithful idempotent
// Exchange — a replay yields a byte-identical response, exactly the observable
// idempotency guarantee): the assertions would FAIL if the broker ever
//   - surfaced a replayed duplicate as connect.CodeAlreadyExists (non-200),
//   - mutated the relayed idempotency_key (→ a different deterministic
//     transaction_id), or
//   - dropped the transaction_id / retrieval_endpoint on the second relay.
//
// executeCalls == 2 additionally pins that the broker FORWARDED both calls (no
// broker-side idempotency short-circuit) — the structural reason conformance is
// transitive.
//
// Transport vs application layer: the broker enforces a per-signature sig1
// anti-replay guard (it rejects a byte-identical reused transport signature). A
// legitimate application-level idempotency replay is NOT a reused transport
// signature — it is a request RE-SIGNED at the transport layer (distinct sig1
// `created` → distinct signature) carrying the SAME application
// `idempotency_key`. The two legs below are signed at distinct `created` stamps
// over the SAME body so they clear the transport anti-replay and exercise the
// APPLICATION idempotency path — the layer the earlier idempotency fix repaired.
//
// Round-trip legs (named honestly):
//   - agent → broker route (real HTTP), twice: two DISTINCT sig1 signatures (one
//     per `created`) over the SAME batch body (same idempotency_key).
//   - broker → Exchange (real HTTP), twice: the broker re-packages and relays
//     each call; the mock Exchange returns its deterministic per-(idem,offer)
//     result.
//   - assertions read the broker's HTTP response items[] both times (the SAME
//     public relay surface the agent reads) + the mock's call count.
func TestExchangeRelay_ReplaySameIdempotencyKeyReturnsOriginalResult(t *testing.T) {
	env := newRelayTestEnv(t)
	env.mockExch.signedURL = "https://cdn.example/signed?from=ex1"

	const idem = "tx-relay-replay-original"
	items := []batchItem{{offerID: "offer-a", exchange: env.exchangeDom}}
	body := env.batchBodyFor(t, idem, items)

	// Two distinct sig1 `created` stamps (both in the verifier window) over the
	// SAME body → distinct transport signatures that each clear the anti-replay.
	base := clock.System{}.Now().Unix()

	// Leg 1: the original relayed execute succeeds; capture the original result.
	first, err := http.DefaultClient.Do(
		signedSig1OverBrokerRouteAt(t, env.brokerURL, env.agentKID, env.agentPriv, body, base))
	if err != nil {
		t.Fatalf("send first relay: %v", err)
	}
	firstItems := readBatchItems(t, first)
	if len(firstItems) != 1 {
		t.Fatalf("first relay returned %d items, want 1", len(firstItems))
	}
	origTxID := firstItems[0].GetTransactionId()
	origURL := firstItems[0].GetRetrievalEndpoint()
	if origTxID == "" || origURL == "" {
		t.Fatalf("first relay missing transaction_id/retrieval_endpoint: tx=%q url=%q", origTxID, origURL)
	}

	// Leg 2: REPLAY the SAME body (same idempotency_key). Conformance: the broker
	// route returns the ORIGINAL result as a 200 success — readBatchItems fatals on
	// any non-200, so an AlreadyExists/error surfaced at the broker route fails here.
	second, err := http.DefaultClient.Do(
		signedSig1OverBrokerRouteAt(t, env.brokerURL, env.agentKID, env.agentPriv, body, base-1))
	if err != nil {
		t.Fatalf("send replay relay: %v", err)
	}
	replayItems := readBatchItems(t, second)
	if len(replayItems) != 1 {
		t.Fatalf("replay returned %d items, want 1 (the original)", len(replayItems))
	}
	if got := replayItems[0].GetOfferId(); got != "offer-a" {
		t.Errorf("replay offer_id = %q, want the original %q", got, "offer-a")
	}
	if got := replayItems[0].GetTransactionId(); got != origTxID {
		t.Errorf("replay transaction_id = %q, want the original %q", got, origTxID)
	}
	if got := replayItems[0].GetRetrievalEndpoint(); got != origURL {
		t.Errorf("replay retrieval_endpoint = %q, want the ORIGINAL %q", got, origURL)
	}

	// The broker forwarded BOTH calls to the Exchange — it has no own idempotency
	// short-circuit, so replay conformance is the Exchange's (transitively the
	// broker route's) guarantee, not a broker-side dedup.
	if env.mockExch.executeCalls != 2 {
		t.Errorf("Exchange.ExecuteTransaction calls = %d, want 2 (broker relays both; no broker-side dedup)",
			env.mockExch.executeCalls)
	}
}
