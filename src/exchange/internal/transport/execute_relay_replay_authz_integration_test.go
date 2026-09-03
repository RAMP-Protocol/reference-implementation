//go:build integration

package transport_test

import (
	"testing"
	"time"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Broker-relay policy on the replay and claim paths.
//
// A tenant with allow_broker_relay=false refuses an execute arriving through a
// broker. The finalized-response and legacy per-item replay paths, and the
// claim insert, all run at ADMISSION — so without the relay gate hoisted there,
// a broker could (a) be served a stored response, signed URLs included, by
// retrying an agent-direct original, and (b) reserve a victim agent's
// (key, digest) with a policy-rejected request. Admission runs the same
// authorizeTransportRelay the per-item pipeline uses, before any claim mutation
// or stored-response disclosure.
//
// Round-trip honesty: every leg drives the public ExecuteTransaction RPC; claim
// and side-effect state is observed through the production repo/billing
// surfaces, never raw SQL.

// TestExecuteRelayReplay_RefusedForDisallowedRelay proves an agent-direct
// original cannot be replayed through a broker onto a tenant that forbids
// relay: the retry is refused PermissionDenied with no stored URL served, on
// the finalized-response path.
func TestExecuteRelayReplay_RefusedForDisallowedRelay(t *testing.T) {
	h := newTestHarness(t)
	// allow_broker_relay defaults to FALSE.
	uri := seedResourceWithRate(t, h, "/articles/relay-replay-denied", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-relay-replay-denied"
	// Agent-direct original succeeds and finalizes a response with a signed URL.
	first, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("agent-direct original must succeed: %v", err)
	}
	if first.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("original response carries no retrieval endpoint")
	}

	// Same request, now relayed through a broker. The tenant forbids relay, so
	// admission must refuse before serving the stored response.
	relayClient := h.brokerRelayClient(t, "broker.replay-denied.v1")
	_, replayErr := executeBrokerRelay(t, h, relayClient, idem, offer)
	assertConnectCode(t, replayErr, connect.CodePermissionDenied)
}

// TestExecuteRelayReplay_AllowedRelayReplaysOriginal is the positive companion:
// on an allow_broker_relay=true tenant, a broker-relayed retry of an agent's
// original is served the original response (relay policy passes, ownership gate
// passes on the agent's body acceptance).
func TestExecuteRelayReplay_AllowedRelayReplaysOriginal(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	uri := seedResourceWithRate(t, h, "/articles/relay-replay-ok", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-relay-replay-ok"
	relayClient := h.brokerRelayClient(t, "broker.replay-ok.v1")
	first, err := executeBrokerRelay(t, h, relayClient, idem, offer)
	if err != nil {
		t.Fatalf("broker-relay original on an allow-relay tenant must succeed: %v", err)
	}
	second, err := executeBrokerRelay(t, h, relayClient, idem, offer)
	if err != nil {
		t.Fatalf("broker-relay retry must replay the original, not fail: %v", err)
	}
	if first.Msg.GetItems()[0].GetTransactionId() != second.Msg.GetItems()[0].GetTransactionId() {
		t.Fatalf("relay retry transaction_id differs: %q vs %q — re-executed instead of replayed",
			first.Msg.GetItems()[0].GetTransactionId(), second.Msg.GetItems()[0].GetTransactionId())
	}
}

// TestExecuteRelayReplay_ExpiredOfferStillReachesRelayVerdict proves an EXPIRED
// offer does not route around the relay opt-out on the finalized-replay path. The
// relay verdict resolves the tenant from the offer's signed canonical_url with the
// signature checked but expiry ignored (an expired offer's signature is still
// valid), so a broker retry of an agent-direct original is refused
// PermissionDenied even after the offer expired — the stored signed URL, still
// live under its own later expiry, is never served.
//
// Before the fix relayPolicyGate resolved each item through the full offer
// verification, which fails an expired offer, skipped it, found no tenant, and let
// admission serve the stored response — the leak this test pins closed.
func TestExecuteRelayReplay_ExpiredOfferStillReachesRelayVerdict(t *testing.T) {
	det := clock.NewDeterministic(time.Now().UTC())
	h := newTestHarnessWithClock(t, det)
	// allow_broker_relay defaults to FALSE.
	uri := seedResourceWithRate(t, h, "/articles/relay-replay-expired", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-relay-replay-expired"
	// Agent-direct original succeeds while the offer is fresh and finalizes a
	// response with a signed URL.
	first, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("agent-direct original must succeed: %v", err)
	}
	if first.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("original response carries no retrieval endpoint")
	}
	balAfterOriginal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after original: %v", err)
	}

	// Advance past the offer's signed expiry (default OfferTTL 5m). The offer is
	// now expired, but the claim and its finalized response persist.
	det.Advance(10 * time.Minute)

	// Retry through a broker on the disallow-relay tenant. The expired offer must
	// still reach the relay verdict and be refused, not skipped-then-served.
	relayClient := h.brokerRelayClient(t, "broker.replay-expired.v1")
	replayResp, replayErr := executeBrokerRelay(t, h, relayClient, idem, offer)
	if replayErr == nil {
		leaked := ""
		if items := replayResp.Msg.GetItems(); len(items) == 1 {
			leaked = items[0].GetRetrievalEndpoint()
		}
		t.Fatalf("SECURITY: expired-offer broker relay served the stored response "+
			"(leaked retrieval_endpoint=%q); want PermissionDenied", leaked)
	}
	assertConnectCode(t, replayErr, connect.CodePermissionDenied)

	// No further charge landed from the refused relay.
	balAfterReplay, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after refused relay: %v", err)
	}
	if balAfterReplay.Value.Cmp(balAfterOriginal.Value) != 0 {
		t.Fatalf("balance moved on the refused relay: %s -> %s",
			balAfterOriginal.Value.FloatString(4), balAfterReplay.Value.FloatString(4))
	}
}

// TestExecuteRelayDisallowed_LeavesNoClaim proves a policy-rejected broker
// request mutates NO claim state: after the refusal, the agent's OWN direct
// request under the same idempotency_key with a DIFFERENT item set proceeds as
// fresh (it is not refused AlreadyExists, which is what a reserved claim would
// cause).
func TestExecuteRelayDisallowed_LeavesNoClaim(t *testing.T) {
	h := newTestHarness(t)
	// allow_broker_relay defaults to FALSE.
	uriA := seedResourceWithRate(t, h, "/articles/relay-claim-a", "0.05")
	uriB := seedResourceWithRate(t, h, "/articles/relay-claim-b", "0.05")
	offerA := discoverOffer(t, h, uriA)
	offerB := discoverOffer(t, h, uriB)

	const idem = "tx-relay-no-claim"
	// A broker relays a request for offer A under the key: refused by policy.
	relayClient := h.brokerRelayClient(t, "broker.no-claim.v1")
	if _, err := executeBrokerRelay(t, h, relayClient, idem, offerA); err == nil {
		t.Fatal("broker relay on a disallow-relay tenant must be refused")
	} else {
		assertConnectCode(t, err, connect.CodePermissionDenied)
	}

	// The agent's own direct request under the SAME key with a DIFFERENT offer
	// must proceed as fresh — proving the refused relay reserved no claim (a
	// reserved claim with A's digest would refuse this as AlreadyExists).
	resp, err := executeSingleItem(t, h, idem, offerB)
	if err != nil {
		t.Fatalf("agent-direct request after a refused relay must be fresh, not AlreadyExists: %v", err)
	}
	if resp.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("agent-direct request after a refused relay returned no retrieval endpoint")
	}
	// And nothing was persisted or charged by the refused relay: the balance
	// reflects exactly the one agent-direct charge (0.05 → 9.95).
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (only the agent-direct request charged)", bal.Value.FloatString(4))
	}
}
