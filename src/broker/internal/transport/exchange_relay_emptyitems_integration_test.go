//go:build integration

package transport_test

import (
	"io"
	"net/http"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
)

// readBrokerErrorDetail reads a relay error response, asserts the given HTTP
// status, and returns the FULL rampv1.ErrorDetail the broker's raw-relay sink
// (writeBrokerError) protojson-marshals into the body. It is the raw-sink
// analogue of the Connect sink's assertBrokerErrorField: the ADR-019 §1
// obligation is asserted on the TYPED ErrorDetail.metadata, never string-matched
// on the message. Reads back through the same public HTTP surface the broker
// produced the body on (Testing Doctrine pt9).
func readBrokerErrorDetail(t *testing.T, resp *http.Response, wantStatus int) *rampv1.ErrorDetail {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, wantStatus, body)
	}
	var detail rampv1.ErrorDetail
	if err := protojson.Unmarshal(body, &detail); err != nil {
		t.Fatalf("parse ErrorDetail (body=%s): %v", body, err)
	}
	return &detail
}

// assertRelayErrorField asserts the raw-relay ErrorDetail body carries
// Domain=="ramp.v1.BrokerService" AND metadata[key]==want. Mirror of the Connect
// sink's assertBrokerErrorField for the raw http.ResponseWriter relay sink.
func assertRelayErrorField(t *testing.T, detail *rampv1.ErrorDetail, key, want string) {
	t.Helper()
	if got := detail.GetDomain(); got != "ramp.v1.BrokerService" {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, "ramp.v1.BrokerService")
	}
	if got := detail.GetMetadata()[key]; got != want {
		t.Fatalf("ErrorDetail.metadata[%q] = %q, want %q (metadata=%v)",
			key, got, want, detail.GetMetadata())
	}
}

// emptyItemsBody marshals a TransactionRequest with NO top-level offer and an
// ABSENT items[] (the post-C1/C2 shape that no sender should produce, but the
// broker must still reject). It carries a valid requester + idempotency_key so
// the body parses cleanly and the request fails ONLY on the empty-items guard.
func (e relayTestEnv) emptyItemsBody(t *testing.T) []byte {
	t.Helper()
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: "tx-empty-items",
		Requester: &rampv1.Requester{
			Id:     e.agentKID,
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	})
	if err != nil {
		t.Fatalf("marshal empty-items TransactionRequest: %v", err)
	}
	return body
}

// itemMissingExchangeBody marshals a 1-item batch TransactionRequest whose sole
// item carries an offer with an EMPTY offer.exchange. The acceptance is signed
// over the shared requester + idempotency_key exactly as batchBodyFor does, so
// the body is well-formed and signature-valid — it fails ONLY on the per-item
// resolveBatchGroups guard, not on the empty-items guard or sig1.
func (e relayTestEnv) itemMissingExchangeBody(t *testing.T) []byte {
	t.Helper()
	const idem = "tx-item-missing-exchange"
	requester := &rampv1.Requester{
		Id:     e.agentKID,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	offer := &rampv1.Offer{
		OfferId:   "offer-no-exchange",
		Exchange:  "", // missing routing target — the per-item guard
		Signature: "sig-offer-no-exchange",
	}
	sig, err := helpers.SignOfferAcceptance(e.agentPriv, offer, requester, idem)
	if err != nil {
		t.Fatalf("SignOfferAcceptance: %v", err)
	}
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{{
			Offer: offer,
			AgentAcceptance: &rampv1.AgentAcceptance{
				Signature:          sig,
				SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
			},
		}},
	})
	if err != nil {
		t.Fatalf("marshal item-missing-exchange TransactionRequest: %v", err)
	}
	return body
}

// TestExchangeRelay_RejectsEmptyItems is the PRIMARY C3 red artifact: it pins the
// NEW empty-items guard the always-batch collapse must add to serveBatch. A
// properly agent-signed TransactionRequest with NO top-level offer and an absent
// items[] is posted to the real broker relay route over real HTTP, through the
// testcontainers-backed relay handler (no DB/handler mocking — same harness as
// the other relay integration tests).
//
// Round-trip legs (named honestly):
//   - agent → broker relay route (real HTTP): ONE sig1 over the empty-items body.
//   - the broker relay handler itself owns the rejection — NO fan-out leg occurs.
//   - assertions read back the broker's HTTP response (400 + ErrorDetail.Message)
//     and the mock Exchange's call count (zero fan-out).
//
// WHY this is RED on HEAD: with items[] absent and no top-level offer,
// isBatchBody returns false (it requires len(items) > 0), so ServeHTTP routes
// the request to the SINGLE-offer path (relayCore.serve → resolveEndpoint),
// which 400s with "offer.exchange required to route an execute relay" — NOT an
// items/min-1 message. The message assertion below therefore FAILS on HEAD and
// PASSES once C3 collapses ServeHTTP to always call serveBatch and serveBatch
// adds the explicit "items[] required (min 1)" guard.
func TestExchangeRelay_RejectsEmptyItems(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.emptyItemsBody(t)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send empty-items request: %v", err)
	}
	// ADR-019 §1 obligation (exchange_relay_batch.go:65): the offending field
	// rides as TYPED ErrorDetail.metadata["field"]=="items", read back through
	// the raw-relay JSON body — never string-matched on the message. FAILS on
	// HEAD: writeBrokerError emits {Message,Domain} only (broker.Error has no
	// Metadata), so GetMetadata() is empty.
	detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
	assertRelayErrorField(t, detail, "field", "items")

	// No fan-out: the guard runs before any Exchange call.
	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an empty-items request, want 0", env.mockExch.executeCalls)
	}
}

// TestExchangeRelay_RejectsItemMissingExchange is the distinguishing companion
// (REFINED PLAN, MEDIUM finding): a 1-item items[] body whose sole item has an
// EMPTY offer.exchange must 400 with the PER-ITEM message, separable from the
// empty-items guard above. Without two distinct message assertions a single 400
// cannot tell which guard fired, so one guard could be deleted while the suite
// stays green.
//
// On HEAD this body HAS items (len > 0) and no top-level offer, so isBatchBody
// returns TRUE → serveBatch → resolveBatchGroups already emits the per-item
// "item %d: offer.exchange required to route an execute relay" 400. This test is
// therefore expected to PASS on HEAD; it exists to pin that the per-item guard
// keeps firing (with its distinct message) after the collapse, so the two 400
// paths remain independently covered.
func TestExchangeRelay_RejectsItemMissingExchange(t *testing.T) {
	env := newRelayTestEnv(t)
	body := env.itemMissingExchangeBody(t)

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, body))
	if err != nil {
		t.Fatalf("send item-missing-exchange request: %v", err)
	}
	// ADR-019 §1 obligation (exchange_relay_batch.go:102): the per-item guard
	// rides TYPED ErrorDetail.metadata["field"]=="offer.exchange" AND
	// metadata["item_index"]=="0", read back through the raw-relay JSON body —
	// this REPLACES the prior strings.Contains message match as the contract.
	// FAILS on HEAD: writeBrokerError emits {Message,Domain} only.
	detail := readBrokerErrorDetail(t, resp, http.StatusBadRequest)
	assertRelayErrorField(t, detail, "field", "offer.exchange")
	assertRelayErrorField(t, detail, "item_index", "0")

	if env.mockExch.executeCalls != 0 {
		t.Errorf("Exchange was called %d times for an item missing offer.exchange, want 0",
			env.mockExch.executeCalls)
	}
}
