//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
)

// The agent's complete-set proof across a fan-out.
//
// An agent signs ONE proof over the whole ordered request set before the broker
// sees it. The broker then splits that set by offer.exchange, and each Exchange
// verifies the proof as a PROJECTION: the items it received must be exactly the
// items the signed set addressed to it, in the signed order. That check is what
// stops a relay dropping or reordering an item and still presenting an
// authentic-looking request — and passing it is what lets the Exchange take a
// request-level claim at all.
//
// The broker's whole part in this is one field assignment on each sub-request.
// Delete it and nothing else in this suite notices: the mock Exchange verifies
// nothing, every merge and ordering assertion still passes, and the real
// Exchange quietly treats each sub-request as a wire-compatible client with no
// proof and skips the claim.
//
// Round-trip legs (named honestly):
//   - agent → broker route (real HTTP): ONE sig1 over the whole batch body,
//     which carries the agent's proof.
//   - broker → each Exchange (real HTTP): the sub-requests the broker actually
//     sent, read back from each Exchange's own capture.
//   - the assertion is the SAME projection verify a real Exchange runs, under
//     the agent's public key, over the bytes each Exchange received.

// TestExchangeRelay_BatchPreservesRequestProofPerProjection sends a two-exchange
// batch carrying a valid complete-set proof and checks each sub-request against
// that proof as the Exchange it was addressed to would.
func TestExchangeRelay_BatchPreservesRequestProofPerProjection(t *testing.T) {
	env := newRelayTestEnv(t)
	mock2, captured2, exchange2Dom := registerSecondExchange(t, env)

	// Interleaved across the two exchanges, so each projection is a genuine
	// subset in signed order rather than a contiguous run. A broker that grouped
	// correctly but reordered within a group fails the projection verify below.
	const idem = "tx-batch-request-proof"
	req := env.batchRequestFor(t, idem, []batchItem{
		{offerID: "offer-a", exchange: env.exchangeDom},
		{offerID: "offer-b", exchange: exchange2Dom},
		{offerID: "offer-c", exchange: env.exchangeDom},
	})
	acceptance, err := helpers.SignRequestAcceptance(env.agentPriv, req)
	if err != nil {
		t.Fatalf("SignRequestAcceptance: %v", err)
	}
	req.AgentRequestAcceptance = acceptance

	resp, err := http.DefaultClient.Do(env.signedRelayRequest(t, marshalBatchBody(t, req)))
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	if got := len(readBatchItems(t, resp)); got != 3 {
		t.Fatalf("merged items = %d, want 3", got)
	}
	if env.mockExch.executeCalls != 1 || mock2.executeCalls != 1 {
		t.Fatalf("fan-out calls = (%d, %d), want (1, 1)",
			env.mockExch.executeCalls, mock2.executeCalls)
	}

	agentPub, ok := env.agentPriv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("agent key is not ed25519: %T", env.agentPriv.Public())
	}
	assertProjectionVerifies(t, env.captured, env.exchangeDom, acceptance, agentPub)
	assertProjectionVerifies(t, captured2, exchange2Dom, acceptance, agentPub)
}

// assertProjectionVerifies reads the sub-request one Exchange was sent and
// checks it the way that Exchange would: the proof must be there, must be the
// agent's own, and must verify as the projection of the signed set onto this
// exchange.
//
// The upstream body is protobuf BINARY, not the agent's JSON — the broker
// re-packages through the typed Connect client, so what has to survive is the
// signed content, not the encoding.
func assertProjectionVerifies(
	t *testing.T,
	captured *capturedHeaders,
	exchangeDom string,
	sent *rampv1.AgentRequestAcceptance,
	agentPub ed25519.PublicKey,
) {
	t.Helper()
	_, _, body := captured.get()
	var sub rampv1.TransactionRequest
	if err := proto.Unmarshal(body, &sub); err != nil {
		t.Fatalf("%s: parse the sub-request it received: %v", exchangeDom, err)
	}
	got := sub.GetAgentRequestAcceptance()
	if got == nil {
		t.Fatalf("%s: sub-request carries no agent_request_acceptance — the broker dropped "+
			"the agent's proof, and this Exchange would take the no-claim compatibility path",
			exchangeDom)
	}
	if !proto.Equal(got, sent) {
		t.Errorf("%s: forwarded proof differs from the one the agent signed:\n got=%v\nsent=%v",
			exchangeDom, got, sent)
	}
	if _, err := helpers.VerifyRequestAcceptanceProjection(&sub, got, exchangeDom, agentPub); err != nil {
		t.Errorf("%s: the sub-request is not the signed projection for this exchange: %v",
			exchangeDom, err)
	}
}
