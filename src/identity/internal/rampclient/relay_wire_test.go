// The stand-in Broker below is a deliberate exception to the rule that a test
// may not mock the Broker. The property under test is what this CLIENT puts on
// the wire, and no assertion through a real Broker could see it: protojson reads
// both field-name spellings inbound, so a real Broker answers the same either
// way. Receiving the request is the only way to read the bytes it was sent.
// Scope of the exception: outbound-shape assertions only — including what the
// signatures on that outbound body cover, which is a property of the bytes sent
// and of nothing else. Anything about what the Broker DOES with the request
// belongs in an integration test against the real service.

package rampclient_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampclient"
)

// TestExecute_PostsCanonicalProtoNames pins the spelling of the one RAMP body
// this package writes by hand. The relay route is not a Connect handler, so no
// codec is registered for it and the marshal options are the producer's own
// choice; protojson's default writes the camelCase json_name alias.
//
// Nothing at the far end notices, which is why this needs its own test: the
// Broker decodes both spellings, so every existing assertion on this path passes
// either way. Drop UseProtoNames from the marshal options and this test fails
// while the rest of the suite stays quiet.
func TestExecute_PostsCanonicalProtoNames(t *testing.T) {
	t.Parallel()
	relay := &recordingRelay{}
	srv := serveRelay(t, relay)

	client, err := rampclient.New(rampclient.Config{
		Keys:      testutil.AgentKeySource(t, "https://agent.example"),
		BrokerURL: srv.URL,
		// The Exchange collaborators are required by New and unused here: this
		// test drives the relay leg, which posts to the Broker. An empty
		// resolver answers no endpoint, so any account call would fail rather
		// than reach a real host by accident.
		Endpoints:    staticResolver{},
		ExchangeBase: resolvers.NewGuardedTransport(nil),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	sent := purchase()
	if _, err = client.Execute(t.Context(), sent); err != nil {
		t.Fatalf("execute: %v", err)
	}

	body := relay.posted()
	testutil.AssertCanonicalWireNames(t, body, sent)
	// Named explicitly as well, because the descriptor walk above reports only
	// what it finds: a body that somehow carried neither spelling would satisfy
	// it. These two are the fields this request is built from, and the acceptance
	// is named at the depth it belongs to — it rides on the per-ITEM message, and
	// a request carrying it at the top level is the single-offer shape the wire
	// contract no longer has.
	testutil.AssertWireCarries(t, body, sent, "idempotency_key", "items[0].agent_acceptance")
}

// purchaseExchange is the exchange every purchase() item is addressed to. The
// complete-set proof is verified as a PROJECTION onto one exchange, so the
// verifier needs the same value the offer carries.
const purchaseExchange = "exchange.example"

// TestExecute_SignsTheCompleteRequestSet verifies, with the agent's own public
// key, the complete-set proof on the body this client actually posts.
//
// It is the only test outside the Exchange that checks this field at all.
// Everything else on this path asserts per-item acceptances, which the client
// would keep signing if the request-level assignment were deleted — the Broker
// forwards whatever it receives, and the Exchange treats a missing proof as a
// wire-compatible client and drops to the path that takes no request claim. So
// the whole request-level idempotency guarantee could disappear here with every
// other suite still passing, and a key reused with a re-discovered offer would
// execute and charge a second time.
//
// The check is the real one the Exchange runs: the same projection verify, over
// the bytes that left, under the key that signed them. Deleting the assignment
// in signAcceptances leaves no proof on the wire and fails on the nil below.
func TestExecute_SignsTheCompleteRequestSet(t *testing.T) {
	t.Parallel()
	relay := &recordingRelay{}
	srv := serveRelay(t, relay)

	// The key is built here rather than through AgentKeySource because the test
	// needs its PUBLIC half to verify with, and the source hands back only the
	// signing key it was built around.
	agentKey := testutil.AgentKey(t, "https://agent.example")
	client, err := rampclient.New(rampclient.Config{
		Keys:      func(context.Context) (ramphttpsig.AgentKey, error) { return agentKey, nil },
		BrokerURL: srv.URL,
		// Unused here for the same reason as in the test above: this leg posts to
		// the Broker and never resolves an Exchange endpoint.
		Endpoints:    staticResolver{},
		ExchangeBase: resolvers.NewGuardedTransport(nil),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err = client.Execute(t.Context(), purchase()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var posted rampv1.TransactionRequest
	if err = protojson.Unmarshal(relay.posted(), &posted); err != nil {
		t.Fatalf("parse the posted TransactionRequest: %v", err)
	}
	acceptance := posted.GetAgentRequestAcceptance()
	if acceptance == nil {
		t.Fatal("the posted request carries no agent_request_acceptance — the Exchange " +
			"would take the compatibility path and never claim the idempotency key")
	}
	pub, ok := agentKey.Private.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("agent key is not ed25519: %T", agentKey.Private.Public())
	}
	if _, err = helpers.VerifyRequestAcceptanceProjection(
		&posted, acceptance, purchaseExchange, pub,
	); err != nil {
		t.Fatalf("the posted complete-set proof does not verify under the agent key: %v", err)
	}
}

// purchase is the smallest TransactionRequest this client will sign and post:
// one item whose offer carries a signature, because an acceptance floating free
// of a concrete offer is refused before anything is sent.
func purchase() *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: "tx-canonical-names",
		Requester: &rampv1.Requester{
			Id:     "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Domain: "agent.example",
		},
		Items: []*rampv1.TransactionItem{{
			Offer: &rampv1.Offer{
				Exchange:  purchaseExchange,
				Signature: "0011223344556677",
			},
		}},
	}
}

// recordingRelay stands in for the Broker's execute-relay route and keeps the
// exact bytes it was posted.
//
// The bytes are written on the server's goroutine and read on the test's, so
// they are guarded. Nothing else connects the two: a loopback socket is not a
// synchronisation point under the Go memory model, and srv.Close() — which would
// be one — is registered with t.Cleanup and therefore runs after the assertions.
// The race detector does not report this today and is not expected to; net/http
// synchronises internally on the way through. The mutex is here because an
// unguarded shared field is not something to leave for the next reader to
// re-derive, and because the sibling doubles in this service already guard
// theirs.
type recordingRelay struct {
	mu   sync.Mutex
	body []byte
}

// record keeps the bytes one request was posted.
func (r *recordingRelay) record(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = body
}

// posted returns the bytes of the last request, or nil before the first.
func (r *recordingRelay) posted() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body
}

// serveRelay starts the stand-in. It answers a bare TransactionResponse: this
// test is about what leaves, and parseRelayResponse still has to decode
// something for Execute to return without an error.
func serveRelay(t *testing.T, rec *recordingRelay) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /broker/v1/exchange/execute",
		func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read relay body", http.StatusBadRequest)
				return
			}
			rec.record(body)
			w.Header().Set("Content-Type", "application/json")
			if _, err = w.Write([]byte(`{"ver":"` + helpers.ProtocolVersion + `"}`)); err != nil {
				t.Errorf("write relay response: %v", err)
			}
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
