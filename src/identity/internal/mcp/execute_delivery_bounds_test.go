//go:build integration

package mcp_test

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
)

// Delivery behaviours that belong to how THIS service configures the fetch,
// driven through ramp_execute.
//
// They were covered a layer down, against a fetcher this repository used to own.
// That fetcher is the protocol SDK's now, and the SDK's suite covers what is
// properly the fetcher's: the redirect refusal, the body cap and its boundary, a
// mispaired key, URL redaction, round-trip stability, the token-shaped refusal
// reason, and an unsignable proof sending nothing. Restating those here would
// assert the SDK against itself.
//
// What does not survive that move is anything only this service decides. Two
// such properties are below.
//
// One property from the retired suite is not restated here and is covered
// upstream instead: that the fetch deadline bounds minting the proof, not only
// the round trip. The SDK's TestContentFetcher_TheDeadlineCoversProofMinting
// drives it by blocking in the SIGNER, which is the only place that tells the
// two apart — a test that blocks in the handler measures the transport's
// deadline and stays green if the ordering is reversed.
//
// It is not restated here because the old downstream test needed a key source
// that blocks, and this layer has no such seam: custody is a real Vault reached
// through the production resolver, so reproducing it would mean building a fake
// custody path that exists only for the test. That is the seam that proves the
// fake. The test belongs where the deadline is derived, which is where it now
// lives.

// TestExecute_ABatchFetchesOverOneConnection pins that the whole batch is
// fetched over one client, and so over one connection.
//
// The cost this stops is the caller's to set. A purchase carries as many offers
// as the agent chose, each delivered from the same edge, so an implementation
// that opens a client per item pays a TLS handshake per item and abandons a
// transport per item, each holding its idle connection and the goroutines behind
// it until it times out.
//
// It reads as a performance property and is really a correctness one about where
// the identity binds. The SDK client binds one agent for its lifetime, which is
// why a client is built per call at all — the point of this test is that per CALL
// is where it stops, not per item.
func TestExecute_ABatchFetchesOverOneConnection(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	edge.SetBody([]byte("licensed"), "text/plain")

	const items = 4
	result := &rampv1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: a.Thumbprint,
	}
	offers := make([]map[string]any, 0, items)
	for i := range items {
		id := fmt.Sprintf("offer-%d", i)
		result.Items = append(result.Items, deliveredItem(id, edge.URLFor(a.Thumbprint)))
		offers = append(offers, signedOffer(id, "exchange.example"))
	}
	f.broker.relayResp = result

	out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": offers,
	})

	if len(out.DeliveryFailures) != 0 {
		t.Fatalf("delivery failed: %+v", out.DeliveryFailures)
	}
	// Every item really was fetched, so the connection count below is about reuse
	// and not about a batch that quietly did less work.
	if got := edge.Hits(); got != items {
		t.Fatalf("the edge served %d requests, want %d", got, items)
	}
	if got := edge.DistinctRemotes(); got != 1 {
		t.Errorf("the batch arrived over %d connections, want 1 — a client per item cannot reuse one", got)
	}
}

// TestExecute_DeliveryCarriesTheCallsCorrelationID pins that the delivery GET
// reaches the edge under the SAME id the agent was handed.
//
// It is the one leg where delivery failures are diagnosed, and the only one that
// is not an RPC — so it correlates through a header the fetcher stamps rather
// than through the interceptor the other two share. When that hook did not exist
// the fetch went out bare, the edge minted its own id because the header was
// absent, and the registry's failure line and the edge's line for the same fetch
// named two different requests. Nothing failed; there was simply no way to join
// them.
//
// Equality is the assertion, not presence. The client now falls back to its own
// default mint when none is configured, so a fetch always carries SOMETHING —
// and a test that only checked the header was there would pass against exactly
// the failure this pins. What has to hold is that the value is the one the tool
// reported, which is the value an agent quotes in a bug report.
func TestExecute_DeliveryCarriesTheCallsCorrelationID(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	edge.SetBody([]byte("licensed"), "text/plain")
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: a.Thumbprint,
		Items: []*rampv1.TransactionResultItem{
			deliveredItem("offer-1", edge.URLFor(a.Thumbprint)),
		},
	}

	out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})
	if len(out.DeliveryFailures) != 0 {
		t.Fatalf("delivery failed: %+v", out.DeliveryFailures)
	}
	if out.RequestID == "" {
		t.Fatal("the tool reported no request_id; there is nothing to correlate against")
	}

	ids := edge.RequestIDs()
	if len(ids) != 1 {
		t.Fatalf("the edge saw %d requests, want 1", len(ids))
	}
	if ids[0] != out.RequestID {
		t.Errorf("the edge saw request id %q, want %q — the id the agent was handed",
			ids[0], out.RequestID)
	}
}

// TestExecute_EmptyBodyIsDeliveredContent pins that a 2xx with no bytes comes
// back as a zero-length resource rather than a delivery failure.
//
// The edge's no-origin mode answers exactly that by design. Reporting it as a
// failure would tell the agent nothing arrived for an item that was delivered —
// and the transaction is paid for either way, so the agent would be left
// believing it had lost the charge. The assertion is on the embedded resource
// being PRESENT and empty, which is what separates "delivered nothing" from
// "did not deliver".
func TestExecute_EmptyBodyIsDeliveredContent(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	edge.SetBody(nil, "text/plain")
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: a.Thumbprint,
		Items:             []*rampv1.TransactionResultItem{deliveredItem("offer-1", edge.URLFor(a.Thumbprint))},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			offerWithCanonicalURL("offer-1", "exchange.example", canonicalArticle),
		},
	})

	resources := resourceBlocks(res)
	if len(resources) != 1 {
		t.Fatalf("got %d embedded resources, want 1 — an empty body is still a delivery", len(resources))
	}
	if n := len(resources[0].Blob); n != 0 {
		t.Errorf("blob carried %d bytes, want 0", n)
	}
}

// configuredPoPTTL is the proof lifetime the two tests below configure.
//
// Deliberately NOT the SDK's own 30-second default. A configured value equal to
// the default is indistinguishable from no configuration at all: drop the wiring
// and every assertion would still hold.
const configuredPoPTTL = 5 * time.Second

// TestExecute_ProofWindowIsTheConfiguredOne pins that the deployment's
// proof-of-possession TTL reaches the proof.
//
// It is a separate knob from the RAMP signature TTL because it is a separate
// risk: the proof covers only the method and the URL, and the delivery edge
// keeps no replay store, so its lifetime IS the window in which an observed
// request can be repeated. A build that stopped passing the value would widen
// that window silently — every fetch would still succeed on the SDK's own
// default, and no assertion about a working delivery would notice.
//
// The assertion reads the emitted header rather than watching the edge accept or
// refuse. Judging the window through a verifier means comparing two clocks that
// nothing holds together: the proof is minted when the fetch happens, the edge's
// instant is chosen when the double is built, and everything between them — a
// database restore, custody setup, an MCP handshake, a relay round trip — moves
// the gap. A case that turned on the difference would then be decided by how
// fast the fixture ran. The difference between created and expires is the
// property itself and depends on nothing else.
func TestExecute_ProofWindowIsTheConfiguredOne(t *testing.T) {
	edge := testutil.NewEdgeDouble(t, time.Now().Unix())

	var sigInput atomic.Value
	edge.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		sigInput.Store(r.Header.Get("Signature-Input"))
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("licensed"))
	})

	f := newBoundedFixture(t, func(c *app.MCPConfig, _ peerSet) { c.PoPTTL = configuredPoPTTL })
	a := f.provision(t, "dev-one")
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: a.Thumbprint,
		Items: []*rampv1.TransactionResultItem{
			deliveredItem("offer-1", edge.URLFor(a.Thumbprint)),
		},
	}

	out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})
	if len(out.DeliveryFailures) != 0 {
		t.Fatalf("delivery failed: %+v", out.DeliveryFailures)
	}

	raw, _ := sigInput.Load().(string)
	created, expires, err := httpsig.PoPWindowOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := expires - created; got != int64(configuredPoPTTL.Seconds()) {
		t.Errorf("proof window = %ds, want %ds — the configured value did not reach the proof",
			got, int64(configuredPoPTTL.Seconds()))
	}
}

// TestExecute_AnExpiredProofIsRefused pins the other half: the window the header
// carries is one a verifier acts on.
//
// The test above proves the number is emitted and this one proves it is
// enforced, which are different failures. A build that emitted the right window
// and never reached an edge that checked it would pass the first test alone.
//
// The EDGE's clock moves rather than the service's: this service signs its RAMP
// requests and mints its bearer on the system clock, and freezing that would
// produce credentials born expired, failing the call long before the proof was
// ever judged.
//
// The middle case has a BUDGET, and it is worth stating rather than denying.
// The edge's instant is fixed when the double is built and the proof is minted
// later, at the fetch, so the refusal holds while the fixture takes less than
// edgeAhead minus the configured TTL — twenty seconds less five, so fifteen. A
// Vault reset, a snapshot restore, app.Build, a sign-up, an MCP handshake and a
// relay round trip run in tens of milliseconds here; fifteen seconds is room for
// a loaded runner, not a claim that the clock does not matter.
//
// Widening it does not blunt what the case proves. Under the SDK's own
// thirty-second default the proof would outlive the edge's instant by ten
// seconds whatever the fixture did, so the refusal can only happen while the
// configured value is the one in force.
func TestExecute_AnExpiredProofIsRefused(t *testing.T) {
	tests := []struct {
		name      string
		edgeAhead time.Duration
		wantFail  bool
	}{
		{name: "inside the window", edgeAhead: 0},
		{name: "past the configured ttl, inside the sdk default", edgeAhead: 20 * time.Second, wantFail: true},
		{name: "long stale", edgeAhead: time.Hour, wantFail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			edge := testutil.NewEdgeDouble(t, time.Now().Add(tc.edgeAhead).Unix())
			edge.SetBody([]byte("licensed"), "text/plain")

			f := newBoundedFixture(t, func(c *app.MCPConfig, _ peerSet) { c.PoPTTL = configuredPoPTTL })
			a := f.provision(t, "dev-one")
			f.broker.relayResp = &rampv1.TransactionResponse{
				Ver:               helpers.ProtocolVersion,
				AgentIdentityHash: a.Thumbprint,
				Items: []*rampv1.TransactionResultItem{
					deliveredItem("offer-1", edge.URLFor(a.Thumbprint)),
				},
			}

			out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
				"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
			})

			if !tc.wantFail {
				if len(out.DeliveryFailures) != 0 {
					t.Fatalf("delivery failed inside the window: %+v", out.DeliveryFailures)
				}
				return
			}
			if len(out.DeliveryFailures) != 1 {
				t.Fatalf("got %d delivery failures, want 1: %+v",
					len(out.DeliveryFailures), out.DeliveryFailures)
			}
			// The exact token, not a substring of the message. The edge answers a
			// refusal vocabulary an agent branches on, and a substring match would
			// accept a neighbouring token that happens to contain the same letters
			// — which is the rule stated where the discovery tokens are rendered
			// and applied to the report leg's refusal.
			if got := out.DeliveryFailures[0].Reason; got != "pop_expired" {
				t.Errorf("reason = %q, want pop_expired — the edge's expiry refusal", got)
			}
		})
	}
}
