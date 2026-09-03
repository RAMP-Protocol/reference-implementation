//go:build integration

package mcp_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
)

// These tests drive the whole custodial delivery path over the MCP wire: the
// agent calls ramp_execute, the service signs the offer acceptance with the
// agent's Vault key, the Exchange binds the delivery URL to that key's
// thumbprint, and the service then fetches the content presenting the SAME key.
//
// The edge double ENFORCES the binding (agent_id == keyid == thumbprint of the
// presented key), so a passing fetch is proof of the whole chain rather than of
// any single link. That is the property registry-side delivery establishes, and the
// reason the double is an enforcing one rather than a stub.

const canonicalArticle = "https://news.example/articles/42"

// deliveryResult is executeResult plus the delivery failures, which the base
// shape deliberately does not carry.
type deliveryResult struct {
	Items            []map[string]any `json:"items"`
	DeliveryFailures []struct {
		OfferID string `json:"offer_id"`
		URL     string `json:"retrieval_endpoint"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"delivery_failures"`
	// RequestID is the correlation id the call ran under, as the agent receives
	// it. Mirrored here so a delivery test can compare it against what the edge
	// saw — the two are the same id or the two sides' logs cannot be joined.
	RequestID string `json:"request_id"`
}

// offerWithCanonicalURL is signedOffer carrying the resource identity the
// embedded resource's uri is taken from.
func offerWithCanonicalURL(offerID, exchange, canonical string) map[string]any {
	offer := signedOffer(offerID, exchange)
	offer["identity"] = map[string]any{"canonical_url": canonical}
	return offer
}

// deliveredItem is a relay result carrying a delivery URL bound to thumbprint.
func deliveredItem(offerID, endpoint string) *rampv1.TransactionResultItem {
	return &rampv1.TransactionResultItem{
		OfferId:           offerID,
		TransactionId:     "tx-" + offerID,
		BillingId:         "bill-" + offerID,
		RetrievalEndpoint: strPtr(endpoint),
	}
}

// resourceBlocks pulls the embedded resources out of a tool result.
func resourceBlocks(res *mcpsdk.CallToolResult) []*mcpsdk.ResourceContents {
	var out []*mcpsdk.ResourceContents
	for _, block := range res.Content {
		if embedded, ok := block.(*mcpsdk.EmbeddedResource); ok {
			out = append(out, embedded.Resource)
		}
	}
	return out
}

// callToolRaw calls a tool and returns the whole result, so a test can assert on
// the content blocks rather than only the structured projection.
func callToolRaw(
	t *testing.T, session *mcpsdk.ClientSession, name string, args map[string]any,
) *mcpsdk.CallToolResult {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("call %s reported an error: %s", name, textOf(res))
	}
	return res
}

// TestExecute_DeliversContentThroughAnEnforcingEdge is the load-bearing test for
// The edge refuses anyone who cannot prove possession of the key the
// URL is bound to, and the content still comes back — which can only happen if
// the key the service fetched with is the key it signed the acceptance with.
func TestExecute_DeliversContentThroughAnEnforcingEdge(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	edge.SetBody([]byte("<html>the licensed article</html>"), "text/html; charset=utf-8")
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
		t.Fatalf("got %d embedded resources, want 1 (content blocks: %d)", len(resources), len(res.Content))
	}
	got := resources[0]
	if string(got.Blob) != "<html>the licensed article</html>" {
		t.Errorf("blob = %q, want the served document", got.Blob)
	}
	if got.MIMEType != "text/html" {
		t.Errorf("mimeType = %q, want text/html with parameters stripped", got.MIMEType)
	}
	// The asset's own identity, NOT the signed delivery URL — which is a
	// short-lived credential and has no business in a client's history.
	if got.URI != canonicalArticle {
		t.Errorf("uri = %q, want the canonical article URL %q", got.URI, canonicalArticle)
	}
	if strings.Contains(got.URI, "agent_id=") || strings.Contains(got.URI, "sig=") {
		t.Errorf("uri %q leaks delivery-URL credentials", got.URI)
	}
}

// TestExecute_FetchesAsTheCallingAgent is the multi-tenant half of the test
// above, and the only one that can tell "resolve the CALLER's key" apart from
// "use whatever key this process holds" — with a single agent in play the two
// are indistinguishable, and a fetcher wired with a construction-time key would
// pass every other test in this file.
//
// The relay returns a URL bound to agent A while agent B makes the call. B's
// custodied key is what the fetch presents, so a correct edge refuses it. That
// refusal IS the property ADR-023 claims: a leaked delivery URL is useless even
// to another registry user. The wiring it depends on is the one the app's own
// comment calls the single place the acceptance key and the fetch key could be
// made to disagree.
func TestExecute_FetchesAsTheCallingAgent(t *testing.T) {
	f := newFixture(t)
	bound := f.provision(t, "dev-one")
	caller := f.provision(t, "dev-two")
	if bound.Thumbprint == caller.Thumbprint {
		t.Fatal("the two agents share a key; the fixture cannot tell them apart")
	}

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{deliveredItem("offer-1", edge.URLFor(bound.Thumbprint))},
	}

	res := callToolRaw(t, f.connect(t, caller.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if got := len(resourceBlocks(res)); got != 0 {
		t.Errorf("got %d embedded resources, want none — the fetch must not have succeeded", got)
	}
	// Decoded off the SAME result, not a second call: two invocations would assert
	// the blocks of one transaction against the structured view of another.
	var out deliveryResult
	decodeStructured(t, res, &out)
	if len(out.DeliveryFailures) != 1 {
		t.Fatalf("got %d delivery failures, want 1: %+v", len(out.DeliveryFailures), out.DeliveryFailures)
	}
	if got := out.DeliveryFailures[0].Reason; got != "keyid_mismatch" {
		t.Errorf("reason = %q, want keyid_mismatch — the edge saw a key that was not the bound one", got)
	}
	// The request DID leave and the edge refused it. Without this the test would
	// also pass if the service had declined to fetch for some reason of its own.
	if hits := edge.Hits(); hits != 1 {
		t.Errorf("edge saw %d requests, want exactly 1", hits)
	}
}

// TestExecute_KeepsTheStructuredTextBlock guards a silent regression: attaching
// content blocks suppresses the SDK's own JSON text block, so every client that
// reads content[0].text would lose the delivery URLs. The handler re-adds it.
func TestExecute_KeepsTheStructuredTextBlock(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	endpoint := edge.URLFor(a.Thumbprint)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{deliveredItem("offer-1", endpoint)},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if len(res.Content) == 0 {
		t.Fatal("no content blocks at all")
	}
	first, ok := res.Content[0].(*mcpsdk.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want the structured text block first", res.Content[0])
	}
	// Decoded rather than substring-matched: encoding/json HTML-escapes the & in a
	// query string, so a raw comparison would fail on a block that is perfectly
	// correct.
	var decoded deliveryResult
	if err := json.Unmarshal([]byte(first.Text), &decoded); err != nil {
		t.Fatalf("content[0] is not the structured output: %v", err)
	}
	if len(decoded.Items) != 1 {
		t.Fatalf("the text block carries %d items, want 1", len(decoded.Items))
	}
	if got, _ := decoded.Items[0]["retrieval_endpoint"].(string); got != endpoint {
		t.Errorf("the structured text block lost the delivery URL: got %q, want %q", got, endpoint)
	}
}

// TestExecute_PartialDeliveryFailureStillSucceeds is the invariant that matters
// most once money has moved: the Exchange has already charged, so a fetch that
// fails must be REPORTED, never turned into a failed call. The URL survives so
// an agent that can reach the edge itself still has what it paid for.
func TestExecute_PartialDeliveryFailureStillSucceeds(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	broken := testutil.NewEdgeDouble(t, time.Now().Unix())
	broken.SetRefusal(http.StatusForbidden,
		`{"error":"Agent binding check failed","reason":"pop_expired"}`)
	brokenURL := broken.URLFor(a.Thumbprint)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{
			deliveredItem("offer-1", edge.URLFor(a.Thumbprint)),
			deliveredItem("offer-2", brokenURL),
		},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			signedOffer("offer-1", "exchange.example"),
			signedOffer("offer-2", "exchange.example"),
		},
	})
	// ONE call, both views. Two invocations would drive two purchases and assert
	// the content blocks of the first against the projection of the second, so a
	// handler that answered differently on a retry would pass unnoticed — on a test
	// whose whole subject is what happens after money has moved.
	var out deliveryResult
	decodeStructured(t, res, &out)

	if got := len(resourceBlocks(res)); got != 1 {
		t.Errorf("got %d embedded resources, want only the one that succeeded", got)
	}
	if len(out.DeliveryFailures) != 1 {
		t.Fatalf("got %d delivery failures, want 1: %+v", len(out.DeliveryFailures), out.DeliveryFailures)
	}
	failure := out.DeliveryFailures[0]
	if failure.OfferID != "offer-2" {
		t.Errorf("failure names offer %q, want offer-2", failure.OfferID)
	}
	if failure.Reason != "pop_expired" {
		t.Errorf("reason = %q, want the edge's own token pop_expired", failure.Reason)
	}
	if failure.URL != brokenURL {
		t.Errorf("failure dropped the delivery URL: got %q", failure.URL)
	}
	// The item itself is untouched: it is the protocol's own object, and the
	// agent can still fetch it.
	if endpoint, _ := out.Items[1]["retrieval_endpoint"].(string); endpoint != brokenURL {
		t.Errorf("items[1].retrieval_endpoint = %q, want it left intact", endpoint)
	}
	if _, present := out.Items[1]["delivery_failure"]; present {
		t.Error("a field of ours was written into the protocol's own item encoding")
	}
}

// TestExecute_AllDeliveriesFailingStillSucceeds is the same invariant at its
// limit: not one byte arrived, and the call still reports a completed purchase.
func TestExecute_AllDeliveriesFailingStillSucceeds(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	broken := testutil.NewEdgeDouble(t, time.Now().Unix())
	broken.SetRefusal(http.StatusInternalServerError, "upstream is down")
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{deliveredItem("offer-1", broken.URLFor(a.Thumbprint))},
	}

	out := callTool[deliveryResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if len(out.Items) != 1 {
		t.Fatalf("got %d items, want the purchase to have been reported", len(out.Items))
	}
	if len(out.DeliveryFailures) != 1 {
		t.Fatalf("got %d delivery failures, want 1", len(out.DeliveryFailures))
	}
	if out.DeliveryFailures[0].Reason != "refused" {
		t.Errorf("reason = %q, want the class when the edge sent no token",
			out.DeliveryFailures[0].Reason)
	}
}

// TestExecute_RefusedItemIsNeverFetched pins that a denied item produces neither
// a fetch nor a delivery failure. There is no URL because nothing was licensed,
// and reporting a failure for it would invent a problem.
//
// The batch carries a DELIVERED item too, which is what makes the hit count mean
// something: with a refused item alone the edge is never handed a URL at all, so
// zero hits would be structurally guaranteed and the assertion would pass against
// a service that fetched refused items eagerly. One hit, for the one licensed
// item, is the real statement.
func TestExecute_RefusedItemIsNeverFetched(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	denial := rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{
			{OfferId: "offer-1", DenialReason: &denial},
			deliveredItem("offer-2", edge.URLFor(a.Thumbprint)),
		},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			signedOffer("offer-1", "exchange.example"),
			signedOffer("offer-2", "exchange.example"),
		},
	})
	var out deliveryResult
	decodeStructured(t, res, &out)

	if got := len(resourceBlocks(res)); got != 1 {
		t.Errorf("got %d embedded resources, want 1 — only the licensed item", got)
	}
	if len(out.DeliveryFailures) != 0 {
		t.Errorf("a refused item produced a delivery failure: %+v", out.DeliveryFailures)
	}
	if hits := edge.Hits(); hits != 1 {
		t.Errorf("edge saw %d requests, want 1 — the refused item must not be fetched", hits)
	}
}

// TestExecute_FallsBackToTheStrippedDeliveryURL covers an offer with no
// canonical URL. The delivery URL minus its query is the content's true
// location and carries no credential.
func TestExecute_FallsBackToTheStrippedDeliveryURL(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{deliveredItem("offer-1", edge.URLFor(a.Thumbprint))},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	resources := resourceBlocks(res)
	if len(resources) != 1 {
		t.Fatalf("got %d embedded resources, want 1", len(resources))
	}
	if want := edge.Origin() + "/article"; resources[0].URI != want {
		t.Errorf("uri = %q, want the stripped delivery URL %q", resources[0].URI, want)
	}
}

// TestExecute_BudgetExhaustedIsReportedPerItem reaches call_budget_exhausted, a
// token this service promises agents and that no test could produce while the
// batch budget was a compiled-in constant.
//
// The budget admits one item and no more, so the second is reported rather than
// fetched. What makes it a real assertion is edge.Hits(): the skipped item must
// not reach the edge at all, and it must keep its URL, because the Exchange has
// already charged for it and the agent may fetch it itself.
func TestExecute_BudgetExhaustedIsReportedPerItem(t *testing.T) {
	const itemCap = 64
	f := newBoundedFixture(t, func(c *app.MCPConfig, _ peerSet) {
		c.MaxContentBytes = itemCap
		c.MaxCallContentBytes = itemCap // room for exactly one item
	})
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	edge.SetBody([]byte("tiny"), "text/plain")
	endpoint := edge.URLFor(a.Thumbprint)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{
			deliveredItem("offer-1", endpoint),
			deliveredItem("offer-2", endpoint),
		},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			signedOffer("offer-1", "exchange.example"),
			signedOffer("offer-2", "exchange.example"),
		},
	})

	if got := len(resourceBlocks(res)); got != 1 {
		t.Errorf("got %d embedded resources, want 1 — the budget admits one item", got)
	}
	var out deliveryResult
	decodeStructured(t, res, &out)
	if len(out.DeliveryFailures) != 1 {
		t.Fatalf("got %d delivery failures, want 1: %+v", len(out.DeliveryFailures), out.DeliveryFailures)
	}
	failure := out.DeliveryFailures[0]
	// The literal, not the package constant: this token is a wire contract an agent
	// branches on, so a test that tracked a rename would hide the break.
	if failure.Reason != "call_budget_exhausted" {
		t.Errorf("reason = %q, want call_budget_exhausted", failure.Reason)
	}
	if failure.URL != endpoint {
		t.Errorf("the skipped item lost its URL: got %q, want %q", failure.URL, endpoint)
	}
	if hits := edge.Hits(); hits != 1 {
		t.Errorf("edge saw %d requests, want 1 — a budgeted-out item must not be fetched", hits)
	}
}

// TestExecute_CallDeadlineIsReportedPerItem reaches call_deadline_exceeded, the
// other previously-unreachable token. Before the call carried a deadline of its
// own this branch could fire only on a client disconnect, so the token named a
// deadline nothing set.
//
// The edge holds the first fetch past the call deadline; the second item is then
// reported rather than attempted, which is what keeps one slow publisher from
// costing N × the per-fetch timeout.
func TestExecute_CallDeadlineIsReportedPerItem(t *testing.T) {
	f := newBoundedFixture(t, func(c *app.MCPConfig, _ peerSet) {
		c.CallContentTimeout = 150 * time.Millisecond
	})
	a := f.provision(t, "dev-one")

	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	edge.SetHandler(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	endpoint := edge.URLFor(a.Thumbprint)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{
			deliveredItem("offer-1", endpoint),
			deliveredItem("offer-2", endpoint),
		},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			signedOffer("offer-1", "exchange.example"),
			signedOffer("offer-2", "exchange.example"),
		},
	})

	var out deliveryResult
	decodeStructured(t, res, &out)
	if len(out.DeliveryFailures) != 2 {
		t.Fatalf("got %d delivery failures, want 2: %+v", len(out.DeliveryFailures), out.DeliveryFailures)
	}
	// The first item was attempted and cut off; only the SECOND was never tried,
	// and it is the one that must carry the deadline token rather than something
	// that reads like a publisher failure.
	if got := out.DeliveryFailures[1].Reason; got != "call_deadline_exceeded" {
		t.Errorf("second item reason = %q, want call_deadline_exceeded", got)
	}
	if hits := edge.Hits(); hits != 1 {
		t.Errorf("edge saw %d requests, want 1 — the second item must not be attempted", hits)
	}
}

// TestExecute_DeliveryFailureMessageCarriesNoCredential pins that the signed URL
// reaches the agent in exactly one place: the failure's own retrieval_endpoint
// field, where it is deliberate and governed by one redaction policy.
//
// It used to appear in the message too, because the message was the rendered
// error and an unreachable fetch wraps a *url.Error whose text embeds the whole
// request URL. Message text is what clients forward into their own diagnostics,
// so it outlives the credential in it; the structured field does not.
func TestExecute_DeliveryFailureMessageCarriesNoCredential(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// A closed listener, so the fetch fails at dial and the cause is the *url.Error
	// that carries the URL — the exact path that used to leak.
	edge := testutil.NewEdgeDouble(t, time.Now().Unix())
	endpoint := edge.URLFor(a.Thumbprint)
	edge.Close()
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{deliveredItem("offer-1", endpoint)},
	}

	res := callToolRaw(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	var out deliveryResult
	decodeStructured(t, res, &out)
	if len(out.DeliveryFailures) != 1 {
		t.Fatalf("got %d delivery failures, want 1: %+v", len(out.DeliveryFailures), out.DeliveryFailures)
	}
	failure := out.DeliveryFailures[0]
	for _, secret := range []string{"sig=", "agent_id=", "kid=", "exp="} {
		if strings.Contains(failure.Message, secret) {
			t.Errorf("message carries %q from the delivery URL: %q", secret, failure.Message)
		}
	}
	if failure.Message == "" {
		t.Error("message is empty; redaction must not cost the diagnosis")
	}
	// The URL still reaches the agent where it is meant to.
	if failure.URL != endpoint {
		t.Errorf("retrieval_endpoint = %q, want the delivery URL %q", failure.URL, endpoint)
	}
}
