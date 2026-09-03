//go:build integration

package mcp_test

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestExecute_SignsAcceptanceAsTheCallerAndReturnsTheDeliveryURL is the ticket's
// core execute property, driven end to end: the tool licenses an offer through
// the relay signed as the caller, and hands back the signed delivery URL.
//
// Two independent signatures ride this call and both are checked. The relay's
// transport signature (sig1) is verified by the production gate and its keyid
// recorded — proving the POST went out as this agent. The detached acceptance in
// the body is verified against the SAME agent's key here, proving the binding the
// Exchange would check is present and correct, not merely that a field was filled.
func TestExecute_SignsAcceptanceAsTheCallerAndReturnsTheDeliveryURL(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: "thumb-xyz",
		Items: []*rampv1.TransactionResultItem{{
			OfferId:           "offer-1",
			TransactionId:     "tx-1",
			RetrievalEndpoint: strPtr("https://edge.example/deliver?sig=abc&agent_id=thumb-xyz"),
		}},
	}
	a := f.provision(t, "dev-one")

	out := callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if len(out.Items) != 1 {
		t.Fatalf("got %d result items, want 1", len(out.Items))
	}
	item := out.Items[0]
	if item["transaction_id"] != "tx-1" {
		t.Errorf("transaction_id = %v, want tx-1", item["transaction_id"])
	}
	if item["retrieval_endpoint"] == nil || item["retrieval_endpoint"] == "" {
		t.Errorf("result carried no delivery URL: %v", item)
	}
	if out.AgentIdentityHash != "thumb-xyz" {
		t.Errorf("agent_identity_hash = %q, want thumb-xyz", out.AgentIdentityHash)
	}

	// The relay POST was signed as this agent (transport sig1).
	call := onlyCall(t, f.broker)
	if call.Path != "/broker/v1/exchange/execute" {
		t.Fatalf("broker saw %q, want the execute relay route", call.Path)
	}
	if call.KeyID != a.Thumbprint {
		t.Errorf("relay signed with %q, want the caller's key %q", call.KeyID, a.Thumbprint)
	}

	// The body carries a detached acceptance that verifies against the caller's
	// OWN registered key — the binding the Exchange authenticates the agent by.
	item0 := f.broker.LastExecute().GetItems()[0]
	acceptance := item0.GetAgentAcceptance()
	if acceptance.GetSignature() == "" {
		t.Fatal("no agent acceptance on the relayed item")
	}
	pub := f.activePublicKey(t, a.Subdomain)
	verifyAcceptance(t, item0.GetOffer(), assertRequesterIsCaller(t, f, a),
		f.broker.LastExecute().GetIdempotencyKey(), acceptance.GetSignature(), pub)
	assertNoBearerLeaked(t, f.broker, f.exchange)
}

// assertRequesterIsCaller checks the requester the adapter actually SENT, and
// returns it for use as a verification input.
//
// Asserting it BEFORE using it is the point. Reading the requester back off the
// peer and feeding it straight into VerifyOfferAcceptance makes the verification
// self-consistent: it passes for whatever requester the adapter sent, including an
// empty one, so the acceptance check alone cannot notice the requester going
// wrong. And the requester IS covered by the acceptance signature — a regression
// there breaks every real peer while a self-consistent suite stays green. Same
// reasoning TestExecute_CallerIdempotencyKeyReachesRelay states for the
// idempotency key; the discover path asserts it at tools_test.go.
func assertRequesterIsCaller(t *testing.T, f *fixture, a agent) *rampv1.Requester {
	t.Helper()
	requester := f.broker.LastExecute().GetRequester()
	// The directory origin, not the bare subdomain: that is what the Broker and
	// Exchange match against the signed Signature-Agent.
	if want := "http://" + a.Subdomain; requester.GetId() != want {
		t.Errorf("requester id = %q, want the caller's directory %q", requester.GetId(), want)
	}
	if got := requester.GetType(); got != rampv1.RequesterType_REQUESTER_TYPE_AGENT {
		t.Errorf("requester type = %v, want AGENT", got)
	}
	return requester
}

// TestExecute_BatchOfOneIsNotSpecialCased pins the ticket's explicit rule: a
// single offer rides the same items[] path as a larger batch — one item in, one
// item out — with no separate single-offer shape.
func TestExecute_BatchOfOneIsNotSpecialCased(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{OfferId: "solo", TransactionId: "tx-solo"}},
	}
	a := f.provision(t, "dev-one")

	callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("solo", "exchange.example")},
	})

	req := f.broker.LastExecute()
	if got := len(req.GetItems()); got != 1 {
		t.Fatalf("relay body carried %d items, want the offer as a 1-element batch", got)
	}
	if req.GetItems()[0].GetOffer().GetOfferId() != "solo" {
		t.Errorf("relayed the wrong offer: %v", req.GetItems()[0].GetOffer())
	}
}

// TestExecute_CallerIdempotencyKeyReachesRelay pins the money path: the Exchange
// dedupes a retry on idempotency_key, so the caller's key MUST travel to the relay
// verbatim. The happy-path acceptance check verifies the key against the value the
// peer received — self-consistent, so it would pass for ANY key, including one the
// adapter substituted. This reads the relayed key directly instead.
func TestExecute_CallerIdempotencyKeyReachesRelay(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{OfferId: "offer-1", TransactionId: "tx-1"}},
	}
	a := f.provision(t, "dev-one")

	callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers":          []map[string]any{signedOffer("offer-1", "exchange.example")},
		"idempotency_key": "idem-fixed-1",
	})

	if got := f.broker.LastExecute().GetIdempotencyKey(); got != "idem-fixed-1" {
		t.Errorf("relay idempotency_key = %q, want the caller's %q; a dropped or substituted "+
			"key turns a retry into a second charge", got, "idem-fixed-1")
	}
}

// TestExecute_OmittedIdempotencyKeyIsMinted covers the other arm of
// buildTransactionRequest: when the caller sends no key, the adapter mints one
// rather than relaying an empty key (which the Exchange could not dedupe on).
func TestExecute_OmittedIdempotencyKeyIsMinted(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{OfferId: "offer-1", TransactionId: "tx-1"}},
	}
	a := f.provision(t, "dev-one")

	callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if got := f.broker.LastExecute().GetIdempotencyKey(); got == "" {
		t.Error("relay idempotency_key is empty when the caller omitted it; the adapter must mint one")
	}
}

// TestExecute_PerItemDenialIsCarriedNotErrored checks that a denied item comes
// back inside a successful response with its typed reason — a per-item denial is a
// partial result, not a call failure. An agent that bought three things and had
// one denied still needs the other two.
func TestExecute_PerItemDenialIsCarriedNotErrored(t *testing.T) {
	f := newFixture(t)
	denied := rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{
			OfferId:      "offer-1",
			DenialReason: &denied,
		}},
	}
	a := f.provision(t, "dev-one")

	out := callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if len(out.Items) != 1 {
		t.Fatalf("got %d items, want 1", len(out.Items))
	}
	if got := out.Items[0]["denial_reason"]; got != denied.String() {
		t.Errorf("denial_reason = %v, want %q", got, denied)
	}
	if out.Items[0]["retrieval_endpoint"] != nil {
		t.Errorf("a denied item must carry no delivery URL: %v", out.Items[0])
	}
}

// TestExecute_WholeRequestRefusalSurfacesTypedReason drives the transport-level
// refusal: a non-2xx from the relay must reach the agent as a failed tool call
// carrying the typed reason, not a bare status.
func TestExecute_WholeRequestRefusalSurfacesTypedReason(t *testing.T) {
	f := newFixture(t)
	denial := &rampv1.ErrorDetail{
		Message: "offer no longer valid",
		Reason: &rampv1.ErrorDetail_TransactionDenial{
			TransactionDenial: &rampv1.TransactionDenial{
				Reason: rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED,
			},
		},
	}
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(denial)
	if err != nil {
		t.Fatalf("marshal ErrorDetail: %v", err)
	}
	f.broker.relayErrStatus = 403
	f.broker.relayErrBody = body
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if !strings.Contains(msg, "DENIAL_REASON_OFFER_EXPIRED") {
		t.Errorf("tool error %q, want it to carry the typed denial reason", msg)
	}
}

// TestExecute_RejectsAnUnsignedOfferBeforeAnyRelayCall pins that an offer with no
// signature is refused locally — there is nothing to accept — and nothing is sent.
func TestExecute_RejectsAnUnsignedOfferBeforeAnyRelayCall(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	unsigned := signedOffer("offer-1", "exchange.example")
	delete(unsigned, "signature")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{unsigned},
	})

	if !strings.Contains(msg, "unsigned") {
		t.Errorf("tool error %q, want it to name the unsigned offer", msg)
	}
	// The broad count, not Calls(): a request the relay's signature gate refused
	// still left this process, and Calls() cannot see one.
	if f.broker.HTTPRequests() != 0 {
		t.Error("an unsigned offer still reached the relay")
	}
}

// TestExecute_RequiresAtLeastOneOffer rejects an empty batch before any call.
func TestExecute_RequiresAtLeastOneOffer(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{},
	})

	if !strings.Contains(msg, "offer") {
		t.Errorf("tool error %q, want it to mention the missing offers", msg)
	}
	if f.broker.HTTPRequests() != 0 {
		t.Error("an empty execute still reached the relay")
	}
}

// TestExecute_ReportsUsingTheReturnedTransaction ties execute to report: the
// transaction_id execute hands back is the one report sends, so a purchase can be
// reported without the agent inventing identifiers.
func TestExecute_ReportsUsingTheReturnedTransaction(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{
			OfferId:           "offer-1",
			TransactionId:     "tx-99",
			BillingId:         "bill-99",
			RetrievalEndpoint: strPtr("https://edge.example/deliver?sig=abc"),
		}},
	}
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-99"}
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	exec := callTool[executeResult](t, session, "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})
	txID, _ := exec.Items[0]["transaction_id"].(string)
	if txID == "" {
		t.Fatal("execute returned no transaction_id to report against")
	}

	report := callTool[reportResult](t, session, "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  txID,
		"idempotency_key": "idem-report-1",
	})
	if report.ReportID != "rep-99" {
		t.Fatalf("report_id = %q, want rep-99", report.ReportID)
	}
	if got := f.issuer.LastReport().GetTransactionId(); got != txID {
		t.Errorf("reported tx %q, want the one execute returned %q", got, txID)
	}
}

// TestReport_RefusesEndpointOnAnotherHost drives the host-anchoring refusal ramp_report
// relies on. The endpoint an Exchange advertises is only as trustworthy as the host
// that served the manifest, so ramp_report resolves through the offer-named Exchange's
// OWN manifest and refuses if that endpoint points at a different host — otherwise a
// hostile manifest could redirect an agent-signed usage report (carrying a real
// transaction id) to any public host it names. The control lives in rampclient; this
// proves ramp_report wires it, so deleting the refusal fails here rather than passing.
func TestReport_RefusesEndpointOnAnotherHost(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// A second, unrelated host the manifest will try to redirect the report to.
	elsewhere := newRAMPPeer(t, f.trust)
	// The offer-named Exchange (f.issuer) advertises elsewhere's origin — a
	// DIFFERENT host than the one the report is addressed to.
	f.issuer.setManifestEndpoint(elsewhere.URL())

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-report-1",
	})

	if !strings.Contains(msg, "different host") {
		t.Errorf("tool error %q, want it to name the host-anchoring refusal", msg)
	}
	// The redirect target received nothing — no signed report leaked to the
	// unrelated host. Counted on ANY path: a request that fails the peer's
	// signature gate, or lands somewhere its mux does not serve, increments no
	// per-RPC counter and still arrived.
	if n := elsewhere.HTTPRequests(); n != 0 {
		t.Errorf("the redirect-target host received %d requests; a refused report must reach no one", n)
	}
	// And the addressed Exchange got no report either: the refusal is before the
	// send. Counted per-RPC rather than per-request here, deliberately — this peer
	// SERVES the manifest the resolver read, so a broad request count is expected
	// to be non-zero and would say nothing about whether a report was sent.
	if n := len(f.issuer.Calls()); n != 0 {
		t.Errorf("the addressed Exchange received %d calls; the report was refused before sending", n)
	}
}

// TestExecute_BatchSignsEachAcceptanceOverItsOwnOffer is the batch property the
// single-offer tests cannot prove. signAcceptances loops over items and signs each
// acceptance over that item's OWN offer; at n=1 that loop is indistinguishable from
// one that signs every item over items[0] or drops the tail. With two distinct
// offers, a correct acceptance verifies against its own offer and MUST fail against
// the sibling's — which catches a reused signature or a dropped item. The relayed
// request also preserves submission order; results correlate back to offers by
// each result item's offer_id.
func TestExecute_BatchSignsEachAcceptanceOverItsOwnOffer(t *testing.T) {
	f := newFixture(t)
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{
			{OfferId: "offer-1", TransactionId: "tx-1"},
			{OfferId: "offer-2", TransactionId: "tx-2"},
		},
	}
	a := f.provision(t, "dev-one")

	callTool[executeResult](t, f.connect(t, a.Token), "ramp_execute", map[string]any{
		"offers": []map[string]any{
			signedOffer("offer-1", "exchange.example"),
			signedOffer("offer-2", "exchange.example"),
		},
	})

	items := f.broker.LastExecute().GetItems()
	if len(items) != 2 {
		t.Fatalf("relay body carried %d items, want 2", len(items))
	}
	if items[0].GetOffer().GetOfferId() != "offer-1" || items[1].GetOffer().GetOfferId() != "offer-2" {
		t.Fatalf("relayed offers out of submission order: %q, %q",
			items[0].GetOffer().GetOfferId(), items[1].GetOffer().GetOfferId())
	}

	pub := f.activePublicKey(t, a.Subdomain)
	requester := assertRequesterIsCaller(t, f, a)
	key := f.broker.LastExecute().GetIdempotencyKey()
	for i, item := range items {
		own := item.GetOffer()
		sig := item.GetAgentAcceptance().GetSignature()
		if sig == "" {
			t.Fatalf("item %d carried no acceptance signature", i)
		}
		if err := helpers.VerifyOfferAcceptance(own, requester, key, sig, pub); err != nil {
			t.Errorf("item %d acceptance does not verify against its own offer %q: %v",
				i, own.GetOfferId(), err)
		}
		sibling := items[(i+1)%2].GetOffer()
		if err := helpers.VerifyOfferAcceptance(sibling, requester, key, sig, pub); err == nil {
			t.Errorf("item %d acceptance ALSO verified against the sibling offer %q; each "+
				"acceptance must bind to its own offer only", i, sibling.GetOfferId())
		}
	}
	assertNoBearerLeaked(t, f.broker)
}

type executeResult struct {
	AgentIdentityHash string           `json:"agent_identity_hash"`
	Items             []map[string]any `json:"items"`
	RequestID         string           `json:"request_id"`
}

// signedOffer builds the offer object an agent hands back to ramp_execute — the
// protojson shape ramp_discover would have returned, with a signature present so
// the acceptance has something to anchor to.
func signedOffer(offerID, exchange string) map[string]any {
	offer := &rampv1.Offer{
		OfferId:   offerID,
		Exchange:  exchange,
		Signature: "sig-" + offerID,
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(offer)
	if err != nil {
		panic(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		panic(err)
	}
	return obj
}

// verifyAcceptance checks the detached acceptance against pub using the same SDK
// verifier the Exchange uses, so the test proves the binding the Exchange will
// authenticate — not just that a signature-shaped string is present.
func verifyAcceptance(
	t *testing.T,
	offer *rampv1.Offer, requester *rampv1.Requester, idempotencyKey, sig string,
	pub ed25519.PublicKey,
) {
	t.Helper()
	if err := helpers.VerifyOfferAcceptance(offer, requester, idempotencyKey, sig, pub); err != nil {
		t.Fatalf("agent acceptance does not verify against the caller's key: %v", err)
	}
}

// activePublicKey reads the agent's current signing public key from custody — the
// key the Exchange would resolve from the agent's directory to verify the
// acceptance.
func (f *fixture) activePublicKey(t *testing.T, subdomain string) ed25519.PublicKey {
	t.Helper()
	key, err := f.keys.Active(t.Context(), subdomain)
	if err != nil {
		t.Fatalf("active key for %s: %v", subdomain, err)
	}
	return key.Public
}

func strPtr(s string) *string { return &s }
