//go:build integration

package mcp_test

import (
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestDiscover_ReturnsOffersVerbatimAndNamesTheRequester checks the two things
// discovery owes the agent: the offers arrive intact, and the request went out
// naming the caller as requester.
//
// "Intact" is the load-bearing half. The offer's signature covers its bytes, so an
// offer that came back re-modelled — a field dropped, a name changed — would be
// useless to license with even though every other assertion passed.
func TestDiscover_ReturnsOffersVerbatimAndNamesTheRequester(t *testing.T) {
	// The offer is issued by the exchange peer and verified against the key that
	// peer publishes, so the loopback directory fetch has to be reachable.
	f := newFixture(t)
	issued := f.exchange.Offer(t, "offer-1")
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:             "https://pub.example/a",
			DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_SEARCH.Enum(),
			Offers:          []*rampv1.Offer{issued},
		}},
	}
	a := f.provision(t, "dev-one")

	out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})

	if len(out.OfferGroups) != 1 {
		t.Fatalf("got %d offer groups, want 1", len(out.OfferGroups))
	}
	group := out.OfferGroups[0]
	if group.URI != "https://pub.example/a" {
		t.Errorf("group uri = %q, want the requested URL", group.URI)
	}
	// How the URL was found is carried through to the agent, not dropped and not
	// replaced in the projection. The fixture Broker reports SEARCH — a value
	// this adapter has no way to produce on its own — so the assertion names its
	// source: an adapter that substituted its own answer, or that mapped every
	// method onto EXCHANGE, fails here. Expecting EXCHANGE against an EXCHANGE
	// fixture would pass either way.
	wantMethod := rampv1.DiscoveryMethod_DISCOVERY_METHOD_SEARCH
	if group.DiscoveryMethod != wantMethod.String() {
		t.Errorf("discovery_method = %q, want %q", group.DiscoveryMethod, wantMethod)
	}
	if len(group.Offers) != 1 {
		t.Fatalf("got %d offers, want 1 (rejected=%+v)", len(group.Offers), group.Rejected)
	}
	offer := group.Offers[0]
	// snake_case, and the signature anchor present: the agent receives the
	// protocol's own encoding, which is what it must hand back unchanged.
	if offer["offer_id"] != "offer-1" {
		t.Errorf("offer_id = %v, want offer-1", offer["offer_id"])
	}
	if offer["signature"] != issued.GetSignature() {
		t.Errorf("signature = %v, want the offer's own signature carried through", offer["signature"])
	}
	// Nothing was rejected: the offer verified, which is the only way it could
	// have reached the offers list at all. Asserting the empty rejection list
	// alongside distinguishes "verified and returned" from "returned unchecked".
	if len(group.Rejected) != 0 {
		t.Errorf("group carried %d rejected offers, want none: %+v", len(group.Rejected), group.Rejected)
	}
	// requester.id is the caller's directory origin (scheme + subdomain), which is
	// what the Broker/Exchange match against the signed Signature-Agent — not the
	// bare subdomain.
	wantID := "http://" + a.Subdomain
	if got := f.broker.LastDiscovery().GetRequester().GetId(); got != wantID {
		t.Errorf("requester id = %q, want the caller's directory %q", got, wantID)
	}
	if got := f.broker.LastDiscovery().GetRequester().GetType(); got != rampv1.RequesterType_REQUESTER_TYPE_AGENT {
		t.Errorf("requester type = %v, want AGENT", got)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("discovery reached the Exchange directly; it must go via the Broker")
	}
	assertNoBearerLeaked(t, f.broker, f.exchange)
}

// TestDiscover_EmptyGroupCarriesItsReason pins that a URL with nothing licensable
// comes back present-but-empty with the typed reason, rather than vanishing. An
// agent that asked about three URLs must be able to tell "no offers" from "never
// asked", and a dropped group makes those indistinguishable.
func TestDiscover_EmptyGroupCarriesItsReason(t *testing.T) {
	f := newFixture(t)
	absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:           "https://pub.example/missing",
			AbsenceReason: &absence,
		}},
	}
	a := f.provision(t, "dev-one")

	out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/missing"},
	})

	if len(out.OfferGroups) != 1 {
		t.Fatalf("got %d groups, want the requested URL present but empty", len(out.OfferGroups))
	}
	if got := out.OfferGroups[0].AbsenceReason; got != absence.String() {
		t.Errorf("absence_reason = %q, want %q", got, absence)
	}
	// This fixture omits the discovery method — our Broker always sets one — so
	// the case covers the projection's rule for an upstream that sends none: it
	// reports nothing rather than the UNSPECIFIED placeholder, the same rule the
	// absence reason follows. Rendering the zero enum as a string would hand the
	// agent a value that looks like an answer.
	if got := out.OfferGroups[0].DiscoveryMethod; got != "" {
		t.Errorf("discovery_method = %q, want empty for an unset method", got)
	}
}

// TestDiscover_BatchOfURIsKeepsOneGroupPerURI covers the obligation a multi-URI
// discovery actually carries: the uris[] the caller supplied is forwarded verbatim,
// and the Broker's per-URI groups come back UNFLATTENED, in order, each still
// bound to the URI it answers — including the one with no offers.
//
// It exists because every other discover test here passes a single-element uris[],
// and a single element cannot distinguish "one group per URI" from "everything
// merged into one group". A regression that concatenated the offers of three URIs
// into one group, reordered them, or dropped the empty group would leave the whole
// rest of the suite green. The equivalent coverage lived in the retired Python
// shim's e2e; this is it at the layer that now owns the behavior.
//
// The two groups that carry offers are issued by DIFFERENT peers, and that is
// load-bearing rather than incidental colour. A Broker fans a query out to every
// Exchange it knows and returns what each one minted, so one response routinely
// carries offers signed by several keys under several domains — which is the
// whole reason discovery resolves a key per exchange domain instead of pinning
// one. With both groups from one peer, a resolver that collapsed to a single
// issuer would verify everything and this test would still pass, while
// production dropped every other Exchange's offers as unverifiable. Keep the two
// peers distinct.
func TestDiscover_BatchOfURIsKeepsOneGroupPerURI(t *testing.T) {
	// Every offer below is verified against the issuing peer's published key, so
	// the loopback directory fetch has to be reachable — for BOTH peers' keys,
	// which are published at two different loopback origins.
	f := newFixture(t)
	uris := []string{
		"https://pub.example/a",
		"https://pub.example/b",
		"https://pub.example/uncatalogued",
	}
	absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{
			{
				// The caller named these URLs, so a real Broker reports EXCHANGE
				// on every group of this response. Nothing here asserts the
				// method; it is set so the fixture does not describe a shape the
				// Broker cannot send.
				Uri:             uris[0],
				DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
				Offers: []*rampv1.Offer{
					f.exchange.Offer(t, "offer-a1"),
					f.exchange.Offer(t, "offer-a2"),
				},
			},
			{
				// A SECOND issuer, signing with its own key under its own domain.
				// Verifying this group means resolving a key the group above did
				// not need.
				Uri:             uris[1],
				DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
				Offers:          []*rampv1.Offer{f.issuer.Offer(t, "offer-b1")},
			},
			// Present but empty, with a typed reason — never silently dropped.
			// It carries the method too: the Broker states one on the absence
			// groups it synthesises, the same as on the groups that carry offers.
			{
				Uri:             uris[2],
				AbsenceReason:   &absence,
				DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
			},
		},
	}
	a := f.provision(t, "dev-one")

	out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": uris,
	})

	// The uris[] reached the Broker verbatim: same values, same order, nothing
	// added or dropped on the way out.
	if got := f.broker.LastDiscovery().GetUris(); !slices.Equal(got, uris) {
		t.Errorf("broker saw uris %v, want the caller's list verbatim %v", got, uris)
	}

	// Three groups back, still one per URI and in the submitted order.
	if len(out.OfferGroups) != len(uris) {
		t.Fatalf("got %d offer groups, want one per requested URI (%d): %+v",
			len(out.OfferGroups), len(uris), out.OfferGroups)
	}
	gotURIs := make([]string, 0, len(out.OfferGroups))
	for _, g := range out.OfferGroups {
		gotURIs = append(gotURIs, g.URI)
	}
	if !slices.Equal(gotURIs, uris) {
		t.Errorf("group uris = %v, want one per requested URI in order %v", gotURIs, uris)
	}

	// Each group carries ITS OWN offers — the check a flattening regression fails.
	wantOffers := map[string][]string{
		uris[0]: {"offer-a1", "offer-a2"},
		uris[1]: {"offer-b1"},
		uris[2]: {},
	}
	for _, g := range out.OfferGroups {
		ids := make([]string, 0, len(g.Offers))
		for _, o := range g.Offers {
			id, _ := o["offer_id"].(string)
			ids = append(ids, id)
		}
		if want := wantOffers[g.URI]; !slices.Equal(ids, want) {
			t.Errorf("group %q carried offers %v, want %v", g.URI, ids, want)
		}
	}

	// The uncatalogued URI is present, empty, and says why.
	empty := out.OfferGroups[2]
	if empty.Licensed {
		t.Errorf("group %q reports licensed with no offers", empty.URI)
	}
	if empty.AbsenceReason != absence.String() {
		t.Errorf("absence_reason = %q, want %q", empty.AbsenceReason, absence)
	}
	assertNoBearerLeaked(t, f.broker, f.exchange)
}

// TestReport_GoesToTheOffersOwnExchange checks the routing rule reporting exists
// for: the report lands at the Exchange named on the offer, found through THAT
// Exchange's own manifest — not at the Broker, and not at whatever endpoint the
// registry happens to be configured with.
func TestReport_GoesToTheOffersOwnExchange(t *testing.T) {
	f := newFixture(t)
	// The report is aimed at f.issuer — an Exchange this service is NOT configured
	// with. That is what makes the assertions below discriminating: routing by
	// configuration instead of by the offer would land on f.exchange, and the
	// "issuer saw it / home saw nothing" pair would both fail.
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-1"}
	a := f.provision(t, "dev-one")

	out := callTool[reportResult](t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-1",
		"billing_id":      "bill-1",
		"idempotency_key": "idem-1",
		"function":        []string{"ai-input"},
	})

	if out.ReportID != "rep-1" {
		t.Fatalf("report_id = %q, want rep-1", out.ReportID)
	}
	call := onlyCall(t, f.issuer)
	if !strings.HasSuffix(call.Path, "/ReportUsage") {
		t.Fatalf("issuing exchange saw %q, want the ReportUsage RPC", call.Path)
	}
	if call.KeyID != a.Thumbprint {
		t.Errorf("signed with %q, want the caller's key %q", call.KeyID, a.Thumbprint)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("the report reached the CONFIGURED exchange; it must follow the offer's exchange instead")
	}
	if len(f.broker.Calls()) != 0 {
		t.Error("the report went through the Broker; it must reach the Exchange directly")
	}
	got := f.issuer.LastReport()
	if got.GetTransactionId() != "tx-1" || got.GetIdempotencyKey() != "idem-1" {
		t.Errorf("report carried tx=%q idem=%q, want tx-1/idem-1",
			got.GetTransactionId(), got.GetIdempotencyKey())
	}
	if fns := got.GetUsage().GetFunction(); len(fns) != 1 || fns[0] != "ai-input" {
		t.Errorf("usage function = %v, want [ai-input]", fns)
	}
	assertNoBearerLeaked(t, f.issuer, f.exchange, f.broker)
}

// A report naming an Exchange whose manifest cannot be read must fail, and must
// not fall back to the configured Exchange. The fallback is the dangerous
// outcome: it would send an agent-signed report about someone else's transaction
// to an Exchange that has no business seeing it.
func TestReport_UnresolvableExchangeIsRefusedWithNoFallback(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		// A host that serves no /.well-known/ramp.json at all.
		"exchange":        "127.0.0.1:1",
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-1",
	})
	if msg == "" {
		t.Fatal("an unresolvable exchange was accepted")
	}
	if len(f.exchange.Calls()) != 0 || len(f.issuer.Calls()) != 0 {
		t.Error("an unresolvable exchange still produced an outbound report")
	}
}

// TestReport_BoundsAnExchangeThatEchoesThePayloadBack is the report leg's half of
// the peer-text bound.
//
// The bound used to sit on the account tools alone, attached to which tool asked
// rather than to where the text came from, so this leg wrote an Exchange's words
// to the operator line unbounded. The usage report reaches an Exchange the caller
// named, exactly as a registration does, so the same Exchange that would echo a
// payload into a refusal here reaches the same log line.
//
// Pinning it on this leg is what stops the bound sliding back to being one tool's
// rule: move it out of failed() and this test goes red while the account tools
// stay green.
func TestReport_BoundsAnExchangeThatEchoesThePayloadBack(t *testing.T) {
	const head = "rejected, you sent: "
	const tail = "Zolvath-Kreznik-Partnership-8817"
	echo := head + strings.Repeat("x", 4096) + tail

	f := newFixture(t)
	f.issuer.failWith(connect.NewError(connect.CodeFailedPrecondition, errStub(echo)))
	a := f.provision(t, "dev-one")

	callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-1",
	})

	lines := f.logs.Find("identity.mcp.call_failed")
	if len(lines) != 1 {
		t.Fatalf("got %d call_failed lines, want 1: %v", len(lines), lines)
	}
	line := lines[0]
	if strings.Contains(line, tail) {
		t.Errorf("the operator line carries text from past the cut: %s", line)
	}
	if !strings.Contains(line, "truncated") {
		t.Errorf("the operator line is not marked as cut, so this leg is unbounded: %s", line)
	}
	if !strings.Contains(line, head) {
		t.Errorf("the operator line dropped the start of the Exchange's message: %s", line)
	}
}

// A RAMP-side refusal on the report leg must surface to the agent, and must not
// look like success.
func TestReport_RAMPRefusalSurfaces(t *testing.T) {
	f := newFixture(t)
	f.issuer.failWith(connect.NewError(connect.CodeFailedPrecondition,
		errStub("usage report rejected")))
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-1",
	})
	if !strings.Contains(msg, "ramp_report") {
		t.Errorf("tool error %q, want it to name the tool that failed", msg)
	}
	if !strings.Contains(msg, "usage report rejected") {
		t.Errorf("tool error %q, want it to carry the Exchange's message", msg)
	}
}

// A RAMP-side refusal on discovery must surface rather than read as "no offers".
// The difference matters: "nothing licensable" is an answer an agent acts on,
// "the Broker refused" is one it retries.
func TestDiscover_RAMPRefusalSurfaces(t *testing.T) {
	f := newFixture(t)
	f.broker.failWith(connect.NewError(connect.CodeUnavailable, errStub("broker is down")))
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})
	if !strings.Contains(msg, "ramp_discover") {
		t.Errorf("tool error %q, want it to name the tool that failed", msg)
	}
	if !strings.Contains(msg, "broker is down") {
		t.Errorf("tool error %q, want it to carry the Broker's message", msg)
	}
}

// TestEveryTool_ReturnsTheCorrelationID pins the consistency the correlation id is
// FOR: an agent quoting an id in a bug report should not have to know which of the
// five tools happens to return one. Two of the five carried it before; a test per
// tool would let the next tool ship without it, so this drives all five.
//
// The id is asserted to be the one the caller SENT on the request, not merely
// non-empty — a freshly minted id would satisfy "non-empty" while being
// uncorrelatable with anything the caller has.
func TestEveryTool_ReturnsTheCorrelationID(t *testing.T) {
	f := newFixture(t)
	f.exchange.registerResp = &rampv1.RegisterResponse{Ver: helpers.ProtocolVersion, BillingRef: "acct-1", Active: true}
	f.exchange.statusResp = &rampv1.GetAccountStatusResponse{Ver: helpers.ProtocolVersion, BillingRef: "acct-1", Active: true}
	// Genuinely issued by a peer whose directory publishes the key, because
	// discovery verifies. A hand-written literal is rejected now, and this test
	// reads only the correlation id — so the discover leg would quietly become
	// "returned nothing and an id" while still passing.
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:             "https://pub.example/a",
			DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
			Offers:          []*rampv1.Offer{f.exchange.Offer(t, "offer-1")},
		}},
	}
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-1"}
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*rampv1.TransactionResultItem{{
			OfferId: "offer-1", TransactionId: "tx-1",
			RetrievalEndpoint: strPtr("https://edge.example/d?sig=a"),
		}},
	}
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	// Hoisted out of the map below so the whole result stays readable. Every tool
	// here is expected to have DONE its job as well as reported an id, and
	// discovery is the one where doing nothing is silent: an empty answer carries
	// a correlation id just as happily as a full one, and the offer reaching the
	// agent depends on verification passing.
	discovered := callTool[discoverResult](t, session, "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})

	// Each entry returns the request_id its tool reported. The id the fixture's
	// session sends is what they must all echo.
	got := map[string]string{
		"ramp_register": callTool[registerResult](t, session, "ramp_register", registerArgs(t, f)).RequestID,
		// Named, so this drives the leg that actually calls the Exchange. The
		// no-argument mode answers from a local note and never leaves the
		// process, so an id echoed there would say nothing about correlation
		// reaching a peer.
		"ramp_status": callTool[statusResult](t, session, "ramp_status", map[string]any{
			"exchange": f.exchange.Domain(t),
		}).RequestID,
		"ramp_discover": discovered.RequestID,
		"ramp_execute": callTool[executeResult](t, session, "ramp_execute", map[string]any{
			"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
		}).RequestID,
		"ramp_report": callTool[reportResult](t, session, "ramp_report", map[string]any{
			"exchange":        f.issuer.Domain(t),
			"transaction_id":  "tx-1",
			"idempotency_key": "idem-1",
		}).RequestID,
	}

	for tool, id := range got {
		if id == "" {
			t.Errorf("%s returned no request_id; every tool returns one", tool)
		}
	}
	if len(discovered.OfferGroups) != 1 || len(discovered.OfferGroups[0].Offers) != 1 {
		t.Errorf("discovery returned %+v; an id echoed by a tool that answered nothing proves nothing",
			discovered.OfferGroups)
	}
}

// --- result shapes and helpers ---

type registerResult struct {
	Exchange   string `json:"exchange"`
	BillingRef string `json:"billing_ref"`
	Active     bool   `json:"active"`
	RequestID  string `json:"request_id"`
}

// statusResult mirrors the tool's ONE output shape. Both modes decode into this
// same type, which is how a test can assert they really do share a schema — two
// types here would let them drift and every test would still pass.
type statusResult struct {
	Accounts  []statusEntry `json:"accounts"`
	RequestID string        `json:"request_id"`
}

type statusEntry struct {
	Exchange   string `json:"exchange"`
	Source     string `json:"source"`
	Registered bool   `json:"registered"`
	Active     *bool  `json:"active"`
	BillingRef string `json:"billing_ref"`
	AsOf       string `json:"as_of"`
}

type discoverResult struct {
	OfferGroups []struct {
		URI string `json:"uri"`
		// Licensed is part of the wire contract deliberately (see offerGroup),
		// so the mirror carries it rather than re-deriving it from len(offers).
		Licensed bool             `json:"licensed"`
		Offers   []map[string]any `json:"offers"`
		// Rejected carries the offers verification refused. The mirror models it
		// as its own shape rather than as a map, because the point of the field is
		// that an agent can branch on the reason — a test reading it as loose JSON
		// would not notice the reason going missing.
		Rejected []struct {
			OfferID string `json:"offer_id"`
			Reason  string `json:"reason"`
		} `json:"rejected"`
		AbsenceReason   string `json:"absence_reason"`
		DiscoveryMethod string `json:"discovery_method"`
	} `json:"offer_groups"`
	AbsenceReason string `json:"absence_reason"`
	RequestID     string `json:"request_id"`
}

type reportResult struct {
	ReportID  string `json:"report_id"`
	RequestID string `json:"request_id"`
}

// onlyCall asserts the peer saw exactly one verified call and returns it.
func onlyCall(t *testing.T, p *rampPeer) peerCall {
	t.Helper()
	calls := p.Calls()
	if len(calls) != 1 {
		t.Fatalf("peer saw %d verified calls, want exactly 1: %+v", len(calls), calls)
	}
	return calls[0]
}

func assertRegistrationField(t *testing.T, data map[string]any, field, want string) {
	t.Helper()
	if got, _ := data[field].(string); got != want {
		t.Errorf("registration_data[%q] = %q, want %q", field, got, want)
	}
}

// hostOf reduces a peer's origin URL to the bare host:port an Offer.exchange
// carries — a domain, never a URL, because the endpoint is the manifest's to give.
func hostOf(t *testing.T, origin string) string {
	t.Helper()
	host := strings.TrimPrefix(origin, "http://")
	if host == origin {
		t.Fatalf("peer origin %q is not the plain http the fixture builds", origin)
	}
	return host
}

// callTool runs one tools/call over the live MCP session and decodes the
// structured result into T. A tool that reported an error fails the test — the
// negative paths assert failure explicitly through callToolErr.
func callTool[T any](
	t *testing.T, session *mcpsdk.ClientSession, name string, args map[string]any,
) T {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("call %s reported an error: %s", name, textOf(res))
	}
	var out T
	decodeStructured(t, res, &out)
	return out
}
