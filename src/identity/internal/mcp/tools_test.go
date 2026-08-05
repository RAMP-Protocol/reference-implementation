//go:build integration

package mcp_test

import (
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
)

// acmeDetails is the licensing information a developer submits at sign-up, and
// what register must forward to the Exchange.
var acmeDetails = signup.FormInput{
	LegalEntity:         "Acme GmbH",
	Address:             "1 Main St, Berlin",
	JurisdictionCountry: "de",
}

// TestRegister_SignsAsTheCallerAndForwardsLicensingDetails is the ticket's core
// property, driven end to end: a tool call authenticated by one developer's bearer
// leaves as a RAMP request signed by THAT developer's custodied key.
//
// Both halves matter. The Exchange only accepted the call because the signature
// verified under the production gate, and the recorded keyid proves which key
// signed — so this is not "a request arrived" but "the right agent asked".
func TestRegister_SignsAsTheCallerAndForwardsLicensingDetails(t *testing.T) {
	f := newFixture(t)
	f.exchange.registerResp = &rampv1.RegisterResponse{
		Ver: rampproto.Ver, BillingRef: "acct-123", Active: true,
	}
	a := f.provision(t, "dev-one", acmeDetails)

	out := callTool[accountResult](t, f.connect(t, a.Token), "ramp_register", nil)

	if out.BillingRef != "acct-123" || !out.Active {
		t.Fatalf("register returned %+v, want billing_ref acct-123 and active", out)
	}
	call := onlyCall(t, f.exchange)
	if !strings.HasSuffix(call.Path, "/Register") {
		t.Fatalf("exchange saw %q, want the Register RPC", call.Path)
	}
	if call.KeyID != a.Thumbprint {
		t.Fatalf("signed with keyid %q, want the caller's own key %q", call.KeyID, a.Thumbprint)
	}
	if call.SignatureAgent != "http://"+a.Subdomain {
		t.Fatalf("Signature-Agent %q, want the caller's own directory http://%s",
			call.SignatureAgent, a.Subdomain)
	}
	// The licensing details reach the Exchange from OUR store, never from the
	// caller: register takes no arguments, so this is the only way they arrive.
	assertRegistrationField(t, f.exchange.LastRegistration(), "legal_entity", "Acme GmbH")
	assertRegistrationField(t, f.exchange.LastRegistration(), "subdomain", a.Subdomain)
	// "DE", not the "de" submitted: sign-up canonicalises the country to its ISO
	// 3166-1 alpha-2 form on the way in (signup/validate.go), and what register
	// forwards is the STORED value, not the raw submission.
	assertRegistrationField(t, f.exchange.LastRegistration(), "jurisdiction_country", "DE")
	assertNoBearerLeaked(t, f.exchange, f.broker)
}

// TestRegister_TwoAgentsSignAsThemselves pins the property that makes the registry
// multi-tenant: one endpoint, one transport, but each caller's request signed with
// its OWN key. A regression that bound one key at construction — or cached the
// first caller's — would still pass every single-agent test and fail here.
func TestRegister_TwoAgentsSignAsThemselves(t *testing.T) {
	f := newFixture(t)
	first := f.provision(t, "dev-one", acmeDetails)
	second := f.provision(t, "dev-two", acmeDetails)
	if first.Thumbprint == second.Thumbprint {
		t.Fatal("the two agents share a key; the fixture cannot tell them apart")
	}

	callTool[accountResult](t, f.connect(t, first.Token), "ramp_register", nil)
	callTool[accountResult](t, f.connect(t, second.Token), "ramp_register", nil)

	calls := f.exchange.Calls()
	if len(calls) != 2 {
		t.Fatalf("exchange saw %d calls, want 2", len(calls))
	}
	if calls[0].KeyID != first.Thumbprint {
		t.Errorf("first call signed with %q, want %q", calls[0].KeyID, first.Thumbprint)
	}
	if calls[1].KeyID != second.Thumbprint {
		t.Errorf("second call signed with %q, want %q", calls[1].KeyID, second.Thumbprint)
	}
}

// TestStatus_ReportsTheAccountState drives the second account RPC. Its request
// carries no identifying field at all, so the signature is the ONLY thing telling
// the Exchange whose status to answer with.
func TestStatus_ReportsTheAccountState(t *testing.T) {
	f := newFixture(t)
	f.exchange.statusResp = &rampv1.GetAccountStatusResponse{
		Ver: rampproto.Ver, BillingRef: "acct-123", Active: false,
	}
	a := f.provision(t, "dev-one", acmeDetails)

	out := callTool[accountResult](t, f.connect(t, a.Token), "ramp_status", nil)

	if out.BillingRef != "acct-123" {
		t.Errorf("billing_ref = %q, want acct-123", out.BillingRef)
	}
	if out.Active {
		t.Error("active = true, want the inactive account the Exchange reported")
	}
	if call := onlyCall(t, f.exchange); call.KeyID != a.Thumbprint {
		t.Errorf("signed with %q, want the caller's key %q", call.KeyID, a.Thumbprint)
	}
}

// TestDiscover_ReturnsOffersVerbatimAndNamesTheRequester checks the two things
// discovery owes the agent: the offers arrive intact, and the request went out
// naming the caller as requester.
//
// "Intact" is the load-bearing half. The offer's signature covers its bytes, so an
// offer that came back re-modelled — a field dropped, a name changed — would be
// useless to license with even though every other assertion passed.
func TestDiscover_ReturnsOffersVerbatimAndNamesTheRequester(t *testing.T) {
	f := newFixture(t)
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: rampproto.Ver,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:             "https://pub.example/a",
			DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_SEARCH.Enum(),
			Offers: []*rampv1.Offer{{
				OfferId:   "offer-1",
				Exchange:  "exchange.example",
				Signature: "deadbeef",
			}},
		}},
	}
	a := f.provision(t, "dev-one", acmeDetails)

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
		t.Fatalf("got %d offers, want 1", len(group.Offers))
	}
	offer := group.Offers[0]
	// snake_case, and the signature anchor present: the agent receives the
	// protocol's own encoding, which is what it must hand back unchanged.
	if offer["offer_id"] != "offer-1" {
		t.Errorf("offer_id = %v, want offer-1", offer["offer_id"])
	}
	if offer["signature"] != "deadbeef" {
		t.Errorf("signature = %v, want the offer's own signature carried through", offer["signature"])
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
		Ver: rampproto.Ver,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:           "https://pub.example/missing",
			AbsenceReason: &absence,
		}},
	}
	a := f.provision(t, "dev-one", acmeDetails)

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
func TestDiscover_BatchOfURIsKeepsOneGroupPerURI(t *testing.T) {
	f := newFixture(t)
	uris := []string{
		"https://pub.example/a",
		"https://pub.example/b",
		"https://pub.example/uncatalogued",
	}
	absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: rampproto.Ver,
		OfferGroups: []*rampv1.OfferGroup{
			{
				// The caller named these URLs, so a real Broker reports EXCHANGE
				// on every group of this response. Nothing here asserts the
				// method; it is set so the fixture does not describe a shape the
				// Broker cannot send.
				Uri:             uris[0],
				DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
				Offers: []*rampv1.Offer{
					{OfferId: "offer-a1", Exchange: "exchange.example", Signature: "sig-a1"},
					{OfferId: "offer-a2", Exchange: "exchange.example", Signature: "sig-a2"},
				},
			},
			{
				Uri:             uris[1],
				DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
				Offers:          []*rampv1.Offer{{OfferId: "offer-b1", Exchange: "other.example", Signature: "sig-b1"}},
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
	a := f.provision(t, "dev-one", acmeDetails)

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
	// The peers are httptest servers on loopback, which the SSRF guard blocks by
	// default. This is the same switch a local stack sets, not a test-only bypass.
	// The SDK guard is two independent flags: SKIP_SSRF drops the dial-time
	// address guard so the httptest loopback origin is reachable, and
	// ALLOW_INSECURE permits its plaintext http scheme.
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")

	f := newFixture(t)
	// The report is aimed at f.issuer — an Exchange this service is NOT configured
	// with. That is what makes the assertions below discriminating: routing by
	// configuration instead of by the offer would land on f.exchange, and the
	// "issuer saw it / home saw nothing" pair would both fail.
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: rampproto.Ver, ReportId: "rep-1"}
	a := f.provision(t, "dev-one", acmeDetails)

	out := callTool[reportResult](t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        hostOf(t, f.issuer.URL()),
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
	// The SDK guard is two independent flags: SKIP_SSRF drops the dial-time
	// address guard so the httptest loopback origin is reachable, and
	// ALLOW_INSECURE permits its plaintext http scheme.
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")

	f := newFixture(t)
	a := f.provision(t, "dev-one", acmeDetails)

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

// A RAMP-side refusal on the report leg must surface to the agent, and must not
// look like success.
func TestReport_RAMPRefusalSurfaces(t *testing.T) {
	// The SDK guard is two independent flags: SKIP_SSRF drops the dial-time
	// address guard so the httptest loopback origin is reachable, and
	// ALLOW_INSECURE permits its plaintext http scheme.
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")

	f := newFixture(t)
	f.issuer.failWith(connect.NewError(connect.CodeFailedPrecondition,
		errStub("usage report rejected")))
	a := f.provision(t, "dev-one", acmeDetails)

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        hostOf(t, f.issuer.URL()),
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
	a := f.provision(t, "dev-one", acmeDetails)

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

// A RAMP-side refusal on status must surface. status is the tool an agent calls
// to find out WHY something else was refused, so it silently reporting an empty
// account when the Exchange is unreachable would be actively misleading.
func TestStatus_RAMPRefusalSurfaces(t *testing.T) {
	f := newFixture(t)
	f.exchange.failWith(connect.NewError(connect.CodeUnavailable, errStub("exchange is down")))
	a := f.provision(t, "dev-one", acmeDetails)

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_status", nil)
	if !strings.Contains(msg, "ramp_status") {
		t.Errorf("tool error %q, want it to name the tool that failed", msg)
	}
	if !strings.Contains(msg, "exchange is down") {
		t.Errorf("tool error %q, want it to carry the Exchange's message", msg)
	}
}

// A bearer whose subject names a subdomain with no developer record must be
// refused BEFORE any Exchange call. Without this the registry would forward a
// RegisterRequest whose licensing fields are all empty strings — a blank legal
// entity recorded against a real agent.
func TestRegister_UnknownDeveloperIsRefusedBeforeAnyExchangeCall(t *testing.T) {
	f := newFixture(t)
	// A validly-signed, unexpired, correctly-audienced token for an agent that
	// never signed up.
	tok, err := f.tokens.Mint("never-signed-up."+baseZone, tokenTTL)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	msg := callToolErr(t, f.connect(t, tok), "ramp_register", nil)
	if !strings.Contains(msg, "sign up") {
		t.Errorf("tool error %q, want it to name the missing sign-up", msg)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("a blank registration reached the Exchange; it must be refused locally")
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
	// The SDK guard is two independent flags: SKIP_SSRF drops the dial-time
	// address guard so the httptest loopback origin is reachable, and
	// ALLOW_INSECURE permits its plaintext http scheme.
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")

	f := newFixture(t)
	f.exchange.registerResp = &rampv1.RegisterResponse{Ver: rampproto.Ver, BillingRef: "acct-1", Active: true}
	f.exchange.statusResp = &rampv1.GetAccountStatusResponse{Ver: rampproto.Ver, BillingRef: "acct-1", Active: true}
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: rampproto.Ver,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:             "https://pub.example/a",
			DiscoveryMethod: rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE.Enum(),
			Offers:          []*rampv1.Offer{{OfferId: "offer-1", Exchange: "exchange.example", Signature: "sig-1"}},
		}},
	}
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: rampproto.Ver, ReportId: "rep-1"}
	f.broker.relayResp = &rampv1.TransactionResponse{
		Ver: rampproto.Ver,
		Items: []*rampv1.TransactionResultItem{{
			OfferId: "offer-1", TransactionId: "tx-1",
			RetrievalEndpoint: strPtr("https://edge.example/d?sig=a"),
		}},
	}
	a := f.provision(t, "dev-one", acmeDetails)
	session := f.connect(t, a.Token)

	// Each entry returns the request_id its tool reported. The id the fixture's
	// session sends is what they must all echo.
	got := map[string]string{
		"ramp_register": callTool[accountResult](t, session, "ramp_register", nil).RequestID,
		"ramp_status":   callTool[accountResult](t, session, "ramp_status", nil).RequestID,
		"ramp_discover": callTool[discoverResult](t, session, "ramp_discover", map[string]any{
			"uris": []string{"https://pub.example/a"},
		}).RequestID,
		"ramp_execute": callTool[executeResult](t, session, "ramp_execute", map[string]any{
			"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
		}).RequestID,
		"ramp_report": callTool[reportResult](t, session, "ramp_report", map[string]any{
			"exchange":        hostOf(t, f.issuer.URL()),
			"transaction_id":  "tx-1",
			"idempotency_key": "idem-1",
		}).RequestID,
	}

	for tool, id := range got {
		if id == "" {
			t.Errorf("%s returned no request_id; every tool returns one", tool)
		}
	}
}

// --- result shapes and helpers ---

type accountResult struct {
	BillingRef string `json:"billing_ref"`
	Active     bool   `json:"active"`
	RequestID  string `json:"request_id"`
}

type discoverResult struct {
	OfferGroups []struct {
		URI string `json:"uri"`
		// Licensed is part of the wire contract deliberately (see offerGroup),
		// so the mirror carries it rather than re-deriving it from len(offers).
		Licensed        bool             `json:"licensed"`
		Offers          []map[string]any `json:"offers"`
		AbsenceReason   string           `json:"absence_reason"`
		DiscoveryMethod string           `json:"discovery_method"`
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
