//go:build integration

package mcp_test

import (
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// acmeFields is a registration payload matching the shared schema fixture: what
// an agent sends after reading an Exchange's published data_schema.
var acmeFields = map[string]any{
	"company_name":  "Acme GmbH",
	"billing_email": "billing@acme.example",
	"vat_id":        "DE123456789",
}

// TestRegister_SignsAsTheCallerAndSendsOnlyWhatTheAgentSupplied is the ticket's
// core property, driven end to end: a tool call authenticated by one developer's
// bearer leaves as a RAMP request signed by THAT developer's custodied key, to
// the Exchange the CALL named.
//
// The negative half is the change. The adapter used to read the developer's
// stored licensing details and forward them; it now fills in nothing, so the
// payload on the wire must be exactly the fields the agent passed and must NOT
// carry anything from our store.
func TestRegister_SignsAsTheCallerAndSendsOnlyWhatTheAgentSupplied(t *testing.T) {
	f := newFixture(t)
	f.exchange.setRegistration(testutil.FullRegistration)
	f.exchange.registerResp = &rampv1.RegisterResponse{
		Ver: helpers.ProtocolVersion, BillingRef: "acct-123", Active: true,
	}
	a := f.provision(t, "dev-one")

	out := callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   acmeFields,
	})

	if out.BillingRef != "acct-123" || !out.Active {
		t.Fatalf("register returned %+v, want billing_ref acct-123 and active", out)
	}
	if out.Exchange != f.exchange.Domain(t) {
		t.Errorf("output names %q, want the Exchange the call was addressed to %q",
			out.Exchange, f.exchange.Domain(t))
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
	sent := f.exchange.LastRegistration()
	for key, want := range acmeFields {
		if got, ok := sent[key]; !ok || got != want {
			t.Errorf("registration_data[%q] = %v, want %v", key, got, want)
		}
	}
	// What the developer store holds must NOT be here. The old form forwarded
	// legal_entity, address, jurisdiction_country, email and subdomain; the agent
	// sent none of them, so none may appear.
	for _, absent := range []string{"legal_entity", "address", "jurisdiction_country", "email", "subdomain"} {
		if _, present := sent[absent]; present {
			t.Errorf("registration_data carries %q, which the agent did not send — "+
				"the adapter must fill in nothing on its behalf", absent)
		}
	}
	if len(sent) != len(acmeFields) {
		t.Errorf("registration_data has %d members, want exactly the %d the agent sent: %v",
			len(sent), len(acmeFields), sent)
	}
	assertNoBearerLeaked(t, f.exchange, f.broker)
}

// TestRegister_EchoesThePublishedTermsDigest pins the terms record. The digest
// states WHICH terms document the operator accepted, and the request signature
// covers that statement — so a registration that echoed nothing, or echoed
// something the Exchange did not publish, would leave a dispute with only a
// timestamp to answer from.
func TestRegister_EchoesThePublishedTermsDigest(t *testing.T) {
	f := newFixture(t)
	f.exchange.setRegistration(testutil.FullRegistration)
	a := f.provision(t, "dev-one")

	callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   acmeFields,
	})

	got, present := f.exchange.LastTermsDigest()
	if !present {
		t.Fatal("the registration carried no terms_digest against an Exchange that publishes one")
	}
	if got != testutil.TermsDigest {
		t.Errorf("echoed %q, want the published %q", got, testutil.TermsDigest)
	}
}

// TestRegister_OmitsTheDigestWhenTheExchangePublishesNone is the companion. The
// protocol says an Exchange publishing no digest MUST ignore a value and MUST
// NOT record it as an acceptance, so sending one would be an unverifiable claim
// planted exactly where a verified one belongs.
func TestRegister_OmitsTheDigestWhenTheExchangePublishesNone(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   map[string]any{"anything": "at all"},
	})

	if got, present := f.exchange.LastTermsDigest(); present {
		t.Errorf("echoed terms_digest %q to an Exchange that publishes none", got)
	}
}

// TestRegister_NoPublishedSchemaPassesThePayloadThrough pins the pass-through
// state. An Exchange that publishes no schema asks for nothing in particular, so
// the pre-check is skipped and whatever the agent sent goes as it is — which is
// how every Exchange behaved before the block existed.
func TestRegister_NoPublishedSchemaPassesThePayloadThrough(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	fields := map[string]any{"whatever": "this exchange wants", "count": float64(3)}

	callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   fields,
	})

	sent := f.exchange.LastRegistration()
	if len(sent) != len(fields) {
		t.Fatalf("registration_data = %v, want the payload unchanged %v", sent, fields)
	}
	for key, want := range fields {
		if sent[key] != want {
			t.Errorf("registration_data[%q] = %v, want %v", key, sent[key], want)
		}
	}
}

// TestRegister_OmittedFieldsAreFineWhereNothingIsAsked pins the degenerate
// payload. An Exchange that publishes no schema asks for nothing in particular,
// so an agent that sends nothing has satisfied it — and every bound the payload
// passes through has to agree, from the SDK's size check to the protobuf
// conversion to the nil validator.
//
// Worth its own test because "nothing" is the value each of those could refuse
// separately, and the refusal would read as a protocol rule rather than as this
// adapter tripping over an absent argument.
func TestRegister_OmittedFieldsAreFineWhereNothingIsAsked(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	out := callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
	})

	if out.Exchange != f.exchange.Domain(t) {
		t.Fatalf("a registration with no fields was refused: %+v", out)
	}
	if sent := f.exchange.LastRegistration(); len(sent) != 0 {
		t.Errorf("registration_data = %v, want it empty", sent)
	}
}

// TestRegister_OmittedFieldsAreRefusedWhereMembersAreRequired is the companion.
// The same absent payload is a refusal at an Exchange that does ask, and the
// refusal names what to send.
func TestRegister_OmittedFieldsAreRefusedWhereMembersAreRequired(t *testing.T) {
	f := newFixture(t)
	f.exchange.setRegistration(testutil.FullRegistration)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
	})
	if msg == "" {
		t.Fatal("an empty payload was sent to an Exchange that requires members")
	}
	for _, want := range []string{"company_name", "billing_email"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name the missing member %q", msg, want)
		}
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("the empty payload was signed and sent anyway")
	}
}

// TestRegister_AtTwoExchangesReachesEachOne is what the whole ticket is for: one
// agent, one adapter, accounts at more than one Exchange, each call addressed
// and routed by the caller's own argument.
func TestRegister_AtTwoExchangesReachesEachOne(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	for _, peer := range []*rampPeer{f.exchange, f.issuer} {
		out := callTool[registerResult](t, session, "ramp_register", registerArgsAt(peer.Domain(t)))
		if out.Exchange != peer.Domain(t) {
			t.Errorf("output names %q, want %q", out.Exchange, peer.Domain(t))
		}
	}
	if len(f.exchange.Calls()) != 1 || len(f.issuer.Calls()) != 1 {
		t.Fatalf("calls landed %d/%d, want one at each Exchange",
			len(f.exchange.Calls()), len(f.issuer.Calls()))
	}
}

// TestRegister_TwoAgentsSignAsThemselves pins the property that makes the
// registry multi-tenant: one endpoint, one transport, but each caller's request
// signed with its OWN key. A regression that bound one key at construction — or
// cached the first caller's — would still pass every single-agent test and fail
// here.
func TestRegister_TwoAgentsSignAsThemselves(t *testing.T) {
	f := newFixture(t)
	first := f.provision(t, "dev-one")
	second := f.provision(t, "dev-two")
	if first.Thumbprint == second.Thumbprint {
		t.Fatal("the two agents share a key; the fixture cannot tell them apart")
	}
	args := registerArgs(t, f)

	callTool[registerResult](t, f.connect(t, first.Token), "ramp_register", args)
	callTool[registerResult](t, f.connect(t, second.Token), "ramp_register", args)

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

// TestStatus_AsksTheNamedExchangeAndMarksTheAnswerAuthoritative drives the
// per-Exchange mode. Its request carries no identifying field beyond the
// recipient, so the signature is the only thing telling the Exchange whose
// status to answer with.
func TestStatus_AsksTheNamedExchangeAndMarksTheAnswerAuthoritative(t *testing.T) {
	f := newFixture(t)
	f.exchange.statusResp = &rampv1.GetAccountStatusResponse{
		Ver: helpers.ProtocolVersion, BillingRef: "acct-123", Active: false,
	}
	a := f.provision(t, "dev-one")

	out := callTool[statusResult](t, f.connect(t, a.Token), "ramp_status", map[string]any{
		"exchange": f.exchange.Domain(t),
	})

	if len(out.Accounts) != 1 {
		t.Fatalf("status returned %d entries for one named Exchange, want 1", len(out.Accounts))
	}
	entry := out.Accounts[0]
	if entry.Source != "exchange" {
		t.Errorf("source = %q, want the authoritative marker", entry.Source)
	}
	if !entry.Registered {
		t.Error("registered = false for an account the Exchange reported")
	}
	if entry.BillingRef != "acct-123" {
		t.Errorf("billing_ref = %q, want acct-123", entry.BillingRef)
	}
	if entry.Active == nil || *entry.Active {
		t.Errorf("active = %v, want the inactive account the Exchange reported", entry.Active)
	}
	assertComparableStamp(t, "the authoritative entry", entry.AsOf)
	if call := onlyCall(t, f.exchange); call.KeyID != a.Thumbprint {
		t.Errorf("signed with %q, want the caller's key %q", call.KeyID, a.Thumbprint)
	}
}

// TestStatus_ReportsNoAccountAtAnExchangeThatHasNone pins that "no account here"
// is an ANSWER. An agent asking where it still needs to register must be able to
// get that without catching an error, which is the whole reason the registered
// flag exists.
func TestStatus_ReportsNoAccountAtAnExchangeThatHasNone(t *testing.T) {
	f := newFixture(t)
	f.exchange.failWith(connect.NewError(connect.CodeNotFound,
		errStub("not registered for paid content yet")))
	a := f.provision(t, "dev-one")

	out := callTool[statusResult](t, f.connect(t, a.Token), "ramp_status", map[string]any{
		"exchange": f.exchange.Domain(t),
	})

	if len(out.Accounts) != 1 {
		t.Fatalf("status returned %d entries, want 1", len(out.Accounts))
	}
	entry := out.Accounts[0]
	if entry.Registered {
		t.Error("registered = true at an Exchange that has no account")
	}
	if entry.Source != "exchange" {
		t.Errorf("source = %q, want the authoritative marker — the Exchange did answer", entry.Source)
	}
	// Null rather than false: nobody said the account is suspended, they said
	// there is no account.
	if entry.Active != nil {
		t.Errorf("active = %v, want null where there is no account to be active", *entry.Active)
	}
	if entry.BillingRef != "" {
		t.Errorf("billing_ref = %q, want none", entry.BillingRef)
	}
}

// TestStatus_WithoutAnExchangeListsLocalHints drives the second mode. It reads
// the local note and must make NO network call at all — which is asserted on the
// peers' raw HTTP counters, not only their RPC counters, because a manifest read
// is an HTTP request that never becomes an RPC.
func TestStatus_WithoutAnExchangeListsLocalHints(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	for _, peer := range []*rampPeer{f.exchange, f.issuer} {
		callTool[registerResult](t, session, "ramp_register", registerArgsAt(peer.Domain(t)))
	}
	beforeExchange, beforeIssuer := f.exchange.HTTPRequests(), f.issuer.HTTPRequests()

	out := callTool[statusResult](t, session, "ramp_status", nil)

	if len(out.Accounts) != 2 {
		t.Fatalf("status returned %d hints after two registrations, want 2: %+v",
			len(out.Accounts), out.Accounts)
	}
	named := map[string]bool{}
	for _, entry := range out.Accounts {
		named[entry.Exchange] = true
		if entry.Source != "local_hint" {
			t.Errorf("entry for %s is marked %q, want the hint marker", entry.Exchange, entry.Source)
		}
		if entry.Active != nil {
			t.Errorf("entry for %s reports active = %v; a hint asked nobody", entry.Exchange, *entry.Active)
		}
		if entry.BillingRef != "" {
			t.Errorf("entry for %s carries a billing_ref; a hint holds no account handle", entry.Exchange)
		}
		assertComparableStamp(t, "the hint for "+entry.Exchange, entry.AsOf)
	}
	for _, want := range []string{f.exchange.Domain(t), f.issuer.Domain(t)} {
		if !named[want] {
			t.Errorf("hints do not name %s", want)
		}
	}
	if f.exchange.HTTPRequests() != beforeExchange || f.issuer.HTTPRequests() != beforeIssuer {
		t.Error("the hint list made a network call; this mode answers from a local note alone")
	}
}

// TestStatus_BothModesReturnTheSameShape is the "one schema, no branching"
// property. It decodes both answers into ONE type and compares the member sets
// the wire actually carried — two decode types here would let the shapes drift
// and every other test would still pass.
func TestStatus_BothModesReturnTheSameShape(t *testing.T) {
	f := newFixture(t)
	f.exchange.statusResp = &rampv1.GetAccountStatusResponse{
		Ver: helpers.ProtocolVersion, BillingRef: "acct-123", Active: true,
	}
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	callTool[registerResult](t, session, "ramp_register", registerArgs(t, f))

	// Decoded LOOSELY — into maps rather than into the typed shape — because the
	// property is about what the wire carries. A typed decode silently drops a
	// member the other mode does not send, which is exactly the drift under test.
	named := onlyEntry(t, callTool[looseStatus](t, session, "ramp_status",
		map[string]any{"exchange": f.exchange.Domain(t)}))
	hints := onlyEntry(t, callTool[looseStatus](t, session, "ramp_status", nil))

	if got, want := memberNames(named), memberNames(hints); !slices.Equal(got, want) {
		t.Errorf("the two modes carry different members:\n  exchange: %v\n  hint:     %v", got, want)
	}
	if named["source"] == hints["source"] {
		t.Errorf("both modes marked their entry %v; the marker is what tells them apart", named["source"])
	}
	// The tool description says status does not report registration
	// requirements, and that is a claim rather than an observation. It is
	// structurally true today because no member of the output could carry one,
	// so what this pins is that no member starts to.
	for _, member := range memberNames(named) {
		if strings.Contains(member, "schema") || strings.Contains(member, "terms") ||
			strings.Contains(member, "requirement") {
			t.Errorf("status carries %q; it reports account state and the tool "+
				"description says it reports nothing about what an Exchange requires", member)
		}
	}
}

// looseStatus decodes a status answer without imposing a shape on its entries,
// so a member present in one mode and absent in the other is visible rather than
// quietly dropped.
type looseStatus struct {
	Accounts []map[string]any `json:"accounts"`
}

// onlyEntry returns the single entry an answer carries, failing otherwise.
func onlyEntry(t *testing.T, out looseStatus) map[string]any {
	t.Helper()
	if len(out.Accounts) != 1 {
		t.Fatalf("answer carries %d entries, want exactly 1: %+v", len(out.Accounts), out.Accounts)
	}
	return out.Accounts[0]
}

// memberNames is an entry's member names, sorted, for comparing two shapes.
func memberNames(entry map[string]any) []string {
	names := make([]string, 0, len(entry))
	for name := range entry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TestStatus_ForgetsAHintTheExchangeContradicts pins the correction path. A note
// the authority has just said is wrong is known-false rather than merely stale,
// and leaving it would have the no-argument mode keep listing an account that
// does not exist.
func TestStatus_ForgetsAHintTheExchangeContradicts(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	callTool[registerResult](t, session, "ramp_register", registerArgs(t, f))
	if got := callTool[statusResult](t, session, "ramp_status", nil); len(got.Accounts) != 1 {
		t.Fatalf("the registration left %d hints, want 1", len(got.Accounts))
	}

	// The operator closes the account at the Exchange. Nothing tells the adapter.
	f.exchange.failWith(connect.NewError(connect.CodeNotFound, errStub("no account")))
	callTool[statusResult](t, session, "ramp_status", map[string]any{
		"exchange": f.exchange.Domain(t),
	})

	if got := callTool[statusResult](t, session, "ramp_status", nil); len(got.Accounts) != 0 {
		t.Errorf("the hint survived a contradiction from the Exchange: %+v", got.Accounts)
	}
}

// TestStatus_RecordsAHintForARegistrationMadeElsewhere is the other direction of
// the correction path, and the only way a hint can appear for an account this
// adapter did not open.
//
// An agent can register at an Exchange through some other client, or an operator
// can create the account by hand. The note-backed list would never mention it,
// so a confirmed status answer writes the note. Without this, the pair is
// half-tested: the suite proves a contradicted hint is dropped and proves
// nothing about a confirmed one appearing.
func TestStatus_RecordsAHintForARegistrationMadeElsewhere(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	// This agent has never called ramp_register, so there is no note to refresh.
	if got := callTool[statusResult](t, session, "ramp_status", nil); len(got.Accounts) != 0 {
		t.Fatalf("a fresh agent already has %d hints: %+v", len(got.Accounts), got.Accounts)
	}

	// The Exchange confirms an account it knows about and this adapter does not.
	named := callTool[statusResult](t, session, "ramp_status", map[string]any{
		"exchange": f.exchange.Domain(t),
	})
	if len(named.Accounts) != 1 || !named.Accounts[0].Registered {
		t.Fatalf("the Exchange's answer did not report an account: %+v", named.Accounts)
	}

	hints := callTool[statusResult](t, session, "ramp_status", nil)
	if len(hints.Accounts) != 1 {
		t.Fatalf("the confirmed account left %d hints, want 1: %+v", len(hints.Accounts), hints.Accounts)
	}
	if got := hints.Accounts[0].Exchange; got != f.exchange.Domain(t) {
		t.Errorf("the hint names %q, want the Exchange that confirmed the account", got)
	}
	if got := hints.Accounts[0].Source; got != "local_hint" {
		t.Errorf("the recorded entry is marked %q, want the hint marker", got)
	}
}

// TestStatus_AnAgentWithNoRegistrationsGetsAnEmptyList pins that having
// registered nowhere is an answer. It is the state every agent starts in, so an
// error there would make the tool unusable exactly when it is most useful.
func TestStatus_AnAgentWithNoRegistrationsGetsAnEmptyList(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	out := callTool[statusResult](t, f.connect(t, a.Token), "ramp_status", nil)
	if len(out.Accounts) != 0 {
		t.Fatalf("a fresh agent has %d hints, want none", len(out.Accounts))
	}
}

// TestStatus_RAMPRefusalSurfaces keeps the case the old suite pinned: a genuine
// refusal is still a failure. status is the tool an agent calls to find out WHY
// something else was refused, so reporting an empty account when the Exchange is
// unreachable would be actively misleading.
func TestStatus_RAMPRefusalSurfaces(t *testing.T) {
	f := newFixture(t)
	f.exchange.failWith(connect.NewError(connect.CodeUnavailable, errStub("exchange is down")))
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_status", map[string]any{
		"exchange": f.exchange.Domain(t),
	})
	if !strings.Contains(msg, "ramp_status") {
		t.Errorf("tool error %q, want it to name the tool that failed", msg)
	}
	if !strings.Contains(msg, "exchange is down") {
		t.Errorf("tool error %q, want it to carry the Exchange's message", msg)
	}
}

// The note store's own failures. Three production paths decide what an agent is
// told when this service's local record cannot be read or written, and each one
// answers differently on purpose. Driving them needs a real store outage, which
// closing the service's pool produces: on the two account legs nothing else is
// behind that pool — the bearer is a signed token and the signing key comes from
// Vault — so what fails is exactly the note reads and writes.

// TestStatus_WithoutAnExchangeFailsWhenTheNoteStoreCannotAnswer is the one path
// where a note failure IS the answer.
//
// This mode has nothing but the local record to report, so an empty list would
// be a wrong answer rather than a degraded one. The agent gets a sentence naming
// what it can do instead, and the operator gets the cause on the same
// call_failed event every other failure of this surface produces — same level,
// same op field — so one query covers the whole surface.
func TestStatus_WithoutAnExchangeFailsWhenTheNoteStoreCannotAnswer(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	callTool[registerResult](t, session, "ramp_register", registerArgs(t, f))

	f.pool.Close()

	msg := callToolErr(t, session, "ramp_status", nil)
	if msg == "" {
		t.Fatal("the hint list answered with the note store down; an empty list would be a wrong answer")
	}
	if !strings.Contains(msg, "ask about one Exchange by name") {
		t.Errorf("error %q does not tell the agent what it can do instead", msg)
	}
	lines := f.logs.Find("identity.mcp.call_failed")
	if len(lines) != 1 {
		t.Fatalf("the note-store failure produced %d call_failed lines, want 1: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], `"op":"ramp_status"`) {
		t.Errorf("line %s does not carry the op an operator filters on", lines[0])
	}
}

// TestRegister_SucceedsWhenTheNoteCannotBeRecorded is the opposite disposition,
// and the one that would be most damaging to get wrong.
//
// The Exchange has already accepted the registration by the time the note is
// written. Failing the call here would tell the agent its registration did not
// happen when it did, and the only thing actually lost is a hint the next status
// call rebuilds. So the failure is logged and the call succeeds — and the log
// line is named for the STORE rather than for either tool, because this same
// write happens on the status path too.
func TestRegister_SucceedsWhenTheNoteCannotBeRecorded(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	f.pool.Close()

	out := callTool[registerResult](t, session, "ramp_register", registerArgs(t, f))
	if out.Exchange != f.exchange.Domain(t) {
		t.Fatalf("a registration the Exchange accepted was reported as failed: %+v", out)
	}
	if lines := f.logs.Find("identity.mcp.notes.record_failed"); len(lines) != 1 {
		t.Fatalf("the unrecorded note produced %d lines, want 1: %v", len(lines), lines)
	}
	if lines := f.logs.Find("identity.mcp.call_failed"); len(lines) != 0 {
		t.Errorf("the call was reported as failed: %v", lines)
	}
	// The authoritative mode still answers: it asks the Exchange and never reads
	// the note store to produce its entry.
	got := callTool[statusResult](t, session, "ramp_status",
		map[string]any{"exchange": f.exchange.Domain(t)})
	if len(got.Accounts) != 1 || !got.Accounts[0].Registered {
		t.Errorf("the per-Exchange answer degraded with the note store down: %+v", got.Accounts)
	}
}

// TestStatus_SucceedsWhenAContradictedNoteCannotBeForgotten is the third path,
// and it has the same disposition as recording for the same reason: the answer
// the caller asked for is already in hand.
//
// The Exchange says there is no account, which makes the local note known-false.
// Dropping it is bookkeeping beside an answer, so a store that will not take the
// delete is logged and the caller still gets the Exchange's answer.
func TestStatus_SucceedsWhenAContradictedNoteCannotBeForgotten(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	callTool[registerResult](t, session, "ramp_register", registerArgs(t, f))
	f.exchange.failWith(connect.NewError(connect.CodeNotFound,
		errStub("not registered for paid content yet")))

	f.pool.Close()

	out := callTool[statusResult](t, session, "ramp_status",
		map[string]any{"exchange": f.exchange.Domain(t)})
	if len(out.Accounts) != 1 || out.Accounts[0].Registered {
		t.Fatalf("the Exchange's answer was lost with the note store down: %+v", out.Accounts)
	}
	if lines := f.logs.Find("identity.mcp.notes.forget_failed"); len(lines) != 1 {
		t.Fatalf("the undeleted note produced %d lines, want 1: %v", len(lines), lines)
	}
	if lines := f.logs.Find("identity.mcp.call_failed"); len(lines) != 0 {
		t.Errorf("the call was reported as failed: %v", lines)
	}
}

// TestStatus_HintsAreScopedToTheCallingAgent is the isolation property of the
// new per-agent table, driven through the tool rather than through the query.
//
// The repository-level test covers the SQL predicate, but it calls Record and
// List directly, so it cannot see the tool layer or the service passing the
// wrong subdomain — a handler reading it from somewhere other than the verified
// bearer, for instance. With one agent in the fixture nothing would notice.
// What leaks under that mistake is which Exchanges another operator does
// business with, which is the only sensitive thing this table holds.
func TestStatus_HintsAreScopedToTheCallingAgent(t *testing.T) {
	f := newFixture(t)
	one := f.provision(t, "dev-one")
	two := f.provision(t, "dev-two")
	sessionOne, sessionTwo := f.connect(t, one.Token), f.connect(t, two.Token)

	callTool[registerResult](t, sessionOne, "ramp_register", registerArgs(t, f))
	callTool[registerResult](t, sessionTwo, "ramp_register", registerArgsAt(f.issuer.Domain(t)))

	for _, tc := range []struct {
		who      string
		session  *mcpsdk.ClientSession
		exchange string
	}{
		{"dev-one", sessionOne, f.exchange.Domain(t)},
		{"dev-two", sessionTwo, f.issuer.Domain(t)},
	} {
		out := callTool[statusResult](t, tc.session, "ramp_status", nil)
		if len(out.Accounts) != 1 {
			t.Fatalf("%s sees %d hints, want only its own: %+v", tc.who, len(out.Accounts), out.Accounts)
		}
		if out.Accounts[0].Exchange != tc.exchange {
			t.Errorf("%s sees a hint for %s, want %s — an agent must not learn where another "+
				"agent does business", tc.who, out.Accounts[0].Exchange, tc.exchange)
		}
	}
}

// assertComparableStamp holds an as_of to the contract the field's own comment
// states: RFC 3339 in UTC, so two entries from different sources are directly
// comparable.
//
// Asserting only that the string is non-empty leaves that contract untested. The
// renderer could format a different layout, or stop converting to UTC so entries
// carry the local offset, and every assertion would still pass while the entries
// stopped being comparable — which is the exact failure the format exists to
// prevent. Both modes are checked, because they are two renderings an agent puts
// side by side.
func assertComparableStamp(t *testing.T, where, asOf string) {
	t.Helper()
	if asOf == "" {
		t.Errorf("%s has no as_of; an entry is only useful with its age", where)
		return
	}
	at, err := time.Parse(time.RFC3339, asOf)
	if err != nil {
		t.Errorf("%s carries as_of %q, which is not RFC 3339: %v", where, asOf, err)
		return
	}
	if _, offset := at.Zone(); offset != 0 {
		t.Errorf("%s carries as_of %q, which is offset %ds from UTC; entries from two "+
			"sources are only directly comparable in one zone", where, asOf, offset)
	}
}
