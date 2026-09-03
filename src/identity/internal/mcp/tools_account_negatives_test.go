//go:build integration

package mcp_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
)

// Every case here asserts the refusal AND the absence of the side effect. "The
// tool returned an error" is half a claim: the half that matters is that nothing
// was fetched, nothing was signed, and nothing was sent.

// The cases come from the shared table the report leg and the allowlist parser
// also drive, so a rule that started admitting one of these on one surface and
// not another shows up in three places rather than one.
//
// An empty exchange is not in that table and is not this rule: it is a MISSING
// argument, refused by the schema before ramp_register's handler runs, and the
// note-backed mode on ramp_status.
func TestAccountTools_RefuseADomainThatIsNotBare(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	for _, tc := range testutil.NonBareDomains {
		t.Run(tc.Name, func(t *testing.T) {
			domain := tc.Of("exchange.example")
			msg := callToolErr(t, session, "ramp_register", registerArgsAt(domain))
			if msg == "" {
				t.Fatalf("ramp_register accepted %q", domain)
			}
			if !strings.Contains(msg, "bare domain") {
				t.Errorf("error %q does not say the value must be a bare domain", msg)
			}
			if msg = callToolErr(t, session, "ramp_status", map[string]any{"exchange": domain}); msg == "" {
				t.Fatalf("ramp_status accepted %q", domain)
			}
		})
	}
	// Nothing was fetched and nothing was sent, on either peer, for any of them.
	if f.exchange.HTTPRequests() != 0 || f.issuer.HTTPRequests() != 0 {
		t.Errorf("a malformed domain still produced traffic: %d/%d requests",
			f.exchange.HTTPRequests(), f.issuer.HTTPRequests())
	}
}

// TestAccountTools_RefuseAnExchangeOutsideTheAllowlist drives the policy on the
// two tools it was added for. The refusal must precede the manifest read, which
// is the fetch the endpoint resolver's own overlay never sees.
func TestAccountTools_RefuseAnExchangeOutsideTheAllowlist(t *testing.T) {
	f := newBoundedFixture(t, func(cfg *app.MCPConfig, p peerSet) {
		cfg.ExchangeAllowlist = p.issuer.Domain(t)
	})
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	// Written out rather than through registerArgs, because the contrast is the
	// point: the allowlist above names the issuer peer and this registers at the
	// exchange peer. The wrapper would hide which of the two is being named.
	msg := callToolErr(t, session, "ramp_register", registerArgsAt(f.exchange.Domain(t)))
	if msg == "" {
		t.Fatal("ramp_register reached an Exchange outside the allowlist")
	}
	if !strings.Contains(msg, f.exchange.Domain(t)) {
		t.Errorf("error %q does not name the domain it refused", msg)
	}
	if callToolErr(t, session, "ramp_status", map[string]any{"exchange": f.exchange.Domain(t)}) == "" {
		t.Fatal("ramp_status reached an Exchange outside the allowlist")
	}
	if got := f.exchange.HTTPRequests(); got != 0 {
		t.Errorf("the excluded Exchange saw %d requests, want none — not even the manifest read", got)
	}

	// A listed Exchange still works, so the lever confines rather than blocks.
	out := callTool[registerResult](t, session, "ramp_register", registerArgsAt(f.issuer.Domain(t)))
	if out.Exchange != f.issuer.Domain(t) {
		t.Fatalf("a listed Exchange was refused: %+v", out)
	}
}

// TestRegister_RefusesAManifestAdvertisingAnotherHost pins the same-host rule on
// the account leg. An Exchange whose manifest names somebody else's endpoint
// would otherwise have a signed registration — the operator's business details —
// delivered to that somebody else.
func TestRegister_RefusesAManifestAdvertisingAnotherHost(t *testing.T) {
	f := newFixture(t)
	f.exchange.setManifestEndpoint(f.issuer.URL())
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgsAt(f.exchange.Domain(t)))
	if msg == "" {
		t.Fatal("a registration followed a manifest pointing at another host")
	}
	// The same TOKEN the report leg carries for the same refusal. Both legs route
	// through one endpoint resolver, so an Exchange advertising somebody else's
	// host is one condition; an operator alert keyed on the token has to fire on
	// whichever tool met it. Asserted on the token rather than on the sentence
	// because the words are the SDK's and a rewording upstream would turn a prose
	// assertion red for no behavioural reason.
	if !strings.Contains(msg, "not_sent") {
		t.Errorf("tool error %q, want it to carry the not_sent class the report leg uses", msg)
	}
	if len(f.issuer.Calls()) != 0 {
		t.Errorf("the redirected-to host received %d calls", len(f.issuer.Calls()))
	}
	if len(f.exchange.Calls()) != 0 {
		t.Errorf("the named Exchange received %d calls", len(f.exchange.Calls()))
	}
}

// TestRegister_RefusesAPayloadThePublishedSchemaRejects is the pre-check. The
// error must name every member that is wrong, because that is what turns a
// refusal into something the agent can act on in one retry.
func TestRegister_RefusesAPayloadThePublishedSchemaRejects(t *testing.T) {
	f := newFixture(t)
	f.exchange.setRegistration(testutil.FullRegistration)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   map[string]any{"vat_id": "DE123456789"},
	})
	if msg == "" {
		t.Fatal("a payload missing every required member was sent")
	}
	for _, want := range []string{"company_name", "billing_email"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name the missing member %q", msg, want)
		}
	}
	// It points the agent at where the requirements are published, which is the
	// tool description's claim and has to be true in the error too.
	if !strings.Contains(msg, "account_registration.data_schema") {
		t.Errorf("error %q does not say where the required shape is published", msg)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("the refused payload was signed and sent anyway")
	}
}

// TestRegister_SurfacesTheExchangesOwnFieldErrors pins the "same clear form"
// half. The adapter's pre-check and the Exchange's own check are the same
// problem with the same remedy, so an agent must not be told which members are
// wrong by one and only "invalid registration data" by the other.
//
// Driven with a synthetic refusal rather than a real Exchange, and that is
// stated rather than hidden. An Exchange that publishes a schema does enforce
// it, but this adapter pre-checks against the same schema before it signs, so a
// non-conforming payload is normally stopped here and the remote refusal is the
// rarer path — reached when the agent's cached copy of the schema is older than
// the one the Exchange now publishes. A stub peer reaches it on demand; the
// Exchange's own gate is covered by its Connect integration suite.
func TestRegister_SurfacesTheExchangesOwnFieldErrors(t *testing.T) {
	f := newFixture(t)
	refusal := connect.NewError(connect.CodeInvalidArgument, errStub("registration data is not acceptable"))
	refusal.AddDetail(mustDetail(t, helpers.RegistrationFailureDetail(
		"exchange.example", "registration data is not acceptable",
		rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
		&rampv1.RegistrationFieldError{Path: "/vat_id", Error: "does not match pattern"},
		&rampv1.RegistrationFieldError{Path: "/billing_email", Error: "is required"},
	)))
	f.exchange.failWith(refusal)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))
	if msg == "" {
		t.Fatal("a refused registration reported success")
	}
	// The typed reason survives: it is what an agent branches on.
	if !strings.Contains(msg, "REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA") {
		t.Errorf("error %q dropped the typed reason", msg)
	}
	// And so do the members, in the same shape the local pre-check uses.
	for _, want := range []string{"/vat_id", "does not match pattern", "/billing_email", "is required"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not carry %q from the Exchange's refusal", msg, want)
		}
	}
	// And the pointer to where the requirements are published — the half that
	// makes the remedy identical. The sibling pre-check test asserts it and this
	// one did not, which is how the two renderings came to disagree while both
	// tests passed: an agent refused by the Exchange was told which members were
	// wrong and never where to read the shape they must match.
	if !strings.Contains(msg, "account_registration.data_schema") {
		t.Errorf("error %q does not say where the required shape is published, so a "+
			"refusal from the Exchange offers a different remedy from the identical "+
			"refusal from the pre-check", msg)
	}
}

// TestRegister_ARefusalWithNoFieldsReadsAsBefore is the companion: a refusal
// that named no members must not grow an empty list on the end.
func TestRegister_ARefusalWithNoFieldsReadsAsBefore(t *testing.T) {
	f := newFixture(t)
	f.exchange.failWith(connect.NewError(connect.CodePermissionDenied, errStub("agent is not permitted")))
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))
	if !strings.Contains(msg, "not permitted") {
		t.Errorf("error %q dropped the Exchange's message", msg)
	}
	if strings.HasSuffix(strings.TrimSpace(msg), "—") {
		t.Errorf("error %q ends in a dangling separator; a refusal naming no members adds nothing", msg)
	}
}

// TestRegister_ReadsTheManifestFreshEveryTime is the protocol's freshness rule
// at the tool surface, and the reason the ticket's "refetch once on a pre-check
// failure" is not implemented as a special case.
//
// A cached schema would refuse a payload the Exchange has since started
// accepting, and a cached terms digest would echo a value it has stopped
// accepting. Reading fresh on every register makes both impossible rather than
// recoverable.
//
// Counted over two REFUSED registers on purpose. A refusal stops before the
// request is routed, so the only manifest read in each is the requirements read
// — which is what makes "exactly two" an exact claim. A register that succeeds
// reads the manifest a second time through the endpoint resolver, whose own
// cache is a separate, deliberately longer-lived thing.
func TestRegister_ReadsTheManifestFreshEveryTime(t *testing.T) {
	f := newFixture(t)
	f.exchange.setRegistration(testutil.FullRegistration)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	args := map[string]any{"exchange": f.exchange.Domain(t), "fields": map[string]any{"vat_id": "DE1"}}

	for attempt := 1; attempt <= 2; attempt++ {
		if callToolErr(t, session, "ramp_register", args) == "" {
			t.Fatalf("attempt %d was accepted against the published schema", attempt)
		}
		if got := f.exchange.ManifestFetches(); got != attempt {
			t.Fatalf("after %d refused registers the manifest was read %d times, want %d — "+
				"a cached schema is what this rule forbids", attempt, got, attempt)
		}
	}

	// The Exchange relaxes what it asks for. Nothing tells the adapter, and the
	// same payload must now go through — which is what says the refusals above
	// were the published schema's answer and not a stale local copy's.
	f.exchange.setRegistration(rwtestutil.Registration{
		DataSchemaJSON: `{"$schema":"https://json-schema.org/draft/2020-12/schema",` +
			`"type":"object","required":["vat_id"],"properties":{"vat_id":{"type":"string"}}}`,
		TermsURI:    testutil.TermsURI,
		TermsDigest: testutil.TermsDigest,
	})

	out := callTool[registerResult](t, session, "ramp_register", args)
	if out.Exchange != f.exchange.Domain(t) {
		t.Fatalf("the same payload was still refused after the Exchange relaxed its schema: %+v", out)
	}
}

// TestRegister_AnUnusableSchemaDoesNotBlockTheRegistration pins that a local
// check which cannot run does not become a local veto. The Exchange's own check
// is the deciding one; refusing here would block a registration it would have
// accepted, with no way for the agent past it.
func TestRegister_AnUnusableSchemaDoesNotBlockTheRegistration(t *testing.T) {
	// A reference leaving the document: the one refusal that describes an attack
	// rather than a mistake, and the one a client must never follow. Taken from
	// the shared table rather than written out, so its verdict token and the
	// bytes that produce it stay one pair — the layer below drives that same
	// table, and a copy here could name a verdict the loader no longer gives.
	unusable := unusableSchema(t, "remote_ref")
	f := newFixture(t)
	f.exchange.setRegistration(rwtestutil.Registration{DataSchemaJSON: unusable.Raw})
	a := f.provision(t, "dev-one")

	out := callTool[registerResult](t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))
	if out.Exchange != f.exchange.Domain(t) {
		t.Fatalf("an unusable published schema blocked the registration: %+v", out)
	}
	if len(f.exchange.Calls()) != 1 {
		t.Fatalf("the Exchange saw %d calls, want the registration to have reached it",
			len(f.exchange.Calls()))
	}
	// The operator is told the pre-check was skipped, with the verdict that
	// explains why. An agent gets no say in it, so the log is the only record.
	lines := f.logs.Find("identity.mcp.register.schema_unusable")
	if len(lines) != 1 {
		t.Fatalf("got %d schema_unusable lines, want 1: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], unusable.Verdict) {
		t.Errorf("log line %s does not carry the verdict that named the refusal", lines[0])
	}
}

// unusableSchema picks one row of the shared refusal table by its verdict.
//
// It fails rather than returning a zero value when the verdict is gone, so a row
// removed upstream surfaces here as "this case no longer exists" instead of as a
// test quietly driving an empty schema.
func unusableSchema(t *testing.T, verdict string) testutil.UnusableSchema {
	t.Helper()
	for _, row := range testutil.UnusableSchemas {
		if row.Verdict == verdict {
			return row
		}
	}
	t.Fatalf("no %q row in the shared unusable-schema table", verdict)
	return testutil.UnusableSchemas[0]
}

// TestRegister_NeverLogsTheSubmittedFields is the privacy rule under test, on
// both paths. The fields are the operator's business details — legal entity,
// billing contact, tax identifiers — and this adapter passes them through
// without logging or storing them.
//
// Driven with a sentinel rather than by reading the code, because the failure
// this guards against is a helpful "err" or "payload" attribute added to a log
// line months from now, which no structural rule over today's source can see.
func TestRegister_NeverLogsTheSubmittedFields(t *testing.T) {
	const sentinel = "Zolvath-Kreznik-Partnership-8817"
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	args := map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   map[string]any{"company_name": sentinel, "vat_id": "DE" + sentinel},
	}

	// The success path.
	callTool[registerResult](t, session, "ramp_register", args)
	assertUnlogged(t, f, sentinel, "a successful registration")

	// And the failure path, which is where a naive fix leaks: the refusal handler
	// records the whole cause for the operator.
	f.exchange.failWith(errStub("the Exchange said no"))
	callToolErr(t, session, "ramp_register", args)
	assertUnlogged(t, f, sentinel, "a refused registration")
}

// TestStatus_HintsCarryNothingFromTheSubmittedFields is the persistence half of
// the same rule, observed through the public read surface.
//
// A persistence round-trip, not a protocol one: the write goes tool → adapter →
// repository → database, and the read comes back through the tool that is the
// only public reader of that record. Nothing here reaches past a layer.
func TestStatus_HintsCarryNothingFromTheSubmittedFields(t *testing.T) {
	const sentinel = "Zolvath-Kreznik-Partnership-8817"
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	callTool[registerResult](t, session, "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   map[string]any{"company_name": sentinel},
	})

	hints := callTool[looseStatus](t, session, "ramp_status", nil)
	if len(hints.Accounts) != 1 {
		t.Fatalf("the registration left %d hints, want 1", len(hints.Accounts))
	}
	for member, value := range hints.Accounts[0] {
		if text, ok := value.(string); ok && strings.Contains(text, sentinel) {
			t.Errorf("hint member %q carries the submitted registration data: %q", member, text)
		}
	}
}

// TestRegister_BoundsAnExchangeThatEchoesThePayloadBack drives the case the
// peer-text bound exists for, which no other test in this package reaches.
//
// Every other staged refusal uses a short fixed message such as "the Exchange
// said no", so the bound never fires and removing it changes nothing any of them
// observe. This one stages an Exchange that quotes the whole submitted payload
// into its refusal — the outcome the payload-privacy rule exists to prevent, and
// the one thing the bound genuinely removes.
//
// Three properties, and each fails on its own if the bound is weakened. The
// sentinel placed past the cut must not reach a log line. The truncation marker
// must be present, so deleting boundPeerCause or raising maxPeerText fails here
// rather than passing quietly. And the agent must still get the message,
// because the peer's sentence is usually the only account of why a registration
// was refused.
func TestRegister_BoundsAnExchangeThatEchoesThePayloadBack(t *testing.T) {
	const head = "refused, you sent: "
	// Far past the bound, so no prefix length this rendering happens to have can
	// leave it inside the budget. The bound itself is maxPeerText, which this
	// external test package cannot name; the internal test beside it drives the
	// exact offset.
	const tail = "Zolvath-Kreznik-Partnership-8817"
	echo := head + strings.Repeat("x", 4096) + tail

	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	f.exchange.failWith(errStub(echo))

	msg := callToolErr(t, session, "ramp_register", registerArgs(t, f))
	if !strings.Contains(msg, head) {
		t.Errorf("the agent was told %q, which drops the peer's own account of the "+
			"refusal — the bound is for the operator line, not for the answer", msg)
	}

	lines := f.logs.Find("identity.mcp.call_failed")
	if len(lines) != 1 {
		t.Fatalf("got %d call_failed lines, want 1: %v", len(lines), lines)
	}
	line := lines[0]
	if strings.Contains(line, tail) {
		t.Errorf("the operator line carries text from past the cut: %s", line)
	}
	if !strings.Contains(line, "truncated") {
		t.Errorf("the operator line is not marked as cut, so the bound did not fire: %s", line)
	}
	// The peer's own sentence still starts the bounded text, so the operator has
	// something to act on. Which text the budget is spent on is pinned in
	// TestBoundPeerCause_SpendsTheBudgetOnThePeersText, where the domain length
	// that makes the two differ can be set.
	if !strings.Contains(line, head) {
		t.Errorf("the operator line dropped the start of the peer's message: %s", line)
	}
}

// assertUnlogged fails when the sentinel appears anywhere in what the service
// recorded.
func assertUnlogged(t *testing.T, f *fixture, sentinel, what string) {
	t.Helper()
	for _, line := range f.logs.Lines() {
		if strings.Contains(line, sentinel) {
			t.Fatalf("%s put the submitted fields in a log line: %s", what, line)
		}
	}
}

// TestRegister_LogsTheOperatorLineWhenTheManifestCannotBeRead covers the one
// outbound leg whose failure the agent cannot fix and the operator can.
//
// The Exchange is reachable and answers, but its manifest comes back a 500, so
// there is no schema to pre-check against and no terms digest to echo. An
// operator investigating "ramp_register keeps failing against that Exchange"
// needs this on the same call_failed line every other outbound failure writes;
// without it the only failure with a server-side remedy is the only one with no
// server-side trace.
func TestRegister_LogsTheOperatorLineWhenTheManifestCannotBeRead(t *testing.T) {
	f := newFixture(t)
	f.exchange.failManifest(http.StatusInternalServerError)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))
	if msg == "" {
		t.Fatal("a registration went ahead with requirements that could not be read")
	}
	if !strings.Contains(msg, f.exchange.Domain(t)) {
		t.Errorf("error %q does not name the Exchange whose manifest failed", msg)
	}
	lines := f.logs.Find("identity.mcp.call_failed")
	if len(lines) != 1 {
		t.Fatalf("got %d call_failed lines, want 1: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "ramp_register") {
		t.Errorf("log line %s does not name the tool the operator would search for", lines[0])
	}
	// Nothing was signed: the failure is the read, before any RPC.
	if len(f.exchange.Calls()) != 0 {
		t.Errorf("the Exchange saw %d signed calls after an unreadable manifest",
			len(f.exchange.Calls()))
	}
}

// TestRegister_RefusesAPayloadPastTheProtocolBounds drives the protocol's own
// payload limits — size, member count, nesting depth.
//
// The placement is half of what is under test. The check runs before the
// manifest is fetched, because a limit that exists to stop work belongs before
// the work it would stop, so this asserts the Exchange was never dialled at all
// rather than merely that the RPC did not happen.
func TestRegister_RefusesAPayloadPastTheProtocolBounds(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// One member past the top-level cap. Every value is small, so this fails the
	// member count and nothing else — the bound under test is the one named.
	fields := make(map[string]any, helpers.MaxRegistrationDataMembers+1)
	for i := range helpers.MaxRegistrationDataMembers + 1 {
		fields[fmt.Sprintf("member_%02d", i)] = "x"
	}

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", map[string]any{
		"exchange": f.exchange.Domain(t),
		"fields":   fields,
	})
	if msg == "" {
		t.Fatal("a payload past the protocol's member cap was accepted")
	}
	if !strings.Contains(msg, "member count") {
		t.Errorf("error %q does not say which bound the payload passed", msg)
	}
	if got := f.exchange.HTTPRequests(); got != 0 {
		t.Errorf("the Exchange saw %d requests, want none — the bound is checked before the fetch", got)
	}
}
