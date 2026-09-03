package mcp

import (
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchpolicy"
)

// The canonical spelling of the exchange argument is driven here rather than
// through the MCP surface because the integration fixture cannot show it. Its
// Exchange double is served on a loopback address — 127.0.0.1 and a port — which
// holds no letter to change the case of and no default port to fold, so a test
// driven through a tool call there would assert that one spelling equals itself.
// The e2e harness registers under an upper-cased domain against a stack whose
// Exchanges have real hostnames; that is the over-the-wire proof for the two
// tools that go through exchacct. This is the proof for all three, at the one
// place the rewrite happens.

// TestCheckExchangeArg_ReturnsTheCanonicalSpelling pins what every tool taking an
// exchange argument gets back.
//
// ramp_report is why this matters: it does not go through exchacct, so before the
// rewrite moved here it logged and sent whatever spelling the agent wrote, and
// the shared endpoint resolver keyed its manifest cache on that raw host.
func TestCheckExchangeArg_ReturnsTheCanonicalSpelling(t *testing.T) {
	t.Parallel()
	// A zero toolset permits every Exchange, which is the no-policy deployment.
	ts := &toolset{}
	for _, tc := range []struct{ name, in, want string }{
		{"already canonical", "exchange.example", "exchange.example"},
		{"mixed case", "Exchange-B.Example", "exchange-b.example"},
		{"upper case with a port", "EXCHANGE.EXAMPLE:8081", "exchange.example:8081"},
		{"a written-out 443 is folded", "Exchange.Example:443", "exchange.example"},
		{"another port is kept", "exchange.example:80", "exchange.example:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ts.checkExchangeArg("ramp_report", tc.in)
			if err != nil {
				t.Fatalf("checkExchangeArg(%q) = %v, want it accepted", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("checkExchangeArg(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCheckExchangeArg_RefusesBeforeItRewrites is the ordering the rewrite
// depends on: a malformed value is refused as the caller wrote it, never
// repaired into something they did not write. The returned spelling is empty on
// refusal so a caller cannot use it by accident.
func TestCheckExchangeArg_RefusesBeforeItRewrites(t *testing.T) {
	t.Parallel()
	ts := &toolset{}
	for _, in := range []string{
		"https://Exchange.Example",
		"Exchange.Example/register",
		"Exchange.Example:443/register",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := ts.checkExchangeArg("ramp_report", in)
			if err == nil {
				t.Fatalf("checkExchangeArg(%q) was accepted", in)
			}
			if got != "" {
				t.Errorf("checkExchangeArg(%q) returned %q beside its error", in, got)
			}
		})
	}
}

// TestCheckExchangeArg_TellsAnAgentTheArgumentIsMissing separates absence from a
// bad shape. An omitted argument decodes to the empty string and reaches the
// handler, and helpers.IsBareDomain says no to it — so without the presence arm
// the agent is told its value has the wrong shape when it sent no value.
//
// Delete the arm and this fails on the wording: the message becomes the
// bare-domain refusal, quoting "" back at a caller that wrote nothing.
func TestCheckExchangeArg_TellsAnAgentTheArgumentIsMissing(t *testing.T) {
	t.Parallel()
	ts := &toolset{}
	got, err := ts.checkExchangeArg("ramp_report", "")
	if err == nil {
		t.Fatalf("checkExchangeArg(\"\") = %q, want a refusal", got)
	}
	if got != "" {
		t.Errorf("checkExchangeArg(\"\") returned %q beside its error", got)
	}
	if !strings.Contains(err.Error(), "needs the exchange domain") {
		t.Errorf("checkExchangeArg(\"\") = %v, want the same \"needs the …\" wording "+
			"ramp_report's other required arguments use", err)
	}
	if strings.Contains(err.Error(), "must be a bare domain") {
		t.Errorf("checkExchangeArg(\"\") = %v, which is the malformed-value refusal; "+
			"the caller sent no value at all", err)
	}
}

// TestUsageReport_CarriesTheCanonicalExchange closes the gap between the rewrite
// and the wire: the value checkExchangeArg returns is the one the handler puts on
// the report, and the report is what the Exchange reads its recipient from.
func TestUsageReport_CarriesTheCanonicalExchange(t *testing.T) {
	t.Parallel()
	ts := &toolset{}
	canonical, err := ts.checkExchangeArg("ramp_report", "Exchange-B.Example:443")
	if err != nil {
		t.Fatalf("checkExchangeArg: %v", err)
	}
	in := reportInput{
		Exchange:       canonical,
		TransactionID:  "tx-1",
		IdempotencyKey: "idem-1",
	}
	if got := in.usageReport().GetExchange(); got != "exchange-b.example" {
		t.Errorf("the report names %q, want the canonical spelling — the agent's "+
			"own spelling reached the wire", got)
	}
}

// TestCheckExchangeArg_AsksThePolicyBeforeItRewrites pins the half of the order
// the two tests above cannot see.
//
// The allowlist reads an operator's list as written and folds no default port,
// because it answers whether someone listed a value rather than whether two
// spellings name the same party. So the policy must be asked with the argument as
// the agent wrote it.
//
// The bare entry and the :443 argument are the one pairing where the two
// spellings disagree, which is why the case is written this way. Asked as
// written, "exchange.example:443" is not on a list holding "exchange.example"
// and the call is refused. Move the rewrite above checkExchangePolicy and this
// fails: the policy is handed the folded "exchange.example", the call is
// permitted, and the deployment reaches an Exchange under a spelling its
// operator did not list.
func TestCheckExchangeArg_AsksThePolicyBeforeItRewrites(t *testing.T) {
	t.Parallel()
	allow, err := exchpolicy.New("exchange.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := &toolset{exchangeAllowed: allow.Permits}

	got, err := ts.checkExchangeArg("ramp_report", "Exchange.Example:443")
	if err == nil {
		t.Fatalf("checkExchangeArg accepted %q and returned %q; the policy was asked "+
			"with the folded spelling instead of the one the agent wrote",
			"Exchange.Example:443", got)
	}
	// And a spelling the operator did list still goes through, with the party
	// spelling coming back — which is what the store and the wire compare on.
	permitted, err := ts.checkExchangeArg("ramp_report", "Exchange.Example")
	if err != nil {
		t.Fatalf("refused %q against a policy that lists it: %v", "Exchange.Example", err)
	}
	if permitted != "exchange.example" {
		t.Errorf("checkExchangeArg returned %q, want the canonical spelling", permitted)
	}
}

// TestFieldRefusal_DropsThePointerWhenNoDomainIsKnown covers the branch the two
// integration tests cannot reach: both drive an error this package built, which
// always names an Exchange.
//
// A URL with a hole in it would send the agent to a host that cannot exist, so
// the sentence is omitted rather than half-rendered.
func TestFieldRefusal_DropsThePointerWhenNoDomainIsKnown(t *testing.T) {
	t.Parallel()
	failures := []*rampv1.RegistrationFieldError{{Path: "/vat_id", Error: "is required"}}

	withDomain := fieldRefusal("exchange.example", failures)
	if !strings.Contains(withDomain, "https://exchange.example/.well-known/ramp.json") {
		t.Errorf("fieldRefusal = %q, want it to point at the Exchange's manifest", withDomain)
	}

	noDomain := fieldRefusal("", failures)
	if strings.Contains(noDomain, "https://") {
		t.Errorf("fieldRefusal = %q, want no URL when no domain is known", noDomain)
	}
	if !strings.Contains(noDomain, "/vat_id") {
		t.Errorf("fieldRefusal = %q, want it to still name the members at fault", noDomain)
	}
}
