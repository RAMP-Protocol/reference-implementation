package exchpolicy_test

import (
	"reflect"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchpolicy"
)

// TestNew_EmptyPolicyPermitsEverything pins the default posture. Every
// deployment that predates this lever runs with no value set, and it must keep
// working exactly as it did — an empty policy that refused would take every
// existing deployment down on upgrade.
func TestNew_EmptyPolicyPermitsEverything(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", ",", " , , "} {
		policy, err := exchpolicy.New(raw)
		if err != nil {
			t.Fatalf("New(%q): %v", raw, err)
		}
		if !policy.Empty() {
			t.Fatalf("New(%q) is not empty", raw)
		}
		if !policy.Permits("anything.example:9999") {
			t.Fatalf("New(%q) refused a domain", raw)
		}
		if policy.Domains() != nil {
			t.Fatalf("New(%q) rendered domains: %v", raw, policy.Domains())
		}
	}
}

// TestPermits_NilReceiverPermitsEverything covers the wiring mistake rather than
// the configuration: a caller holding no policy has no policy, which permits.
// Refusing here would fail closed on a nil nobody chose.
func TestPermits_NilReceiverPermitsEverything(t *testing.T) {
	t.Parallel()
	var policy *exchpolicy.Allowlist
	if !policy.Permits("exchange.example") || !policy.Empty() || policy.Domains() != nil {
		t.Fatal("a nil policy is not the permit-everything policy")
	}
}

func TestPermits_ListedAndUnlisted(t *testing.T) {
	t.Parallel()
	policy, err := exchpolicy.New("exchange.example, exchange-b.example:8081")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	permitted := []string{
		"exchange.example",
		"EXCHANGE.EXAMPLE",
		"exchange-b.example:8081",
	}
	for _, domain := range permitted {
		if !policy.Permits(domain) {
			t.Errorf("refused %q, which is listed", domain)
		}
	}
	refused := []string{
		"other.example",
		// A subdomain of a listed domain is a different party, and the protocol
		// treats it as one. Listing a parent must not admit its children.
		"sub.exchange.example",
		// The port is part of the identity: a listed host on another port is a
		// different endpoint, and an operator listing one did not list the other.
		"exchange.example:8081",
		"exchange-b.example",
		"",
	}
	for _, domain := range refused {
		if policy.Permits(domain) {
			t.Errorf("permitted %q, which is not listed", domain)
		}
	}
}

// TestPermits_ReadsTheOperatorsListAsWritten pins the one difference between
// this policy's comparison and account.CanonicalExchange, so a later change that
// merges the two fails here rather than silently widening a deployment's policy.
//
// The protocol folds a written-out :443, because a schemeless domain is https
// and the two spellings name one party. This policy does not, because it is not
// answering that question — it is answering whether an operator listed a value.
// Listing the bare host therefore does not admit the :443 spelling.
//
// If this assertion starts failing, the fix is a decision, not a test edit.
// Folding here means a deployment permits a spelling its operator did not write.
func TestPermits_ReadsTheOperatorsListAsWritten(t *testing.T) {
	t.Parallel()
	bare, err := exchpolicy.New("exchange.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if bare.Permits("exchange.example:443") {
		t.Error("permitted exchange.example:443 against a list holding only the bare host — " +
			"the allowlist folded a port the operator did not write")
	}
	// A port that is not the default survives untouched on both sides, which is
	// what makes the refusal above a statement about :443 and not about ports.
	local, err := exchpolicy.New("exchange.example:8081")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !local.Permits("exchange.example:8081") {
		t.Error("refused exchange.example:8081 against a list holding exactly it")
	}
	if got := local.Domains(); len(got) != 1 || got[0] != "exchange.example:8081" {
		t.Errorf("Domains() = %v, want [exchange.example:8081] — the parsed policy must "+
			"read back as the operator wrote it", got)
	}
}

// TestNew_DefaultPortEntryIsRefused pins the other half of that decision: the
// spelling this policy will not compare is refused when it is CONFIGURED, not
// left to fail as a mismatch later.
//
// An entry writing out :443 can never permit a call. The policy is asked twice —
// once at the tool layer with the agent's argument as written, once below it
// with account.CanonicalExchange's spelling, which drops :443 — so the second
// question fails whichever way the agent writes the domain. Accepting the entry
// would give the operator a policy that excludes the Exchange they configured,
// with the first evidence arriving as a refused registration attributed to the
// agent.
//
// Delete refuseDefaultPort and this fails; the deployment then boots with dead
// configuration and nothing says so.
func TestNew_DefaultPortEntryIsRefused(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"exchange.example:443",
		"exchange-a.example,exchange-b.example:443",
		"EXCHANGE.EXAMPLE:443",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			policy, err := exchpolicy.New(raw)
			if err == nil {
				t.Fatalf("New(%q) accepted an entry that can never match; parsed %v",
					raw, policy.Domains())
			}
			if !strings.Contains(err.Error(), ":443") {
				t.Errorf("New(%q) = %v, want an error naming the port it refused", raw, err)
			}
		})
	}
}

// TestNew_MalformedEntryIsRefused is the case the error return exists for. A
// dropped entry would leave the operator with a policy narrower than the one
// they wrote, and nothing would say so until an agent was refused.
//
// The cases come from the shared table the two tool surfaces also drive, which
// is what this parser has to agree with: a domain the policy admits must not be
// one the request then refuses, and the reverse.
func TestNew_MalformedEntryIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range testutil.NonBareDomains {
		raw := tc.Of("exchange.example")
		if _, err := exchpolicy.New("good.example," + raw); err == nil {
			t.Errorf("New accepted %q (%s)", raw, tc.Name)
		} else if !strings.Contains(err.Error(), raw) {
			t.Errorf("New(%q) error does not name the offending entry: %v", raw, err)
		}
	}
}

// TestDomains_ReadsBackWhatWasParsed is what an operator checks a typo against.
// Sorted, so the boot line is the same on every restart and a diff of two boots
// shows a configuration change rather than a map iteration.
func TestDomains_ReadsBackWhatWasParsed(t *testing.T) {
	t.Parallel()
	policy, err := exchpolicy.New(" b.example:8081 ,a.example, B.EXAMPLE:8081 ")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := policy.Domains(); !reflect.DeepEqual(got, []string{"a.example", "b.example:8081"}) {
		t.Fatalf("Domains() = %v", got)
	}
}
