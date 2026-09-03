// Package exchpolicy is the deployment's answer to whether this service will
// speak to a given Exchange at all.
//
// It exists because the account tools stopped naming one configured Exchange.
// Before that, an operator chose the single Exchange this service would ever
// sign a request to, and that choice was the policy. Now an authenticated agent
// names the Exchange per call, so without a lever the registry becomes an
// agent-directed outbound-traffic surface attributable to the operator's
// infrastructure. The SSRF guard is not that lever: it stops private and
// internal addresses, not hostile public ones.
//
// # What it reaches, and what it does not
//
// An empty policy permits every Exchange, which is how this service behaved
// before the lever existed, so a deployment that wants none writes none.
//
// It governs the three legs where this service picks an Exchange and sends that
// Exchange a request the agent's key signed: register, account status, and the
// usage report. Two other legs reach an Exchange and are NOT governed, and both
// are outside what an allowlist could decide:
//
//   - The purchase goes through the Broker's execute relay. The Broker chooses
//     which Exchange to hand it to, from an offer the Exchange itself signed, so
//     there is no domain here to hold against a list.
//   - The offer-key lookup fetches an Exchange's published directory to VERIFY
//     an offer that arrived. It reads a public key rather than sending anything
//     the agent signed, and refusing to verify an offer would not stop the offer
//     — it would only stop this service noticing the offer was forged.
//
// Stating the two is the point: "applies to every outbound call" would be the
// comfortable sentence and it would be false.
package exchpolicy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Allowlist is a set of Exchange domains this deployment will speak to.
//
// A nil or empty Allowlist permits every domain, so the no-policy case needs no
// branch at any call site — Permits answers true and callers hold one code path
// rather than one per configuration.
type Allowlist struct {
	allowed map[string]struct{}
}

// New parses a comma-separated list of bare domains. An empty or whitespace-only
// value yields a policy that permits everything.
//
// A malformed entry is an error rather than a dropped entry, and that is the
// whole reason this returns one. An operator who mistypes one domain in a list
// of four has configured a policy that silently excludes the Exchange they meant
// to include; dropping it quietly would make the first evidence a refused
// registration weeks later, pointing at the agent rather than at the setting.
// An entry that writes out :443 is refused for that same reason — see
// refuseDefaultPort.
//
// The rule is helpers.IsBareDomain — the same rule the tools apply to the
// exchange argument and the same bytes protovalidate stamps on the wire field.
// One definition, so a domain this policy admits cannot be one the request
// refuses, or the reverse.
func New(raw string) (*Allowlist, error) {
	allowed := map[string]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !helpers.IsBareDomain(entry) {
			return nil, fmt.Errorf(
				"exchpolicy: %q is not a bare domain — an entry is a domain with an "+
					"optional port (\"exchange.example\" or \"exchange.example:8081\"), "+
					"never a URL", entry)
		}
		if err := refuseDefaultPort(entry); err != nil {
			return nil, err
		}
		allowed[normalize(entry)] = struct{}{}
	}
	if len(allowed) == 0 {
		return &Allowlist{}, nil
	}
	return &Allowlist{allowed: allowed}, nil
}

// refuseDefaultPort rejects an entry that writes out :443.
//
// Such an entry can never permit anything, which is why it is refused rather
// than folded. This policy is asked twice about one call: the tool layer asks
// with the agent's argument as written, and the requirements read below it asks
// with account.CanonicalExchange's spelling, which drops a written-out :443. An
// entry carrying the port therefore fails the second question whatever the agent
// writes — name the Exchange bare and the deep check refuses, name it with the
// port and the deep check still sees the bare form. The operator has configured
// an Exchange nobody can reach.
//
// Refused at parse for the same reason a malformed entry is: the alternative is
// a registration refused weeks later, pointing at the agent rather than at the
// setting. Only :443 is affected — every other port survives canonicalisation
// and is compared as written, which is what an operator's list is meant to be.
func refuseDefaultPort(entry string) error {
	if host, port, found := strings.Cut(entry, ":"); found && port == "443" {
		return fmt.Errorf(
			"exchpolicy: %q writes out the default HTTPS port, and an entry carrying "+
				"it can never be matched — the check below the tools compares the "+
				"canonical spelling, which drops :443. Write %q", entry, host)
	}
	return nil
}

// Permits reports whether this deployment will speak to domain.
//
// Comparison is on the lowercased domain and nothing more. It deliberately does
// NOT fold a written-out :443 the way the protocol's audience check does: that
// check decides whether two spellings name the same PARTY, which is a protocol
// question with a protocol answer, while this decides whether an operator listed
// a value. An operator's list is read as written.
func (a *Allowlist) Permits(domain string) bool {
	if a == nil || len(a.allowed) == 0 {
		return true
	}
	_, ok := a.allowed[normalize(domain)]
	return ok
}

// Empty reports whether this policy permits every Exchange.
func (a *Allowlist) Empty() bool {
	return a == nil || len(a.allowed) == 0
}

// Domains renders the policy for one boot log line, sorted so the line is stable
// across restarts. An operator reads back what the service PARSED rather than
// what they believe they set, which is the difference that catches a typo before
// an agent does.
func (a *Allowlist) Domains() []string {
	if a == nil || len(a.allowed) == 0 {
		return nil
	}
	out := make([]string, 0, len(a.allowed))
	for domain := range a.allowed {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

// normalize is the spelling this policy compares on: lowercased and trimmed,
// nothing else.
//
// It deliberately does NOT delegate to account.CanonicalExchange, and the two
// must not be merged. That function answers whether two values name the same
// PARTY, so it folds a written-out :443 the way the protocol's audience check
// does. This one answers whether an operator listed a value, and an operator's
// list is read as written.
//
// The consequence is real and intended: with exchange.example listed, an agent
// naming exchange.example:443 is refused, even though the two reach one account
// at one Exchange. The refusal is the safe direction, and the boot log line
// prints what was PARSED so an operator sees which spelling they configured.
//
// The opposite pairing is not left to this asymmetry, because it has no safe
// direction — it is dead configuration either way. New refuses an entry that
// writes out :443 rather than folding it here; see refuseDefaultPort for what
// makes such an entry unmatchable.
func normalize(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}
