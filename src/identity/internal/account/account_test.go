package account_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// TestCanonicalExchange is the party rule, as pure logic.
//
// It is unit-tested rather than driven through a service because it is exactly
// that — a normalizer with no collaborators. What it decides has consequences
// two layers away: the note store's key is (subdomain, exchange) over plain
// text, so two spellings of one domain are two notes, and the second is one no
// later call can find, refresh or delete. The deployment's allowlist does NOT
// compare through this function — it reads an operator's list as written — so a
// change here moves the store and the wire, not the policy.
func TestCanonicalExchange(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, in, want string }{
		{"already canonical", "exchange.example", "exchange.example"},
		{"upper case", "EXCHANGE.EXAMPLE", "exchange.example"},
		{"mixed case", "Exchange.Example", "exchange.example"},
		{"mixed case with a port", "Exchange-B.Example:8081", "exchange-b.example:8081"},
		{"surrounding space", "  exchange.example  ", "exchange.example"},
		{"space and case together", " EXCHANGE.example ", "exchange.example"},
		// A schemeless domain is https, so these three name one party and must
		// produce one note. The protocol's audience check folds the same port,
		// which is why both spellings reach one account at one Exchange.
		{"a written-out 443 is folded", "exchange.example:443", "exchange.example"},
		{"443 with case", "Exchange.Example:443", "exchange.example"},
		{"443 with space", " exchange.example:443 ", "exchange.example"},
		// Only 443. Folding 80 would read http into a value that names no
		// scheme, and every other port names a different endpoint.
		{"port 80 is kept", "exchange.example:80", "exchange.example:80"},
		{"a non-default port is kept", "exchange.example:8081", "exchange.example:8081"},
		{"0443 is a different string, not a spelling of 443", "exchange.example:0443", "exchange.example:0443"},
		// Not this function's job: the shape rule refuses these before they get
		// here, and canonicalising is not narrowing. A value that arrives
		// malformed must come out malformed rather than be quietly repaired
		// into something the caller never wrote — including one whose trailing
		// :443 would otherwise be read as a port to fold.
		{"a path is left alone", "exchange.example/register", "exchange.example/register"},
		{"a URL keeps its port", "https://exchange.example:443", "https://exchange.example:443"},
		{"empty stays empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := account.CanonicalExchange(tc.in); got != tc.want {
				t.Errorf("CanonicalExchange(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
