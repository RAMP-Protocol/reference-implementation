package rampaudience

import (
	"fmt"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// RecipientOf answers who a request dialled at origin is addressed to.
//
// The answer is normally the host of that origin: an Exchange is reached at its
// own identity, so the party at the far end of the wire and the party the
// request names are the same string, and a second setting for one fact could
// only ever disagree with the URL.
//
// override is for the deployments where that is not true, because something
// routes between the caller and the Exchange: a test harness reaching it
// through a mapped 127.0.0.1 port, or a stack where the caller dials an
// in-network alias while the Exchange publishes itself under a public
// hostname. The dialled host then names no Exchange at all, and the sender has
// to be told the identity separately. Empty means "derive it".
//
// The bare-domain check runs on BOTH paths. A derived host can be a shape the
// wire refuses — an underscored container alias, a bracketed IPv6 literal, a
// trailing root dot, port 0 — because HostOf answers a weaker question than the
// protocol does. An override is caller input that nothing else validates.
// Either way the request is signed before it is refused, so refusing here is
// what turns a far-end rejection, which names nothing the operator set, into a
// local error naming the value.
func RecipientOf(origin, override string) (string, error) {
	recipient := override
	if recipient == "" {
		host, err := helpers.HostOf(origin)
		if err != nil {
			return "", fmt.Errorf("origin %q has no host: %w", origin, err)
		}
		recipient = host
	}
	if !helpers.IsBareDomain(recipient) {
		return "", fmt.Errorf(
			"recipient %q is not a bare domain (%q or %q)",
			recipient, "exchange.example", "exchange.example:8081")
	}
	return recipient, nil
}

// Require returns an error unless i is a usable interceptor, for a mux builder
// to call before it mounts anything.
//
// A nil interceptor mounts cleanly and checks nothing, which is the one failure
// mode this package exists to prevent — so every builder that takes one refuses
// a nil rather than treating it as "no recipient to enforce". The refusal lives
// here, in one exported function, because two services making the same refusal
// in their own words is two sentences a reader cannot find from each other.
//
// surface names what was being built, so the error says which mount was left
// without a check. The three callers pass "exchange mount options", "broker
// mount options" and "raw mount options" — one per option-set function, since
// that is where each service's mount is now assembled.
func Require(i *Interceptor, surface string) error {
	if i == nil {
		return fmt.Errorf("%s: the recipient interceptor is required", surface)
	}
	return nil
}
