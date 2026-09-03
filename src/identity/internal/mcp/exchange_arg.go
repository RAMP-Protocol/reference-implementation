package mcp

import (
	"fmt"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// Three tools take an Exchange domain as an argument, so everything every one of
// them does with that argument lives here rather than once per tool. Two checks
// and one rewrite, in this order, all before anything leaves the process: what
// the value IS, whether this deployment will speak to it, and then the one
// spelling the rest of the service compares and stores.

// validateExchangeDomain enforces the one thing the exchange field's contract
// already claimed: it is a DOMAIN, not a URL.
//
// The value is routing input that reaches URL construction downstream — the
// well-known endpoint resolver builds {scheme}://{exchange}/.well-known/ramp.json
// by concatenation — so a caller that can smuggle a path, query, or fragment past
// this point picks the URL this service fetches rather than merely the host it
// fetches from.
//
// The rule is helpers.IsBareDomain: the shape the wire itself admits, the same
// bytes protovalidate stamps on every domain-valued field in the protocol. The
// value does not only choose a URL here, it also travels on the request as the
// `exchange` field, so checking it against that one definition is what keeps
// this refusal and the receiving Exchange's own refusal from ever disagreeing.
// It is narrower than asking whether the value is merely parseable as a host,
// and the narrow rule is the correct one for a value bound for the wire.
//
// Refused rather than narrowed to the host, deliberately. Narrowing would let a
// caller send a request this service silently rewrote — and these calls open
// accounts and move money, so the agent should learn its input was wrong here
// rather than have it quietly reinterpreted.
//
// tool names the caller so the message keeps the tool-name prefix every error on
// this surface carries; an agent reading a failure knows which of its calls
// produced it without inferring from the wording.
func validateExchangeDomain(tool, exchange string) error {
	if !helpers.IsBareDomain(exchange) {
		return notBareDomainError(tool, exchange)
	}
	return nil
}

// notBareDomainError is the sentence an agent gets for an exchange argument that
// is not a bare domain, whichever layer refused it.
//
// Two layers do: this one, so the agent gets a readable message, and exchacct,
// so the rule is a structural guarantee rather than a convention a second caller
// could skip. One wording means an agent cannot tell which layer answered, and
// there is nothing to tell — it is the same refusal for the same reason.
func notBareDomainError(tool, exchange string) error {
	return fmt.Errorf(
		"%s: exchange must be a bare domain (\"exchange.example\" or "+
			"\"exchange.example:8081\"), not %q — a scheme, path, query or fragment is not part of it",
		tool, exchange,
	)
}

// missingExchangeError is the sentence for an argument that was not sent at all.
//
// Worded like the tool's other required arguments — "needs the …" — rather than
// like a refusal, because nothing was refused: there is no value to quote back.
func missingExchangeError(tool string) error {
	return fmt.Errorf(
		"%s needs the exchange domain — the bare domain of the Exchange this call is "+
			"for, such as \"exchange.example\"", tool)
}

// notPermittedError is the sentence for a domain this deployment will not reach,
// shared by the same two layers and for the same reason.
func notPermittedError(tool, exchange string) error {
	return fmt.Errorf(
		"%s: this registry is not configured to reach %q — its operator limits which "+
			"Exchanges it will contact, and that one is not on the list",
		tool, exchange,
	)
}

// checkExchangePolicy refuses a domain this deployment will not speak to.
//
// It runs in the TOOL layer as well as below, and the two are not redundant —
// but what this one adds is READABILITY, not reach. Every leg that could dial
// carries the same policy underneath it: the shared endpoint resolver's overlay
// for anything that routes, and exchreg's own Allow for the register path's
// manifest read, which goes direct and would otherwise be the one leg holding
// the rule by convention. So an excluded domain is refused whether or not this
// check runs. What it buys is the agent getting a sentence that names the
// policy, instead of a routing failure it cannot interpret.
func (t *toolset) checkExchangePolicy(tool, exchange string) error {
	if t.exchangeAllowed == nil || t.exchangeAllowed(exchange) {
		return nil
	}
	return notPermittedError(tool, exchange)
}

// checkExchangeArg runs both checks in the order that sends least, then returns
// the canonical spelling of the argument. A tool calls this rather than the
// pieces separately, so a new tool cannot pick up one and miss another.
//
// Canonicalising HERE rather than once per tool is what this function is for.
// exchacct canonicalises on its own first line, so register and status were
// covered, but ramp_report does not go through that service — it logged the
// caller's spelling and sent the caller's spelling, and the shared endpoint
// resolver keys its manifest cache on that raw host, so one Exchange written two
// ways occupied two cache entries.
//
// Absence is answered before either check, because it is a different problem
// with a different remedy: the agent left the argument out, and telling it the
// value has the wrong shape sends it looking at a value it never sent. The
// shared table of malformed values excludes the empty string for exactly this
// reason. The other two required arguments on ramp_report say "needs the …", so
// this one says it too and the tool reports absence one way.
//
// The rewrite runs AFTER both checks, and the order is load-bearing in both
// directions. After validateExchangeDomain, because canonicalising is not
// narrowing: a malformed value must be refused as the caller wrote it rather
// than repaired into something they did not. After checkExchangePolicy, because
// the allowlist reads an operator's list as written and folds no default port —
// see exchpolicy, which documents why it answers a different question from this
// rewrite.
func (t *toolset) checkExchangeArg(tool, exchange string) (string, error) {
	if exchange == "" {
		return "", missingExchangeError(tool)
	}
	if err := validateExchangeDomain(tool, exchange); err != nil {
		return "", err
	}
	if err := t.checkExchangePolicy(tool, exchange); err != nil {
		return "", err
	}
	return account.CanonicalExchange(exchange), nil
}
