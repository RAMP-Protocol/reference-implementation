package mcp

import (
	"context"
	"fmt"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// What ramp_register and ramp_status share: one rendering of an exchacct failure
// for both.
//
// The two tools are different calls with the same failure vocabulary — the same
// kinds, the same remedies, the same rule about which failures an operator hears.
// One renderer is what stops the two drifting into telling an agent different
// things about the same refusal. It sits in its own file rather than in either
// tool's, because a shared renderer living in one caller's file reads as that
// caller's own until the day someone changes it for that caller alone.

// accountFailure turns an exchacct failure into what the agent is told, and
// decides which failures the operator also hears about. It serves BOTH account
// tools — opening an account and asking after one fail the same ways.
//
// The split is by who refused. A local refusal — the payload is outside the
// protocol's bounds, carries a value the wire cannot hold, or does not match the
// schema the Exchange publishes — is the caller's own input coming back, and it
// is answered without a log line: nothing left this process, and one of those
// messages quotes the data itself. Everything that involved a third party or
// this service's own store reaches the operator through accountCallFailed.
func (t *toolset) accountFailure(ctx context.Context, who caller, tool string, err error) error {
	kind, ok := exchacct.KindOf(err)
	if !ok {
		return t.accountCallFailed(ctx, who, tool, err)
	}
	switch kind {
	// The two refusals the service makes about the ARGUMENT, before it reads or
	// sends anything. Rendered as the verdicts they are rather than through the
	// transport-failure path, and worded by the same helpers this layer's own
	// checks use, so an agent cannot tell which layer refused.
	//
	// Not reachable from a tool call: checkExchangeArg applies both rules first.
	// The arms exist because the service is reachable without this layer — its
	// package doc names "whatever asks next" — and a kind with no arm here falls
	// through to a transport-failure rendering that names the wrong problem.
	case exchacct.KindExchangeShape:
		return notBareDomainError(tool, exchacct.ExchangeOf(err))
	case exchacct.KindNotPermitted:
		return notPermittedError(tool, exchacct.ExchangeOf(err))
	case exchacct.KindFieldsOutOfBounds:
		return fmt.Errorf(
			"%s: fields are outside what a registration may carry (%w); the protocol bounds "+
				"the payload's size, its member count and how deeply it nests",
			tool, exchacct.CauseOf(err))
	case exchacct.KindFieldsMalformed:
		return fmt.Errorf(
			"%s: fields carry a value a registration cannot hold: %w", tool, exchacct.CauseOf(err))
	case exchacct.KindFieldsRefused:
		return registrationFieldFailure(tool, exchacct.ExchangeOf(err), exchacct.FieldsOf(err))
	case exchacct.KindOutbound:
		return t.exchangeRefused(ctx, who, tool, err)
	case exchacct.KindNotes:
		return t.notesUnavailable(ctx, who, tool, err)
	// KindRequirements has no arm of its own: the Exchange did not answer, which
	// is the same thing the default says. Naming it would read as a decision and
	// make no difference, and accountCallFailed is written so that a kind added
	// later carries its own answer rather than needing one here.
	default:
		return t.accountCallFailed(ctx, who, tool, err)
	}
}

// accountCallFailed is the account tools' operator line: failed(), with the one
// rule this surface adds.
//
// Whether the operator hears the message at all is ASKED of the error
// rather than decided by which arm above happens to call this. exchacct marks a
// failure whose text can quote the caller's registration data; a marked one is
// answered to the agent and never written to a log line. Reading the mark here
// means a kind added later carries its own answer instead of falling through to
// a log line because this switch does not name it yet.
//
// That is the only rule this surface adds. The bound on a peer's own text is not
// one of them: it applies wherever a peer's words reach an operator line, so it
// sits on failed() beside logFailure rather than here.
func (t *toolset) accountCallFailed(ctx context.Context, who caller, tool string, err error) error {
	if exchacct.Sensitive(err) {
		return fmt.Errorf("%s: %w", tool, exchacct.CauseOf(err))
	}
	return t.failed(ctx, who, tool, err)
}

// notesUnavailable is what an agent is told when this service's own note store
// could not answer, and what the operator is told about it.
//
// The operator's half is the same identity.mcp.call_failed line every other
// failure on this surface produces, at the same level and carrying the same op
// field, so one query covers the whole surface. The cause is written in full:
// the store is ours, and nothing a third party wrote is in it.
//
// The agent's half is this sentence rather than the rendered cause. It names
// what it can do instead — ask about one Exchange by name, which does not read
// the note store at all — where the cause would name a database it cannot act
// on.
func (t *toolset) notesUnavailable(ctx context.Context, who caller, tool string, err error) error {
	t.logFailure(ctx, who, tool, err, err.Error())
	return fmt.Errorf(
		"%s: could not read where this agent has registered; ask about one Exchange "+
			"by name to get its own answer instead", tool)
}

// exchangeRefused turns a peer's refusal into what the agent is told. It serves
// both account tools: the Exchange refuses a registration and an account-status
// call the same way, through the same transport.
//
// It runs the ordinary path first, so the operator gets a call_failed line and
// the agent gets the typed reason it branches on. Then, if the peer attached a
// registration failure naming FIELDS, it says which — because an Exchange that
// refuses on its schema and an adapter that refuses on the same schema are the
// same problem with the same remedy, and an agent told "invalid registration
// data" by one and "/vat_id: does not match pattern" by the other would
// reasonably think they were different.
//
// The reason token is kept alongside rather than replaced. It is the part an
// agent branches on; the field list is the part a human or a retry acts on, and
// dropping either would make this worse than what it replaces.
//
// A test drives this by staging a peer whose refusal carries the detail an
// enforcing Exchange attaches, rather than by standing up an Exchange: the
// adapter's own pre-check refuses a non-conforming payload before the call is
// signed, so in a healthy deployment the remote refusal is the rarer path — it
// is reached when the agent's cached copy of the schema is older than the one
// the Exchange now publishes.
func (t *toolset) exchangeRefused(ctx context.Context, who caller, tool string, err error) error {
	refusal := t.accountCallFailed(ctx, who, tool, err)
	fields := detailOf(err).GetRegistrationFailure().GetFieldErrors()
	if len(fields) == 0 {
		return refusal
	}
	return fmt.Errorf("%w — %s", refusal, fieldRefusal(exchacct.ExchangeOf(err), fields))
}

// registrationFieldFailure renders the local pre-check's schema refusal.
func registrationFieldFailure(tool, exchange string, failures []*rampv1.RegistrationFieldError) error {
	return fmt.Errorf("%s: %s will not accept these fields — %s",
		tool, exchange, fieldRefusal(exchange, failures))
}

// fieldRefusal renders what a schema refusal tells the agent: which members are
// at fault, then where the requirements are published.
//
// ONE renderer for two sources, and the remedy sentence is the half that has to
// be shared. The same refusal arrives from this adapter's pre-check and from the
// Exchange's own answer, and the agent's remedy is identical either way — read
// the schema, fix the members, retry. An agent that got the pointer from one
// source and a bare field list from the other would reasonably read them as two
// different problems, which is the outcome one renderer exists to prevent.
//
// The pointer is dropped when no domain is known rather than rendered as a URL
// with a hole in it. That case is a caller passing an error this package did not
// build; a sentence naming https:///.well-known/ramp.json would send the agent
// somewhere that cannot exist.
//
// The scheme is https because that is what an Exchange's manifest is served over
// in any deployment an agent reaches from outside, and it matches the URL the
// ramp_register tool description gives.
func fieldRefusal(exchange string, failures []*rampv1.RegistrationFieldError) string {
	list := fieldFailureList(failures)
	if exchange == "" {
		return list
	}
	return fmt.Sprintf(
		"%s. The shape it requires is published at "+
			"https://%s/.well-known/ramp.json under account_registration.data_schema",
		list, exchange)
}

// fieldFailureList renders the members of a refusal, one per entry.
//
// Shared by the local pre-check and the Exchange's own refusal through
// fieldRefusal, which is the whole point: the two are the same problem and must
// not read as two.
func fieldFailureList(failures []*rampv1.RegistrationFieldError) string {
	parts := make([]string, 0, len(failures))
	for _, f := range failures {
		if path := f.GetPath(); path != "" {
			parts = append(parts, path+": "+f.GetError())
			continue
		}
		// An empty path addresses the whole object, which is how a missing
		// required member is reported. Rendering a bare ": ..." there would read
		// as a member with no name.
		parts = append(parts, f.GetError())
	}
	return strings.Join(parts, "; ")
}
