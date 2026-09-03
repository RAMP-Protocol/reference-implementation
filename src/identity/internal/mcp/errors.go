package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampsdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampreason"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampclient"
)

// errNoIdentity is returned when a tool runs without an authenticated agent on
// the request. It should be unreachable — the bearer gate refuses such a request
// long before a tool executes — so reaching it means the middleware chain was
// assembled wrong. It fails closed rather than acting as some default agent.
//
// It WRAPS agentsign.ErrNoIdentity rather than restating it, so the outbound leg
// and this one answer errors.Is the same way: the condition is one condition, and
// a caller that wants to branch on "unauthenticated" should not have to know
// which layer noticed first.
var errNoIdentity = fmt.Errorf("mcp: no authenticated agent on the request: %w",
	agentsign.ErrNoIdentity)

// errIdentityMismatch is returned when the session's agent and the bearer on the
// current request disagree. Failing closed is the only safe reading: two answers
// to "whose key signs this" is not a case to pick a winner in.
var errIdentityMismatch = errors.New(
	"mcp: the bearer on this request names a different agent than the session it was sent on",
)

// deliveryReason renders a failed content fetch for the agent.
//
// It is a SIBLING of rampError rather than a branch inside it because the two
// have opposite outcomes: a rampError fails the tool call, whereas a delivery
// failure must not — the transaction is already paid for. Folding them together
// would put the two dispositions one edit apart, and the wrong one is a charge
// the agent cannot use.
//
// The reason is a machine-readable token so an agent can branch: the edge's own
// refusal (missing_agent_key, keyid_mismatch, pop_expired) when it sent one,
// otherwise the failure class.
// The message is built the same way the log line is — through deliveryCause,
// which keeps the delivery URL out of it. The agent holds that URL already, in the
// failure's own retrieval_endpoint field where it is there on purpose and governed
// by one redaction policy. Repeating it inside free-form prose adds nothing and
// takes it somewhere else: message text is what clients forward to their own
// diagnostics and logs, which outlive the credential in it.
func deliveryReason(err error) (reason, message string) {
	// The content tier's own class is read FIRST, and the order is not
	// arbitrary. Every fetch that reached the SDK comes back wrapped in a client
	// error too, which copies the content tier's reason across — so the two
	// agree today on the edge's own tokens. Reading the inner one anyway means
	// this keeps answering the same way whether or not the SDK goes on copying.
	var fetchErr *resolvers.FetchError
	if errors.As(err, &fetchErr) {
		return fetchErr.ReasonOf(), deliveryCause(err)
	}
	// A failure that never reached the content tier, so there is no content-tier
	// class to read: the credentials the fetch signs with could not be produced,
	// or the client refused before building a request. Those carry the client's
	// own class instead, and reading it is what keeps a named cause from
	// rendering as the token reserved for one nobody could name.
	//
	// Neither condition is reachable through ramp_execute today — the purchase
	// signs with the same key source, so custody failing takes the call down one
	// leg earlier. The arm is here because this function's job is to put a token
	// on ANY failure of the content leg, and a classified failure arriving
	// unclassified is the shape that stops an operator alert firing.
	var callErr *rampsdkconnect.CallError
	if errors.As(err, &callErr) {
		if isNotSignable(err) {
			return callErr.ReasonOf(), notSignableMessage
		}
		return callErr.ReasonOf(), deliveryCause(err)
	}
	// Neither tier classified it. It reaches here as the class the SDK uses for
	// an unclassified fetch, so the agent still gets a token rather than a bare
	// message it cannot branch on.
	return resolvers.FetchUnknown.String(), deliveryCause(err)
}

// deliveryCause is the failure's rendering, for the log line beside the
// agent-facing message above.
//
// It does no redaction of its own, and that is the point worth recording. A
// delivery URL keeps its credential in the query, and the HTTP client wraps every
// transport failure in a *url.Error whose Error() embeds the whole URL. The
// content tier rebuilds that wrapper without the query before the error leaves
// the SDK, so the diagnostic part ("connection refused", "context deadline
// exceeded") arrives already separated from the part that must not outlive the
// fetch. A second strip here would be a copy of a rule that has one owner — and
// the earlier copy of exactly that rule is what drifted.
//
// That covers a failure the content tier produced, and only that. A failure that
// never reached it carries whatever ITS cause carries, which for a custody
// outage is the key store's own URL. This function is the LOG's rendering, where
// that is wanted; notSignableMessage is what the agent gets instead.
func deliveryCause(err error) string {
	return err.Error()
}

// notSignableMessage is what an agent is told when this service could not
// produce the credentials its call would be signed with — and it is a fixed
// sentence, deliberately.
//
// Every OTHER failure's cause is worth passing on: a peer's refusal explains
// itself, and the SDK's own routing refusals name the check that declined. These
// are different in kind. They describe this service's own machinery — a key
// store that is down or denying us, a key whose id does not identify it, a
// signer this deployment never configured — and a transport failure inside
// custody arrives carrying the store's host, port and secret path, because every
// branch of that classifier preserves the error underneath it. The agent can act
// on none of it, and the message is what a client forwards into its own logs,
// which outlive the request.
//
// The whole set is treated alike rather than only the outage, because the agent
// can act on none of them and the operator needs all of them — a split would
// mean picking, per condition, which half of that is more true. Nothing
// diagnosable is lost either way: the token beside this is what an agent
// branches on, and the failure is logged with its whole cause on every leg that
// can reach here.
const notSignableMessage = "the calling agent's signing key could not be produced"

// isNotSignable reports whether err is this service's own failure to produce the
// credentials a call is signed with, rather than a peer's refusal or a check on
// something the caller supplied.
//
// Two clauses, because the condition arrives in two shapes. A leg that resolves
// the key itself before building a request says so with the SDK's class — the
// three SDK verbs and the relay purchase. A leg that leaves the resolution to
// the signing transport cannot: the failure surfaces from inside RoundTrip, so
// net/http and then the RPC client wrap it in their own transport errors and the
// class is gone. Only the sentinel chain crosses both, which is why the second
// clause is the one that matters — without it, the two account tools answer with
// a transport code and hand the agent the key store's own diagnostics.
func isNotSignable(err error) bool {
	var callErr *rampsdkconnect.CallError
	if errors.As(err, &callErr) && callErr.Kind == rampsdkconnect.CallNotSignable {
		return true
	}
	return errors.Is(err, ramphttpsig.ErrNoSigningKey)
}

// failed records why a RAMP call failed and returns what the agent is told.
//
// The two are not the same text, and this is the one place that is true by
// construction rather than by each caller remembering. An agent gets a token it
// can branch on and prose that says nothing about this service's internals; an
// operator gets the whole cause, including the parts deliberately kept out of
// the agent's copy. Returning the agent's half from the function that writes the
// operator's half is what stops a leg shipping one without the other — which is
// the state every leg but the delivery one was in.
//
// EVERY failure is recorded, not only the redacted ones. A peer's refusal is
// already legible to the agent, but nothing on this side kept it, so a report
// that "the Exchange keeps refusing" had no server-side trace to check it
// against. The reason token is on the line so one query serves both, matching
// the two delivery-leg lines that already carry it.
func (t *toolset) failed(ctx context.Context, who caller, op string, err error) error {
	t.logFailure(ctx, who, op, err, boundPeerCause(err))
	return rampError(op, err)
}

// logFailure writes the operator's half, with cause as its rendering of what
// went wrong.
//
// The rendering is a parameter because one caller's cause is not a peer's: the
// note store is ours, so notesUnavailable writes it in full. Everything reaching
// an operator line through failed above is bounded, so the line's shape — event
// name, level, fields — is still decided in one place.
func (t *toolset) logFailure(ctx context.Context, who caller, op string, err error, cause string) {
	t.logger(ctx, who).WarnContext(ctx, "identity.mcp.call_failed",
		"subdomain", who.subdomain, "op", op, "reason", reasonOf(err),
		"err", cause)
}

// maxPeerText bounds a third party's error text on an operator line. Long enough
// for any refusal sentence a peer writes for a human, short enough that an echoed
// payload does not fit.
const maxPeerText = 300

// boundPeerCause renders a failed outbound call for the operator line, bounding
// the part a third party wrote and nothing else.
//
// It applies to every leg that carries a peer's words, not only the account
// tools. An Exchange writes its own refusal message, and one that echoes a
// submitted value into it would put registration data on this line — the outcome
// this service's whole payload-privacy rule exists to prevent. The usage report
// reaches an Exchange the same way, and discover and execute carry whatever the
// Broker relays back. Attaching the bound to which tool asked, rather than to
// where the text came from, is what left the report leg unbounded.
//
// A bound is not redaction: a short echoed value still travels, and the honest
// reason to bound rather than omit is that the peer's sentence is usually the
// only account of why a call was refused, so dropping it entirely would leave an
// operator nothing to act on. What the bound removes is the case that matters
// most, a peer echoing the whole payload back. The agent still gets the message
// in full, and the typed reason token on the line is unbounded because this
// service builds it.
//
// The bound is on the CAUSE rather than on the rendered error. This service
// builds the prefix — "exchacct: outbound at <domain>: " — and a bare domain may
// be 260 bytes, so bounding the whole string spends the peer's budget on our own
// text and can leave the peer's sentence with almost none of it. The peer's
// sentence is usually the only account of why a registration was refused, so it
// is the part the budget exists for.
//
// The prefix is recovered from the rendered error rather than rebuilt here, so
// there is no second copy of the error's own layout to keep in step with it. An
// error that does not render its cause at the end falls back to bounding the
// whole, which is the safe direction: never less bounded than before.
func boundPeerCause(err error) string {
	rendered := err.Error()
	cause := exchacct.CauseOf(err)
	if cause == nil {
		return boundPeerText(rendered)
	}
	prefix, ok := strings.CutSuffix(rendered, cause.Error())
	if !ok {
		return boundPeerText(rendered)
	}
	return prefix + boundPeerText(cause.Error())
}

// boundPeerText truncates text that a third party may have written, marking the
// cut so a reader knows the line is not the whole message.
//
// The cut moves back to a character boundary. A third party writes this text and
// may write it in any language, so a cut at a fixed byte offset lands inside a
// multi-byte character often rather than rarely — and the broken tail renders as
// U+FFFD in front of the marker, which reads as corruption rather than as a
// truncation the reader can trust.
func boundPeerText(s string) string {
	if len(s) <= maxPeerText {
		return s
	}
	cut := maxPeerText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "… (truncated)"
}

// rampError turns a failed RAMP call into the message the agent sees.
//
// The point is to preserve the TYPED reason. RAMP carries the precise cause in an
// ErrorDetail — "offer expired", "insufficient balance", "billing ref inactive" —
// while the transport code alone says only which broad class it fell into. An
// agent that has to act on the difference cannot do it from "permission denied",
// so the typed reason is surfaced when present and the transport code is the
// fallback.
//
// Both outbound shapes land here: the Connect legs carry the detail on a
// *connect.Error, and the relay leg carries it on a *rampclient.Error. Rendering
// for BOTH happens at this layer, which is why rampclient returns its refusal as
// a value rather than a sentence — a reason rendered into prose one layer down
// cannot be recovered here without parsing it back out.
func rampError(op string, err error) error {
	if reason := reasonOf(err); reason != "" {
		return fmt.Errorf("%s: %s: %s", op, reason, messageOf(err))
	}
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return fmt.Errorf("%s: %s: %s", op, connErr.Code(), connErr.Message())
	}
	// Neither a peer that named a reason nor one that answered at all: the relay
	// leg's own refusals, which carry a kind this layer does not render, and the
	// failures raised before a request exists. Those have no reason to surface and
	// their own text is the useful part.
	//
	// A signing failure does NOT arrive here, despite being local — it is named by
	// condition above, so it takes the first arm with a token and a fixed
	// sentence.
	return fmt.Errorf("%s: %w", op, err)
}

// detailOf pulls the RAMP ErrorDetail out of whichever outbound error shape
// carries one, or nil.
//
// The three shapes are walked in ONE place because the reason and the message
// are two views of the same detail, and reading them in two functions meant
// every new outbound error type had to be added to both in lockstep. They had
// already drifted apart on what happens when a shape matches but carries no
// detail, which is the drift this removes.
func detailOf(err error) *rampv1.ErrorDetail {
	var callErr *rampsdkconnect.CallError
	if errors.As(err, &callErr) && callErr.Detail != nil {
		return callErr.Detail
	}
	var rampErr *rampclient.Error
	if errors.As(err, &rampErr) && rampErr.Detail != nil {
		return rampErr.Detail
	}
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return connectDetail(connErr)
	}
	return nil
}

// reasonOf extracts the typed reason token from any of the outbound error
// shapes, as a short stable string an agent can branch on. Empty means the peer
// supplied none.
//
// The typed detail is read first, whichever shape carried it. Failing that, the
// SDK's own failure still has a class to report, and that class covers the
// refusals which never reached a peer at all — an address that failed a routing
// check, a signature custody would not produce. A Connect error cannot express
// those, because no call was made.
//
// Last, the condition read from the sentinel chain rather than from a type. A
// call whose key is resolved inside the signing transport fails as a transport
// error the RPC client has already wrapped, so there is no class left to read
// and the transport code would be reported instead — which names the peer for a
// fault that never left this process. Reading the condition here is what keeps
// one token on one condition across every leg, so an alert keyed on it covers
// all five tools rather than the three that happen to classify for themselves.
func reasonOf(err error) string {
	if name := rampreason.Name(detailOf(err)); name != "" {
		return name
	}
	var callErr *rampsdkconnect.CallError
	if errors.As(err, &callErr) {
		return callErr.ReasonOf()
	}
	if isNotSignable(err) {
		return rampsdkconnect.CallNotSignable.String()
	}
	return ""
}

// messageOf is the human-readable half that accompanies a typed reason.
//
// It falls through on an EMPTY detail message rather than on a missing detail,
// which is the one place the two readers legitimately differ. A peer can name a
// reason and leave the prose to the transport — a Connect refusal carrying a
// reason enum and nothing else is exactly that shape — and returning the
// detail's empty string there would drop the only sentence the peer sent. A
// reason has no such fallback: the transport code is not one, and reasonOf
// reports nothing rather than something an agent cannot branch on.
func messageOf(err error) string {
	if detail := detailOf(err); detail.GetMessage() != "" {
		return detail.GetMessage()
	}
	// Same treatment as on the delivery leg, and for the same reason: this
	// service's own failure to produce a signature describes its key store, its
	// configuration or its key material, address included. Every other failure's
	// cause is worth passing on and is passed on.
	if isNotSignable(err) {
		return notSignableMessage
	}
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return connErr.Message()
	}
	return err.Error()
}

// connectDetail returns the first RAMP ErrorDetail attached to a Connect error
// that actually names a reason. A detail carrying none is skipped rather than
// returned, so a peer that attached an empty one does not mask a later detail
// that named the cause.
func connectDetail(connErr *connect.Error) *rampv1.ErrorDetail {
	for _, d := range connErr.Details() {
		msg, err := d.Value()
		if err != nil {
			continue
		}
		detail, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if rampreason.Name(detail) != "" {
			return detail
		}
	}
	return nil
}
