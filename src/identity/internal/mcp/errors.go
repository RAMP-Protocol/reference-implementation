package mcp

import (
	"errors"
	"fmt"
	"net/url"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/delivery"
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
	var deliveryErr *delivery.Error
	if errors.As(err, &deliveryErr) {
		return deliveryErr.ReasonOf(), deliveryCause(err)
	}
	return delivery.KindUnknown.String(), deliveryCause(err)
}

// deliveryCause is the failure's cause with any delivery URL kept out of it, for
// the log line beside the agent-facing message above.
//
// On an unreachable fetch the wrapped cause is a *url.Error, and its Error()
// embeds the whole request URL — query included, which is where a delivery URL
// keeps its credential. Unwrapping past it preserves the part worth diagnosing
// ("connection refused", "context deadline exceeded") and drops the part that
// must not outlive the fetch. Every other kind already renders safely: the
// fetcher redacts its own malformed-URL message, and the rest carry no URL.
func deliveryCause(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
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
	// Not a transport-level refusal: a dial failure, a timeout, a blocked target,
	// or a local signing failure (custody down, no active key, unauthenticated).
	// Those carry no ErrorDetail and their own text is the useful part.
	return fmt.Errorf("%s: %w", op, err)
}

// reasonOf extracts the typed reason token from either outbound error shape, as a
// short stable string an agent can branch on. Empty means the peer supplied none.
func reasonOf(err error) string {
	var rampErr *rampclient.Error
	if errors.As(err, &rampErr) {
		return rampErr.Reason()
	}
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return detailReason(connErr)
	}
	return ""
}

// messageOf is the human-readable half that accompanies a typed reason.
func messageOf(err error) string {
	var rampErr *rampclient.Error
	if errors.As(err, &rampErr) && rampErr.Detail != nil {
		return rampErr.Detail.GetMessage()
	}
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return connErr.Message()
	}
	return err.Error()
}

// detailReason extracts the typed reason from the first RAMP ErrorDetail attached
// to a Connect error. An error with no detail — or one whose detail carries no
// reason — yields the empty string, and the caller falls back to the code.
func detailReason(connErr *connect.Error) string {
	for _, d := range connErr.Details() {
		msg, err := d.Value()
		if err != nil {
			continue
		}
		detail, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if name := rampclient.ReasonName(detail); name != "" {
			return name
		}
	}
	return ""
}
