// Package rampaudience refuses a RAMP request that names a different recipient.
//
// Every addressed request states, in its own body, which party the sender meant
// it for. That statement is needed because the RFC 9421 signature does not carry
// it: a signature proves the sender signed the URL IT DIALLED, and that URL is
// resolved from a fetched, cached /.well-known/ramp.json. Poison or stale that
// resolution and the request arrives somewhere else with every signature still
// verifying. The body field says who the sender meant, and the genuine recipient
// refuses a request that names anybody else.
//
// The comparison itself is the protocol SDK's helpers.CheckAudience — this
// package holds no rule of its own. What it adds is the two things a Connect
// server needs around that call: finding the values a given request states, and
// turning the SDK's verdict into a status code. Both services mount it, so the
// question is asked in one place rather than once per handler.
package rampaudience

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// recipientField is the name the protocol gives the recipient on every addressed
// request. Reading it off the descriptor by this name — rather than listing the
// message types that carry it — is what keeps this package from drifting behind
// the proto: a request type that gains the field is covered the day it does.
const recipientField = "exchange"

// Interceptor refuses a request addressed to a different Exchange, before the
// handler runs and therefore before any database is touched.
//
// It is deliberately an interceptor and not a line in each handler. The check is
// the same question for every addressed RPC, it has to run first, and a handler
// that forgot to ask it would look exactly like a handler that asked and got a
// pass. Mounting it once means a new addressed RPC arrives already guarded.
type Interceptor struct {
	// self is this service's own published identity domain — the value it
	// stamps into the offers it issues, NOT the host its process listens on.
	// The two are allowed to differ, and an operator who configures the
	// listening host here would refuse every request that named them correctly.
	self string
}

// NewInterceptor builds the interceptor for a service whose published identity
// is self.
//
// A self that is not a bare domain is refused HERE, at construction, so the
// process fails to boot. Left to run time it would surface as an internal error
// on every call, which reads to each caller as our fault in a way that says
// nothing about which setting is wrong.
func NewInterceptor(self string) (*Interceptor, error) {
	if !helpers.IsBareDomain(self) {
		return nil, fmt.Errorf(
			"rampaudience: own identity %q is not a bare domain — it must be the domain "+
				"this service publishes (\"exchange.example\" or \"exchange.example:8081\"), "+
				"not the host it listens on", self,
		)
	}
	return &Interceptor{self: self}, nil
}

// WrapUnary checks the recipient every arriving unary request names.
//
// A request that names no recipient at all is refused rather than waved through.
// Treating an absent value as "the caller did not claim one, so let it pass" is
// what made the check optional for whoever was sending, which is the posture the
// required field exists to end.
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// Client-side calls run through the same interface. Only a server is a
		// recipient, so only a server has an audience to check.
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		msg, ok := req.Any().(proto.Message)
		if !ok {
			return next(ctx, req)
		}
		claimed, addressed := Recipients(msg)
		if !addressed {
			return next(ctx, req)
		}
		if err := i.check(ctx, req.Spec().Procedure, msg, claimed); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient passes through: this service opens no streams, and a
// client is not a recipient.
func (i *Interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler passes through. Every RPC the two RAMP services serve is
// unary, so there is no streaming request carrying a recipient to check — and a
// streaming one would arrive here UNCHECKED, which is why the guard test asserts
// that every served method is unary rather than leaving the claim to this
// comment.
func (i *Interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// check turns the SDK's verdict into a status code carrying a typed detail.
//
// The split the SDK draws is the one that matters here: everything the REQUEST
// can get wrong comes back as a verdict, and only an unusable identity of OUR
// OWN comes back as an error. So a request fault is reported to the caller as
// their invalid argument, and a deployment fault is reported as ours. The three
// request verdicts share a code because they are the same answer to the caller —
// this request is not one we will act on — and differ in the reason, which is
// what a client branches on.
//
// Every refusal carries an ErrorDetail and is logged. The detail is the generic
// envelope, not a typed reason: no protocol enum covers a wrong recipient, so
// what a client can branch on is the verdict token in the detail's metadata,
// alongside the field the fault is about. The sibling refusal one hop away — the
// Broker rejecting an item whose offer names no exchange — is built the same
// generic way and names the same field, so a caller comparing the two finds one
// description of one class of fault. If a wrong recipient ever deserves a typed
// reason, that is a request for one in the protocol module, not something this
// package can invent.
func (i *Interceptor) check(
	ctx context.Context, procedure string, msg proto.Message, claimed []string,
) error {
	verdict, index, err := i.judge(claimed)
	if err != nil {
		// Unreachable while NewInterceptor is the only constructor, which is why
		// it is mapped rather than assumed away: the day a second path builds one,
		// this answers with the code a broken deployment deserves.
		i.log(ctx, slog.LevelError, procedure, verdict.String(), err.Error())
		return connect.NewError(connect.CodeInternal,
			fmt.Errorf("rampaudience: cannot check the recipient: %w", err))
	}
	if verdict == helpers.AudienceAccepted {
		return nil
	}
	message, ok := refusals[verdict]
	if !ok {
		// The zero value and anything the SDK might add later. Refused rather
		// than passed, so a verdict this package does not know ends as a
		// rejection and not an acceptance.
		i.log(ctx, slog.LevelError, procedure, verdict.String(), "unknown verdict")
		return connect.NewError(connect.CodeInternal,
			fmt.Errorf("rampaudience: unusable recipient verdict %q", verdict))
	}
	i.log(ctx, slog.LevelWarn, procedure, verdict.String(), message)
	return connectserver.AttachErrorDetail(
		connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%s: %s", fieldFor(msg), message)),
		serviceDomain(procedure),
		message,
		refusalMeta(msg, verdict, index),
	)
}

// judge asks the SDK's question one claimed value at a time, so a refusal can
// say WHICH value was the problem. Handing the whole list over at once returns
// one verdict and no position, which leaves a caller with a twenty-item batch
// knowing only that some item named somebody else. The first value that is not
// accepted decides, which is the order the SDK's own loop uses.
func (i *Interceptor) judge(claimed []string) (helpers.AudienceVerdict, int, error) {
	if len(claimed) == 0 {
		// A message that states no values at all. Asked of the SDK rather than
		// answered here, so the empty verdict and an unusable identity of our own
		// still come back from the one place that decides them.
		verdict, err := helpers.CheckAudience(i.self)
		return verdict, 0, err
	}
	for index, value := range claimed {
		verdict, err := helpers.CheckAudience(i.self, value)
		if err != nil || verdict != helpers.AudienceAccepted {
			return verdict, index, err
		}
	}
	return helpers.AudienceAccepted, 0, nil
}

// refusalMeta is what a client reads off the refusal: the field the fault is
// about, the verdict, and — for a message whose audience is per item — which
// item. The keys are the Broker's, because the Broker refuses the same field one
// hop away and a client should not need a second vocabulary for the second
// service.
func refusalMeta(msg proto.Message, verdict helpers.AudienceVerdict, index int) map[string]string {
	meta := map[string]string{"field": fieldFor(msg), "verdict": verdict.String()}
	if perItemAudience(msg) {
		meta["item_index"] = strconv.Itoa(index)
	}
	return meta
}

// refusals is the sentence each request-fault verdict is reported with. The
// authoritative reason is the verdict token in the detail's metadata; this is
// the developer-facing half ADR-019 marks non-authoritative.
var refusals = map[helpers.AudienceVerdict]string{
	helpers.AudienceEmpty: "the request names no recipient — every addressed request must " +
		"carry the domain of the party it is meant for",
	helpers.AudienceMalformed: "the named recipient is not a bare domain — a scheme, path, " +
		"query or fragment is not part of one",
	// The value the caller sent is echoed by the caller's own copy of it; ours is
	// not named. What the caller needs is to see that the name they addressed is
	// not us, and naming ours would answer "which Exchange lives at this address"
	// for anyone who asks with a guess.
	helpers.AudienceMismatch: "this request is addressed to a different Exchange",
}

// fieldFor names the field the refusal is about, in the spelling the message
// actually uses. A TransactionRequest states its recipient per item, so a caller
// pointed at a top-level "exchange" would look for a field that does not exist.
//
// The per-item spelling is the Broker's, verbatim: it refuses the same field on
// the same message and reports "offer.exchange" with the position in
// "item_index". Two spellings for one proto field would make a client handle the
// Exchange's refusal and the Broker's as different faults.
func fieldFor(msg proto.Message) string {
	if perItemAudience(msg) {
		return "offer.exchange"
	}
	return recipientField
}

// perItemAudience reports whether the message states its recipient once per
// item rather than once for the message.
func perItemAudience(msg proto.Message) bool {
	_, ok := msg.(*rampv1.TransactionRequest)
	return ok
}

// serviceDomain is the ErrorInfo-compatible grouping key: the fully-qualified
// service name, read off the procedure this call arrived on rather than
// configured. One interceptor instance serves several mounts — the Exchange puts
// it on both its RAMP services — so a configured value would be wrong on all but
// one of them.
func serviceDomain(procedure string) string {
	trimmed := strings.TrimPrefix(procedure, "/")
	if idx := strings.LastIndex(trimmed, "/"); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}

// log records the refusal against the request-scoped logger, so a refused call
// leaves a trace on this side too. Without it the only record of a
// wrong-recipient request is the caller's, and an operator debugging "my agent
// gets invalid_argument" has nothing to read.
//
// The RPC goes under "path", the key the signature gate's own rejection writes
// for the same value, so one query finds every rejection of a request rather
// than one query per key.
//
// The level is the caller's, because the two faults this reports are not one
// severity. A refused request is ordinary traffic and warns. An own identity we
// cannot use, or a verdict this package does not know, is our deployment
// failing every caller — an operator alerting on error level has to see it, and
// would see nothing if it warned alongside the ordinary refusals.
func (i *Interceptor) log(ctx context.Context, level slog.Level, path, verdict, message string) {
	reqctx.FromContext(ctx).Log(ctx, level, "rampaudience.refused",
		"path", path, "verdict", verdict, "self", i.self, "reason", message)
}

// Recipients returns the recipient values a request states, and whether the
// request is addressed at all.
//
// Two shapes, because the protocol has two. Almost every addressed request
// carries one top-level `exchange` field, and this reads it off the message
// descriptor by name rather than from a list of types — the rule then lives in
// the proto, where it belongs, and a new request type that carries the field is
// covered without an edit here.
//
// TransactionRequest is the documented exception: it has no top-level field
// because its audience already exists per item, inside each item's
// Exchange-signed Offer. An intermediary cannot redirect an execute call without
// invalidating that signature, so a top-level field would only add a
// top-level-versus-items mismatch to police. Every item is returned, and
// CheckAudience is variadic, so one call decides them all.
//
// A message with neither is not addressed, and DiscoveryRequest is the reason.
// It travels one direct hop from agent to Broker and stops there: the Broker
// never forwards it, it authors fresh per-Exchange queries from it, and those
// legs carry the field. The agent could not name the recipients in any case,
// because choosing the fan-out set is the Broker's job.
//
// That is a statement about what the protocol gives this message, not a claim
// that the hop is bound to one Broker. It is not bound: the SDK rebuilds the
// signed @target-uri from the ARRIVING request, falling back to its Host header,
// and the server binding passes no expected host into verification. A captured
// discovery request replayed at a second Broker, with the Host it was signed
// for, therefore verifies there — the nonce is new in that Broker's own replay
// store. A recipient field is what refuses that on the messages that carry one;
// DiscoveryRequest carries none, so for discovery the exposure stands.
func Recipients(msg proto.Message) (claimed []string, addressed bool) {
	if tx, ok := msg.(*rampv1.TransactionRequest); ok {
		items := tx.GetItems()
		if len(items) == 0 {
			// No items means no audience statement anywhere in the message.
			// Reported as addressed-with-nothing-claimed rather than as not
			// addressed, so it is refused: an execute request that names no
			// Exchange is exactly what this check exists to stop, and
			// protovalidate's own items rule is not this package's to rely on.
			return nil, true
		}
		claimed = make([]string, 0, len(items))
		for _, item := range items {
			claimed = append(claimed, item.GetOffer().GetExchange())
		}
		return claimed, true
	}
	field := msg.ProtoReflect().Descriptor().Fields().ByName(recipientField)
	if field == nil || field.Kind() != protoreflect.StringKind || field.IsList() {
		return nil, false
	}
	return []string{msg.ProtoReflect().Get(field).String()}, true
}
