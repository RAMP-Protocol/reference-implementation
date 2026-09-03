package mcp

import (
	"context"
	"log/slog"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// The dependency set every tool handler is a method on, the two helpers all five
// of them share, and the table that mounts them.
//
// This file is named for what it holds rather than for any tool, and that is the
// layout rule for the package: tools_<name>.go holds that tool and nothing else,
// so a reader looking for a tool opens its file and finds it. Anything five tools
// share belongs here; anything two of them share belongs in a file named for the
// pair. A mount table for five tools sitting under one tool's name sends the
// reader to the wrong file and hides the endpoint's surface in the last place
// they would look for it.

// toolset holds what the tool handlers need. It exists so the handlers are
// methods with one dependency set rather than closures capturing loose values.
type toolset struct {
	ramp rampCaller
	// discovery and reports are the legs the protocol SDK serves; ramp is what
	// this repository still implements. See ports.go for why the split is at the
	// seam rather than behind one interface.
	discovery discoverer
	reports   reporter
	// accounts opens and reports the caller's Exchange accounts. The two account
	// tools are decode-call-render over it: the workflow, its ordering and its
	// local notes are the service's, not the handler's.
	accounts *exchacct.Service
	// exchangeAllowed is the deployment's Exchange policy, asked here so an agent
	// gets a sentence naming it rather than a routing failure.
	exchangeAllowed exchangeAllowed
	// content fetches the licensed bytes for a delivered item. It signs as the
	// caller, using the same custodied key the offer acceptance was signed with —
	// which is the key the Exchange bound the delivery URL to.
	content contentFetcher
	// callTimeout bounds one ramp_execute's whole content leg, and
	// maxCallContentBytes what it may accumulate. Both are CALL-scoped, so they
	// live here rather than in the fetcher, which bounds one request and has no
	// notion of a batch.
	//
	// maxItemContentBytes mirrors the fetcher's own per-item cap. It is held here
	// only so the budget check can ask whether the NEXT body could still fit,
	// instead of admitting one and discovering the overrun afterwards.
	callTimeout         time.Duration
	maxCallContentBytes int64
	maxItemContentBytes int64
	// log is the construction-time logger, used only when a call arrives with no
	// request-scoped one. Handlers log through toolset.logger(ctx, caller).
	log *slog.Logger
	// directory builds a caller's directory origin. It is the OUTBOUND SIGNER's own
	// function (agentsign), not a copy of its logic: the Broker/Exchange authorize a
	// request by comparing the signed Signature-Agent origin to requester.id, so
	// the two values must be produced by the same code, not merely configured from
	// the same setting.
	directory func(subdomain string) string
}

// callCtx is the context every outbound leg and the service below it run under:
// the caller's context carrying this call's correlation id, plus the same
// request-scoped logger the handler logs through.
//
// The logger is attached rather than left to be found, because the one already
// on the context belongs to whichever request opened the SESSION, and a service
// reading that would stamp every line with the wrong request id.
//
// EVERY tool handler goes through this, not only the ones with a service under
// them that reads the logger today. caller.outbound is the correlation id alone
// and is what this builds on; no handler calls it directly, deliberately. Two
// forms for one concept would leave the next tool author picking one at random,
// and the choice decides whether a line added a layer down carries this call's
// request id or the session-open request's — the exact failure this helper
// exists to remove.
func (t *toolset) callCtx(ctx context.Context, who caller) context.Context {
	return reqctx.IntoContext(who.outbound(ctx), t.logger(ctx, who))
}

// agentDirectory is the caller's directory origin — its RAMP identity, matching
// the Signature-Agent the outbound signature carries. requester.id must be this,
// not the bare subdomain, or the Broker/Exchange reject the call as one agent
// trying to act on behalf of another.
func (t *toolset) agentDirectory(subdomain string) string {
	return t.directory(subdomain)
}

// register mounts every tool on srv. Adding a tool here is the ONLY way it
// becomes reachable, so this list is the endpoint's surface.
func (t *toolset) register(srv *mcpsdk.Server) {
	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_register",
		Description: "Open this agent's account at one RAMP Exchange, or return the existing one. " +
			"'exchange' is required: that Exchange's bare domain (\"exchange.example\" or " +
			"\"exchange.example:8081\"). 'fields' carries the registration details it asks " +
			"for, and an Exchange that asks for nothing needs none. " +
			"What to put in 'fields' is published by the Exchange itself, at " +
			"https://<exchange>/.well-known/ramp.json under account_registration.data_schema — " +
			"a JSON Schema naming the required and optional members. Read it and send members " +
			"that match; an Exchange publishing no schema asks for nothing in particular. " +
			"Submitting a registration accepts that Exchange's terms, the document at its " +
			"terms_uri, in the revision its terms_digest names — this call echoes that digest, " +
			"so the acceptance records which revision was agreed. Nothing is filled in for you. " +
			"Safe to call more than once: a repeat returns the same account handle.",
	}, t.handleRegister)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_status",
		Description: "List this agent's RAMP accounts. The answer is always a list of entries with " +
			"the same shape, each carrying a 'source' marker saying where it came from — read that " +
			"field first. Pass 'exchange' (a bare domain) to ask that Exchange directly: one entry, " +
			"source \"exchange\", fetched now and authoritative, with 'registered' saying whether " +
			"an account exists there — registered false is a normal answer, not an error. Omit " +
			"'exchange' to get every Exchange this adapter has registered the agent at, each source " +
			"\"local_hint\": those come from a local note, make no network call, can be out of " +
			"date, and miss any registration made outside this adapter — re-ask with 'exchange' to " +
			"confirm one. 'active' is null wherever nobody authoritative was asked. This tool does " +
			"not report what an Exchange requires to register; that is published in the Exchange's " +
			"own /.well-known/ramp.json.",
	}, t.handleStatus)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_discover",
		Description: "Find licensable offers for one or more URLs, or for a free-form query. " +
			"Returns one group per requested URL, each carrying that URL's offers. A URL with " +
			"nothing licensable comes back as an empty group with a reason, never silently dropped. " +
			"Pass an offer back unchanged to license it.",
	}, t.handleDiscover)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_execute",
		Description: "License one or more discovered offers and get a signed delivery URL for each. " +
			"Pass the offers ramp_discover returned, unchanged. A single offer is fine — it is just a " +
			"batch of one. Each result is licensed independently: a delivered item carries a delivery " +
			"URL and its transaction id, a refused one carries the reason. The content itself comes " +
			"back with the result, so there is nothing further to fetch.",
	}, t.handleExecute)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_report",
		Description: "Report usage of licensed content to the Exchange that issued the offer. " +
			"Reporting is a licensing obligation: an offer's terms may require it, and overdue " +
			"reports can get later purchases denied.",
	}, t.handleReport)
}
