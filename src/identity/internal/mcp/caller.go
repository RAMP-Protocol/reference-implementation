package mcp

import (
	"context"
	"log/slog"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
)

// caller is the authenticated agent behind one tool call, resolved once at the
// top of each handler.
type caller struct {
	// subdomain is the agent's directory subdomain — the durable RAMP identity
	// the outbound signature is made with.
	subdomain string
	// requestID correlates this tool call with the HTTP request that carried it.
	requestID string
}

// callerFrom resolves who is making THIS call.
//
// The identity is taken from the per-request TokenInfo the SDK hands the handler,
// not from the context, and the reason is subtle enough to be worth stating: the
// context a tool handler receives is the one the SDK captured when the SESSION was
// established, not the one belonging to the request being served (the SDK passes
// req.Context() to server.Connect once, at connect time, and the jsonrpc2 layer
// detaches it thereafter). Reading identity off that context means reading whoever
// opened the session. That is correct today only because the SDK independently
// pins a session to the TokenInfo.UserID that created it and refuses a mismatch —
// i.e. the invariant holds through an external library's behaviour rather than
// through anything asserted here.
//
// So: prefer the per-request value, fall back to the context when the SDK supplies
// no Extra, and FAIL CLOSED when the two disagree. A disagreement means the
// session-pinning assumption no longer holds, and the safe reading of "two answers
// to whose key signs this" is neither.
func callerFrom(ctx context.Context, req *mcpsdk.CallToolRequest) (caller, error) {
	fromCtx := agentsign.SubdomainFromContext(ctx)
	c := caller{subdomain: fromCtx}

	extra := extraOf(req)
	if extra == nil {
		if fromCtx == "" {
			return caller{}, errNoIdentity
		}
		return c, nil
	}
	if extra.Header != nil {
		c.requestID = extra.Header.Get(reqctx.HeaderRequestID)
	}
	if extra.TokenInfo == nil || extra.TokenInfo.UserID == "" {
		if fromCtx == "" {
			return caller{}, errNoIdentity
		}
		return c, nil
	}
	if fromCtx != "" && fromCtx != extra.TokenInfo.UserID {
		return caller{}, errIdentityMismatch
	}
	c.subdomain = extra.TokenInfo.UserID
	return c, nil
}

// extraOf returns the per-request extras, tolerating a nil request so a direct
// unit call does not panic.
func extraOf(req *mcpsdk.CallToolRequest) *mcpsdk.RequestExtra {
	if req == nil {
		return nil
	}
	return req.Extra
}

// logger returns the request-scoped logger for this call, so every tool line
// carries request_id like the rest of the service. The construction-time logger
// is the fallback, and the id is re-attached explicitly because the context the
// handler holds is the session's, whose scoped logger carries the id of whichever
// request opened the session rather than this one.
func (t *toolset) logger(ctx context.Context, c caller) *slog.Logger {
	if c.requestID != "" {
		// This call has its own correlation id. Start from the construction-time
		// logger, which carries NO request_id, so the id is stamped exactly once.
		// The context logger already holds the session-open request's id, and slog
		// appends attributes rather than replacing them — building on it would emit
		// two conflicting request_id keys on every line.
		return t.log.With("request_id", c.requestID)
	}
	// No id of this call's own: fall back to the context's scoped logger, which
	// carries the id the middleware minted for the request that opened the session.
	if base := reqctx.FromContext(ctx); base != nil {
		return base
	}
	return t.log
}

// outbound returns the context the RAMP client should run under: the caller's
// context plus this call's correlation id, so an outbound leg travels under the
// same id as the tool call that caused it.
func (c caller) outbound(ctx context.Context) context.Context {
	if c.requestID == "" {
		return ctx
	}
	return reqctx.WithID(ctx, c.requestID)
}
