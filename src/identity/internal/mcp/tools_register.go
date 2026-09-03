package mcp

import (
	"context"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerInput opens an account at one Exchange.
type registerInput struct {
	// Exchange is the bare domain of the Exchange to register at. Same value and
	// same rule as ramp_report's: a domain, never a URL, because the endpoint is
	// resolved from that Exchange's own manifest and a caller that could name the
	// endpoint would choose where a signed registration is sent.
	Exchange string `json:"exchange"`
	// Fields is the registration data that Exchange asks for, as its published
	// data_schema describes it.
	//
	// Nothing here is filled in on the agent's behalf. This adapter holds no view
	// of what any Exchange wants, and a payload assembled from our own store
	// would be one the agent never saw and could not correct — which is what the
	// old zero-argument form did.
	Fields map[string]any `json:"fields,omitempty"`
}

// registerOutput is the RegisterResponse projection, plus the Exchange it
// answers for. The domain is echoed because an agent registering at several
// Exchanges holds several of these, and an account handle alone does not say
// which one it belongs to.
type registerOutput struct {
	Exchange string `json:"exchange"`
	// BillingRef is the Exchange-minted account handle. Opaque, stable across
	// calls, and never accepted back as input — the Exchange resolves the account
	// from the request signature.
	BillingRef string `json:"billing_ref"`
	// Active reports whether the account may transact right now. An account can
	// exist and be inactive; the operator activates it out of band.
	//
	// A plain bool, unlike ramp_status's tri-state: the Exchange has just
	// answered about an account that now exists, so there is no "nobody
	// authoritative was asked" case for false to be confused with.
	Active bool `json:"active"`
	// RequestID is the correlation id this call ran under, quotable in a bug
	// report. Every tool returns it, so an agent never has to know which of the
	// five happens to carry one.
	RequestID string `json:"request_id,omitempty"`
}

// handleRegister opens the caller's account at the Exchange it names.
//
// Everything between the argument check and the answer is exchacct's: the
// requirements read, the pre-check, the send and the local note. What stays here
// is what a transport owns — who is calling, whether the argument is one this
// deployment will act on, and how the outcome reads.
func (t *toolset) handleRegister(
	ctx context.Context, req *mcpsdk.CallToolRequest, in registerInput,
) (*mcpsdk.CallToolResult, registerOutput, error) {
	const tool = "ramp_register"
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, registerOutput{}, err
	}
	if in.Exchange, err = t.checkExchangeArg(tool, in.Exchange); err != nil {
		return nil, registerOutput{}, err
	}
	acct, err := t.accounts.Register(t.callCtx(ctx, who), who.subdomain, in.Exchange, in.Fields)
	if err != nil {
		return nil, registerOutput{}, t.accountFailure(ctx, who, tool, err)
	}
	active := acct.IsActive()
	// The submitted fields are NOT on this line, and must never be: they are the
	// operator's business details, and this adapter passes them through without
	// logging or storing them.
	// acct.Exchange rather than the argument: it is the spelling the note store
	// and the wire used, so an operator filtering this event on the canonical
	// domain finds the call that created the account.
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.register",
		"subdomain", who.subdomain, "exchange", acct.Exchange, "active", active)
	return nil, registerOutput{
		Exchange:   acct.Exchange,
		BillingRef: acct.BillingRef,
		Active:     active,
		RequestID:  who.requestID,
	}, nil
}
