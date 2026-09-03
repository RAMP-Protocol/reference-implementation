package mcp

import (
	"context"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Where an entry's information came from. It is the first field an agent should
// read, because it decides how much the rest of the entry is worth.
const (
	// sourceExchange is what that Exchange said during this call.
	sourceExchange = "exchange"
	// sourceLocalHint is what this adapter last saw and has not re-checked.
	sourceLocalHint = "local_hint"
)

// statusInput asks about one Exchange, or about all of them.
type statusInput struct {
	// Exchange is the bare domain to ask directly. Omit it to list every
	// Exchange this adapter has registered the agent at, from a local note and
	// with no network call.
	Exchange string `json:"exchange,omitempty"`
}

// accountEntry is one account, in ONE shape whichever mode produced it.
//
// A single shape rather than one per mode is deliberate: two shapes from one
// tool means an agent has to branch on which arguments it passed to know how to
// read the answer, and agents handle that badly. The honesty about where each
// answer came from is per entry instead, in Source.
type accountEntry struct {
	// Exchange is the bare domain this entry is about.
	Exchange string `json:"exchange"`
	// Source says where the entry came from — read it first.
	Source string `json:"source"`
	// Registered is whether an account exists.
	//
	// Under "exchange" it is that Exchange's own answer as of AsOf, and false is
	// a normal answer rather than a failure. Under "local_hint" it says only that
	// this adapter saw a registration accepted at AsOf, which the Exchange may
	// since have undone.
	Registered bool `json:"registered"`
	// Active is whether the account may transact right now.
	//
	// Null whenever nobody authoritative was asked: every hint, and an Exchange
	// answer for an account that does not exist. Reporting false there would say
	// an existing account is suspended, which is a different fact.
	Active *bool `json:"active"`
	// BillingRef is the Exchange-minted account handle. Empty wherever no
	// authority reported one: every hint, and an Exchange answer for an account
	// that does not exist.
	//
	// Always emitted, never omitted, and that is the "one schema" rule biting: a
	// member that disappears in one mode makes the two answers different shapes,
	// which is exactly the branching this tool's output exists to avoid.
	BillingRef string `json:"billing_ref"`
	// AsOf is when this entry's information was established: the moment of this
	// call for "exchange", the last accepted registration or confirmed status for
	// "local_hint". RFC 3339.
	AsOf string `json:"as_of"`
}

// statusOutput is always a list, in both modes.
type statusOutput struct {
	// Accounts is empty when this adapter has registered the agent nowhere. That
	// is an answer, never an error.
	Accounts []accountEntry `json:"accounts"`
	// RequestID is the correlation id this call ran under.
	RequestID string `json:"request_id,omitempty"`
}

// handleStatus reports the caller's accounts.
func (t *toolset) handleStatus(
	ctx context.Context, req *mcpsdk.CallToolRequest, in statusInput,
) (*mcpsdk.CallToolResult, statusOutput, error) {
	const tool = "ramp_status"
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, statusOutput{}, err
	}
	var entries []accountEntry
	if in.Exchange == "" {
		entries, err = t.statusHints(ctx, who, tool)
	} else {
		entries, err = t.statusFromExchange(ctx, who, tool, in.Exchange)
	}
	if err != nil {
		return nil, statusOutput{}, err
	}
	return nil, statusOutput{Accounts: entries, RequestID: who.requestID}, nil
}

// statusFromExchange asks one Exchange and returns its answer as the single
// authoritative entry.
//
// "No account here" is not an error on this path. exchacct answers it as an
// account that is simply not registered, so an agent working out where it still
// needs to register reads it as data rather than catching a failure.
func (t *toolset) statusFromExchange(
	ctx context.Context, who caller, tool, exchange string,
) ([]accountEntry, error) {
	exchange, err := t.checkExchangeArg(tool, exchange)
	if err != nil {
		return nil, err
	}
	acct, err := t.accounts.Status(t.callCtx(ctx, who), who.subdomain, exchange)
	if err != nil {
		return nil, t.accountFailure(ctx, who, tool, err)
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.status",
		"subdomain", who.subdomain, "exchange", acct.Exchange,
		"registered", acct.Registered, "active", acct.IsActive())
	return []accountEntry{{
		Exchange:   acct.Exchange,
		Source:     sourceExchange,
		Registered: acct.Registered,
		Active:     acct.Active,
		BillingRef: acct.BillingRef,
		AsOf:       stamp(acct.AsOf),
	}}, nil
}

// statusHints lists what this adapter last saw, without touching the network.
//
// The list is a HINT and the entries say so. It can miss a registration made
// outside this adapter, and it can name one the Exchange has since closed —
// which is why the per-Exchange call remains the authoritative answer and why
// this one carries no billing reference and no activity.
func (t *toolset) statusHints(ctx context.Context, who caller, tool string) ([]accountEntry, error) {
	hints, err := t.accounts.Hints(t.callCtx(ctx, who), who.subdomain)
	if err != nil {
		// Through the same renderer as every other account failure, so this one
		// reaches the operator on the same event at the same level with the same
		// op field. The sentence the agent gets is still this store's own; see
		// notesUnavailable.
		return nil, t.accountFailure(ctx, who, tool, err)
	}
	entries := make([]accountEntry, 0, len(hints))
	for _, hint := range hints {
		entries = append(entries, accountEntry{
			Exchange:   hint.Exchange,
			Source:     sourceLocalHint,
			Registered: true,
			AsOf:       stamp(hint.AsOf),
		})
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.status.hints",
		"subdomain", who.subdomain, "count", len(entries))
	return entries, nil
}

// stamp renders an instant for the wire. RFC 3339 in UTC, so two entries from
// different sources are directly comparable.
func stamp(at time.Time) string {
	return at.UTC().Format(time.RFC3339)
}
