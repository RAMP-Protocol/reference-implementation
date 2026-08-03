package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/types/known/structpb"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// toolset holds what the tool handlers need. It exists so the handlers are
// methods with one dependency set rather than closures capturing loose values.
type toolset struct {
	ramp       rampCaller
	developers developerReader
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
		Description: "Create this agent's account on the RAMP Exchange, or return the existing one. " +
			"Takes no arguments: the account belongs to the signed-in developer, and the licensing " +
			"details submitted at sign-up are forwarded automatically. Safe to call more than once — " +
			"a repeat call returns the same account handle.",
	}, t.handleRegister)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name: "ramp_status",
		Description: "Report this agent's RAMP account state: its account handle and whether the " +
			"account is currently active. Takes no arguments. An inactive or absent account is why " +
			"a purchase would be refused.",
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

// noInput is the argument shape of a tool that takes none. The caller's identity
// comes from its bearer token, so a tool acting on "this agent" has nothing left
// to accept — and deliberately offers no field that could name a different agent.
type noInput struct{}

// accountOutput mirrors the account fields RegisterResponse and
// GetAccountStatusResponse share.
type accountOutput struct {
	// BillingRef is the Exchange-minted account handle. Opaque, stable across
	// calls, and never accepted back as input — the Exchange resolves the account
	// from the request signature.
	BillingRef string `json:"billing_ref"`
	// Active reports whether the account may transact right now. An account can
	// exist and be inactive; the operator activates it out of band.
	Active bool `json:"active"`
	// RequestID is the correlation id this call ran under, quotable in a bug
	// report. Every tool returns it, so an agent never has to know which of the
	// five happens to carry one.
	RequestID string `json:"request_id,omitempty"`
}

// handleRegister creates the caller's Exchange account.
//
// The Exchange derives WHO is registering from the verified request signature
// (ADR-017 D6), never from the payload, so this handler sends only the business
// details: the legal entity, address, and jurisdiction the developer supplied at
// sign-up. Those are read back from our own store rather than accepted as tool
// arguments — a caller must not be able to register under someone else's legal
// identity.
func (t *toolset) handleRegister(
	ctx context.Context, req *mcpsdk.CallToolRequest, _ noInput,
) (*mcpsdk.CallToolResult, accountOutput, error) {
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, accountOutput{}, err
	}
	data, err := t.registrationFor(ctx, who.subdomain)
	if err != nil {
		return nil, accountOutput{}, err
	}
	resp, err := t.ramp.Register(who.outbound(ctx), &rampv1.RegisterRequest{
		Ver:              rampproto.Ver,
		RegistrationData: data,
	})
	if err != nil {
		return nil, accountOutput{}, rampError("ramp_register", err)
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.register",
		"subdomain", who.subdomain, "active", resp.GetActive())
	return nil, accountOutput{
		BillingRef: resp.GetBillingRef(),
		Active:     resp.GetActive(),
		RequestID:  who.requestID,
	}, nil
}

// registrationFor reads the caller's own licensing details and packs them for the
// Exchange. It sits between the handler and the store so the handler stays a
// transport concern: read who is calling, delegate, shape the answer.
func (t *toolset) registrationFor(ctx context.Context, subdomain string) (*structpb.Struct, error) {
	developer, err := t.developers.BySubdomain(ctx, subdomain)
	if err != nil {
		return nil, developerLookupError(subdomain, err)
	}
	return registrationData(developer)
}

// handleStatus reports the caller's account state.
func (t *toolset) handleStatus(
	ctx context.Context, req *mcpsdk.CallToolRequest, _ noInput,
) (*mcpsdk.CallToolResult, accountOutput, error) {
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, accountOutput{}, err
	}
	resp, err := t.ramp.AccountStatus(who.outbound(ctx),
		&rampv1.GetAccountStatusRequest{Ver: rampproto.Ver})
	if err != nil {
		return nil, accountOutput{}, rampError("ramp_status", err)
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.status",
		"subdomain", who.subdomain, "active", resp.GetActive())
	return nil, accountOutput{
		BillingRef: resp.GetBillingRef(),
		Active:     resp.GetActive(),
		RequestID:  who.requestID,
	}, nil
}

// registrationData packs the developer's licensing details into the
// operator-defined payload the Exchange stores without inspecting. The field
// names match what the sign-up form collected, so the Exchange's system of record
// sees the same vocabulary the developer filled in.
func registrationData(d account.Developer) (*structpb.Struct, error) {
	data, err := structpb.NewStruct(map[string]any{
		"legal_entity":         d.LegalEntity,
		"address":              d.Address,
		"jurisdiction_country": d.JurisdictionCountry,
		"email":                d.Email,
		"subdomain":            d.Subdomain,
	})
	if err != nil {
		return nil, fmt.Errorf("ramp_register: build registration payload: %w", err)
	}
	return data, nil
}

// developerLookupError maps a store failure to a caller-facing one. A missing
// account is the interesting case: it means the bearer names a developer we have
// no record of, which is a real inconsistency rather than a routine "not found",
// so it is reported as such instead of being passed off as a RAMP-side refusal.
// Every error a tool returns is prefixed with that tool's name, so an agent
// reading a failure knows which call produced it without inferring from wording.
func developerLookupError(subdomain string, err error) error {
	if errors.Is(err, account.ErrNotFound) {
		return fmt.Errorf("ramp_register: no developer account for %q — sign up before registering", subdomain)
	}
	return fmt.Errorf("ramp_register: read developer account: %w", err)
}
