package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
)

// executeInput licenses one or more discovered offers. A single offer is not
// special-cased — it is the degenerate 1-element batch.
type executeInput struct {
	// Offers are the offers to license, each the FULL object ramp_discover
	// returned, handed back unchanged. Their signatures cover those bytes, so an
	// edited offer will not verify at the Exchange.
	Offers []map[string]any `json:"offers"`
	// IdempotencyKey makes a retried purchase safe: the Exchange dedupes on it and
	// returns the original result rather than charging twice. Optional — a fresh
	// key is minted when absent, so a plain call always executes; supply the same
	// value to retry the same purchase.
	//
	// NOTE the deliberate asymmetry with ramp_report, which REQUIRES this field.
	// The two tools take opposite positions on the same field name because the
	// cost of an absent key differs: a report without one is a silent
	// double-count, whereas a purchase without one is a caller who did not intend
	// a retry at all, and refusing it would make the common single-shot call
	// impossible to write. A caller that retries MUST pass the original key —
	// omitting it on a retry is a second purchase, and it will be charged as one.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// executeOutput is the TransactionResponse projection.
type executeOutput struct {
	// AgentIdentityHash is the RFC 7638 thumbprint every item's delivery URL is
	// bound to — the caller's own key. Shared across the batch.
	AgentIdentityHash string `json:"agent_identity_hash,omitempty"`
	// Items holds one result per offer, in the order they were submitted, each the
	// protocol's own TransactionResultItem encoding. There is deliberately no
	// per-item "licensed" boolean: an item is the protocol's own object and adding
	// a field of ours to it would corrupt an encoding the agent may hand back. Read
	// it as: a DELIVERED item carries retrieval_endpoint (and expires_at); a
	// REFUSED item carries denial_reason. Exactly one of the two is always present.
	Items []map[string]any `json:"items"`
	// DeliveryFailures reports the delivered items whose content this service could
	// not fetch. An entry appears ONLY for a failure — a success is evident from the
	// embedded resource carrying the bytes — and it sits outside items[] for the
	// same reason there is no per-item "licensed" boolean above.
	//
	// A failure here is not a failed purchase: the item was licensed and charged
	// for, and its retrieval_endpoint is still valid, so an agent that can reach the
	// edge itself may simply fetch it.
	DeliveryFailures []deliveryFailure `json:"delivery_failures,omitempty"`
	// RequestID is the correlation id this call ran under, quotable in a bug report.
	RequestID string `json:"request_id,omitempty"`
}

// handleExecute licenses the offers through the Broker's execute relay.
//
// The relay is the one RAMP call that is not a Connect route. The agent's binding
// travels as a detached acceptance per item — signed with the caller's custodied
// key inside the RAMP client — so the Exchange verifies the agent independently of
// however many hops relayed the request.
//
// It returns the signed delivery URL per item AND the content itself: the URL is
// bound to the caller's custodied key, which lives in Vault and never reaches the
// agent, so this service is the only party that can satisfy the edge's
// proof-of-possession check (ADR-023). The bytes ride back as embedded resources
// on the tool result; nothing is stored, because the fetch happens inside the
// call that pays for it.
func (t *toolset) handleExecute(
	ctx context.Context, req *mcpsdk.CallToolRequest, in executeInput,
) (*mcpsdk.CallToolResult, executeOutput, error) {
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, executeOutput{}, err
	}
	if len(in.Offers) == 0 {
		return nil, executeOutput{}, errors.New("ramp_execute needs at least one offer")
	}
	rpc, err := buildTransactionRequest(t.requester(who.subdomain), in)
	if err != nil {
		return nil, executeOutput{}, err
	}
	resp, err := t.ramp.Execute(t.callCtx(ctx, who), rpc)
	if err != nil {
		return nil, executeOutput{}, t.failed(ctx, who, "ramp_execute", err)
	}
	out, err := projectTransaction(resp)
	if err != nil {
		return nil, executeOutput{}, err
	}
	out.RequestID = who.requestID
	log := t.logger(ctx, who)
	blocks := t.deliver(t.callCtx(ctx, who), log, who, in, &out)
	log.InfoContext(ctx, "identity.mcp.execute",
		"subdomain", who.subdomain, "offers", len(in.Offers), "items", len(out.Items),
		"delivery_failures", len(out.DeliveryFailures))
	return &mcpsdk.CallToolResult{Content: blocks}, out, nil
}

// buildTransactionRequest assembles the batch from the caller's offers. requester
// is the caller's RAMP identity, built from the authenticated context and never
// from the input. The acceptances themselves are signed later, inside the RAMP
// client, where the caller's private key lives.
func buildTransactionRequest(
	requester *rampv1.Requester, in executeInput,
) (*rampv1.TransactionRequest, error) {
	items := make([]*rampv1.TransactionItem, 0, len(in.Offers))
	for i, raw := range in.Offers {
		offer, err := mapToOffer(raw)
		if err != nil {
			return nil, fmt.Errorf("ramp_execute: offer %d is malformed: %w", i, err)
		}
		items = append(items, &rampv1.TransactionItem{Offer: offer})
	}
	key := in.IdempotencyKey
	if key == "" {
		key = "idem-" + uuid.NewString()
	}
	return &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: key,
		Requester:      requester,
		Items:          items,
	}, nil
}

// mapToOffer turns the generic JSON object ramp_discover handed the agent back
// into an Offer. Round-tripping through the map rather than re-modelling the offer
// is deliberate: the offer's signature covers its bytes, so reconstructing it
// field by field risks dropping one and invalidating the signature.
func mapToOffer(raw map[string]any) (*rampv1.Offer, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode offer: %w", err)
	}
	var offer rampv1.Offer
	if err = protojson.Unmarshal(encoded, &offer); err != nil {
		return nil, fmt.Errorf("decode offer: %w", err)
	}
	return &offer, nil
}

// projectTransaction renders the response for the agent, carrying each result
// item across as the protocol's own encoding rather than a hand-written mirror
// that would have to track every field change.
func projectTransaction(resp *rampv1.TransactionResponse) (executeOutput, error) {
	items := make([]map[string]any, 0, len(resp.GetItems()))
	for _, item := range resp.GetItems() {
		obj, err := protoToMap(item)
		if err != nil {
			return executeOutput{}, fmt.Errorf("ramp_execute: render result item %q: %w",
				item.GetOfferId(), err)
		}
		items = append(items, obj)
	}
	return executeOutput{
		AgentIdentityHash: resp.GetAgentIdentityHash(),
		Items:             items,
	}, nil
}
