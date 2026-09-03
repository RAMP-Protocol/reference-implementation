package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampreason"
)

// discoverInput asks for offers by URL, by free-form query, or both. At least one
// is required — a request naming nothing to license has no answer.
type discoverInput struct {
	// URIs are the exact resources to price. Each one comes back as its own
	// group, so a batch never loses track of which offers belong to which URL.
	URIs []string `json:"uris,omitempty"`
	// Query is a free-form description of the wanted content, for when the agent
	// has no URL yet.
	Query string `json:"query,omitempty"`
}

// discoverOutput is the DiscoveryResponse projection.
type discoverOutput struct {
	// OfferGroups holds one entry per requested URI, in request order.
	OfferGroups []offerGroup `json:"offer_groups"`
	// AbsenceReason explains a whole response that yielded nothing. Empty when
	// any group carries offers. A refusal is a successful answer, not an error:
	// "nothing licensable here" is information the agent asked for.
	AbsenceReason string `json:"absence_reason,omitempty"`
	// RequestID is the correlation id this call ran under. Returned so an agent
	// reporting a problem can quote the id that appears in our logs.
	RequestID string `json:"request_id,omitempty"`
}

// offerGroup is one requested URL and what could be licensed for it.
type offerGroup struct {
	// URI is the resource this group answers for.
	URI string `json:"uri"`
	// Licensed reports whether anything can be licensed for this URI. It is
	// redundant with len(offers) > 0 and stated anyway: an explicit boolean is a
	// contract, whereas "infer it from whether a list is empty" is a convention
	// each caller re-derives and some get wrong.
	Licensed bool `json:"licensed"`
	// Offers are the licensable offers, each the complete signed object exactly
	// as the Exchange issued it. Pass one back UNCHANGED to license it: the
	// offer's signature covers these bytes, and editing any field — even
	// re-ordering during a round-trip through a lossy model — invalidates it.
	Offers []map[string]any `json:"offers"`
	// Rejected names the offers that failed verification, and why. They are
	// VISIBLE but not licensable: an agent that receives two offers where it
	// expected three can tell a thin catalog from a signature that did not check
	// out, which is otherwise indistinguishable from silence.
	//
	// The offer itself is deliberately NOT carried. An agent licenses by handing
	// an offer back, and the purchase path does not yet re-verify what it is
	// handed, so returning a rejected offer in full would hand back the one thing
	// that must not be submitted. The id is enough to correlate it with a log
	// line; the reason is enough to act on.
	Rejected []rejectedOffer `json:"rejected,omitempty"`
	// AbsenceReason explains an empty group: not in catalog, no offers,
	// entitlement or budget absent, upstream briefly unavailable. A URL with
	// nothing to sell is reported here rather than dropped, so the agent can tell
	// "refused" from "never asked".
	AbsenceReason string `json:"absence_reason,omitempty"`
	// DiscoveryMethod says how the Broker found this URL: the agent named it, or
	// the Broker chose it on the agent's behalf. The Broker decides the value,
	// because it is the only component that knows which of those happened. This
	// tool accepts a free-text query as well as uris, but the query path returns
	// no groups yet, so every group an agent actually receives today came from a
	// URL it named and reads DISCOVERY_METHOD_EXCHANGE. It is projected because
	// that stops being true once the query path can answer, and an agent that
	// never saw the field would have no way to tell a URL it asked for from one
	// that was found for it.
	DiscoveryMethod string `json:"discovery_method,omitempty"`
}

// rejectedOffer is an offer the verifier would not accept.
type rejectedOffer struct {
	// OfferID identifies which offer failed, so a group carrying several can be
	// told apart. Empty when the rejected object carried no id at all, which is
	// itself a signal worth passing on rather than hiding.
	OfferID string `json:"offer_id,omitempty"`
	// Reason is a stable token an agent can branch on: the signature did not
	// verify, the offer had expired, no key could be resolved for the issuing
	// exchange, or it carried fields this protocol version does not declare.
	Reason string `json:"reason"`
}

// handleDiscover runs discovery through the Broker.
//
// The requester is the caller's own subdomain — its WBA directory host, which is
// the identity the Exchange resolves keys against and lazy-registers. It comes
// from the authenticated context, never from the tool arguments.
func (t *toolset) handleDiscover(
	ctx context.Context, req *mcpsdk.CallToolRequest, in discoverInput,
) (*mcpsdk.CallToolResult, discoverOutput, error) {
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, discoverOutput{}, err
	}
	if len(in.URIs) == 0 && in.Query == "" {
		return nil, discoverOutput{}, errors.New("ramp_discover needs at least one uri or a query")
	}
	rpc := &rampv1.DiscoveryRequest{
		Ver:       helpers.ProtocolVersion,
		Uris:      in.URIs,
		Requester: t.requester(who.subdomain),
	}
	if in.Query != "" {
		rpc.Query = &in.Query
	}
	result, err := t.discovery.Resolve(t.callCtx(ctx, who), rpc)
	if err != nil {
		return nil, discoverOutput{}, t.failed(ctx, who, "ramp_discover", err)
	}
	out, err := projectDiscovery(result)
	if err != nil {
		return nil, discoverOutput{}, err
	}
	out.RequestID = who.requestID
	// Rejections are logged as well as returned. The agent needs them to read its
	// own result; an operator needs them because a whole exchange's offers failing
	// verification is a key-rotation or manifest problem on that exchange, which
	// no single agent's view would ever make visible.
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.discover",
		"subdomain", who.subdomain, "uris", len(in.URIs), "groups", len(out.OfferGroups),
		"rejected", out.rejectedCount())
	return nil, out, nil
}

// rejectedCount totals the offers verification refused across every group.
func (o discoverOutput) rejectedCount() int {
	n := 0
	for _, g := range o.OfferGroups {
		n += len(g.Rejected)
	}
	return n
}

// requester is the caller's RAMP identity as every tool sends it. Built in one
// place because the Broker and Exchange authorize a call by comparing this id to
// the signed Signature-Agent: two constructions of the same value are two chances
// for it to be spelled differently, and the failure that produces is a rejected
// request that names neither side.
func (t *toolset) requester(subdomain string) *rampv1.Requester {
	return &rampv1.Requester{
		Id:     t.agentDirectory(subdomain),
		Domain: subdomain,
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
}

// projectDiscovery renders the verified result for the agent, carrying each
// accepted Offer across as the JSON object the Exchange signed rather than
// re-modelling it field by field. A hand-written mirror would have to track every
// protocol change to stay signature-faithful; passing the object through cannot
// drift.
//
// It reads the already-sorted result rather than the raw response, so only
// offers that verified can reach the agent — the split is made upstream, in one
// verifier, and this function has no way to widen it.
func projectDiscovery(result core.DiscoveryResult) (discoverOutput, error) {
	out := discoverOutput{
		OfferGroups:   make([]offerGroup, 0, len(result.Groups)),
		AbsenceReason: rampreason.EnumPtrName(result.AbsenceReason),
	}
	for _, group := range result.Groups {
		offers, err := projectOffers(group.Verified)
		if err != nil {
			return discoverOutput{}, err
		}
		out.OfferGroups = append(out.OfferGroups, offerGroup{
			URI:             group.URI,
			Licensed:        len(offers) > 0,
			Offers:          offers,
			Rejected:        projectRejected(group.Rejected),
			AbsenceReason:   rampreason.EnumPtrName(group.AbsenceReason),
			DiscoveryMethod: rampreason.EnumPtrName(group.DiscoveryMethod),
		})
	}
	return out, nil
}

// projectOffers renders each verified Offer as a plain JSON object via protojson,
// so the agent receives — and can hand back — the protocol's own encoding.
func projectOffers(offers []core.VerifiedOffer) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(offers))
	for _, offer := range offers {
		obj, err := protoToMap(offer.Offer())
		if err != nil {
			return nil, fmt.Errorf("ramp_discover: render offer %q: %w", offer.Offer().GetOfferId(), err)
		}
		out = append(out, obj)
	}
	return out, nil
}

// projectRejected names each offer verification refused, and why.
//
// Only the id and the reason travel. The offer object stays behind: an agent
// licenses by handing an offer back, and returning one that failed verification
// would put the single object that must not be submitted into the agent's hands.
func projectRejected(rejected []core.RejectedOffer) []rejectedOffer {
	if len(rejected) == 0 {
		return nil
	}
	out := make([]rejectedOffer, 0, len(rejected))
	for _, r := range rejected {
		out = append(out, rejectedOffer{
			OfferID: r.Offer.GetOfferId(),
			Reason:  rejectionReason(r.Reason),
		})
	}
	return out
}

// rejectionReason maps a verifier failure onto a stable token.
//
// The token is what an agent branches on, so it is derived from the SDK's
// sentinels rather than from the error text: a message can be reworded upstream
// without notice, and an agent keying off prose would break silently when it
// was. An unrecognised cause reports the class instead of leaking the text.
//
// Two things about the arms are load-bearing, and both were wrong when this was
// first written, in ways no test could see because every case still produced a
// token.
//
// The ORDER matters for unknown fields. An offer carrying a field this build
// cannot render fails signature verification, and the SDK wraps BOTH sentinels
// so a caller mapping a refusal to a denial reason resolves through the generic
// one while a caller wanting the specific cause can still reach it. This is the
// second kind of caller, so the specific arm has to be tested first — below the
// signature arm it can never match.
//
// The EXPIRY sentinel comes from the verifier, not from the presented-offer
// helper beside it. Those are two distinct values with different messages and
// neither wraps the other, so matching the wrong one silently reports every
// expired offer as unclassified.
func rejectionReason(err error) string {
	switch {
	case err == nil:
		return "unverified"
	case errors.Is(err, helpers.ErrUnknownFields):
		return "unknown_fields"
	case errors.Is(err, helpers.ErrOfferSignatureInvalid):
		return "signature_invalid"
	case errors.Is(err, core.ErrOfferExpired):
		return "offer_expired"
	case errors.Is(err, helpers.ErrUnknownKey):
		return "issuer_key_unresolved"
	default:
		return "unverified"
	}
}

// protoToMap renders a protobuf message as the generic JSON object shape an MCP
// tool result carries. UseProtoNames keeps the snake_case field names the rest of
// the protocol speaks, so what the agent sees here matches the wire and the spec.
//
// The unknown-field check is the load-bearing part. By the time a message reaches
// here it has been decoded against the protocol version this repo pins, and
// protojson does not emit fields that version does not declare — there is no
// option that makes it. So a message from a peer running a NEWER protocol arrives
// carrying fields that would be silently dropped on the way out. For an Offer that
// is not cosmetic: the signature covers the canonical encoding of the whole
// message, so a dropped field means the offer no longer verifies, and it fails
// later, at the Exchange, pointing at the agent's offer rather than at this
// boundary. Refusing here costs the same call and names the real cause.
func protoToMap(msg proto.Message) (map[string]any, error) {
	if err := checkNoUnknownFields(msg); err != nil {
		return nil, err
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// checkNoUnknownFields refuses a message carrying fields this service's pinned
// protocol does not declare, anywhere in its tree.
//
// The recursive walk is the load-bearing part, not a thoroughness flourish.
// GetUnknown() reports the unknown set of the ONE message it is called on, and an
// Offer nests deeply — pricing, terms, attestations, previews, subscription_quota,
// identity, reporting. A newer peer's added field lands in the unknown set of
// whichever nested message declares it, where a top-level check cannot see it. The
// offer would then pass through here with that field silently dropped and fail
// later at the Exchange, naming the agent's offer rather than this boundary —
// precisely the outcome the guard exists to prevent, and precisely the case a
// top-level check misses.
//
// The reported path locates the skew (".pricing", ".terms[0]") so an operator can
// see which nested message their pin is behind on. An empty path is the root.
func checkNoUnknownFields(msg proto.Message) error {
	root := msg.ProtoReflect().Descriptor().FullName()
	return protorange.Range(msg.ProtoReflect(), func(p protopath.Values) error {
		// Non-message steps (scalars, and the unknown bytes themselves, which the
		// walk surfaces as their own step) carry no unknown set of their own.
		node, ok := p.Index(-1).Value.Interface().(protoreflect.Message)
		if !ok {
			return nil
		}
		unknown := node.GetUnknown()
		if len(unknown) == 0 {
			return nil
		}
		// Path[0] is the root step, which renders as the message name in parens;
		// dropping it leaves the field path relative to the root named separately.
		return fmt.Errorf(
			"%w: %s%s carries %d bytes this service's pinned protocol does not declare; "+
				"passing it on would drop them and invalidate its signature",
			errProtocolSkew, root, p.Path[1:].String(), len(unknown),
		)
	})
}

// errProtocolSkew marks the one failure an operator resolves by upgrading this
// service's protocol pin rather than by changing anything an agent did.
var errProtocolSkew = errors.New("mcp: protocol skew")
