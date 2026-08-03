// Batch ExecuteTransaction fan-out for the broker relay (batch fan-out).
//
// A batch TransactionRequest (items[] present) is grouped by
// items[i].offer.exchange and fanned out as ONE broker-signed sub-request per
// distinct exchange, then the per-exchange TransactionResponse.items[] are
// merged back into one response in ORIGINAL item order. Fan-out is NON-ATOMIC:
// a transport failure to one exchange synthesises per-item denials for that
// group's offer_ids while the other groups' results stand.
//
// Trust is a WHOLE-REQUEST admission gate: every distinct offer.exchange must
// be registry-trusted, well-known-resolvable, AND pass the post-resolve
// registry SSRF check BEFORE any fan-out side effect. If ANY group fails, the
// whole request is rejected with zero fan-out. A trusted-but-unreachable
// exchange, by contrast, yields per-item denials at fan-out time (non-atomic).
//
// The relay Core still owns the ONE whole-body sig1 boundary verify + the ONE
// replay add over the entire batch body — the agent signs the broker route
// as-received exactly once; the broker re-signs each per-exchange sub-request
// with the broker key alone. The Core Invariant holds: each sub-request
// carries each item's offer + acceptance + the shared requester +
// idempotency_key byte-identical, so every item's detached acceptance still
// verifies upstream. The transport adapter keeps the unmarshal, the
// load-bearing admission ordering (ResolveGroups → VerifyAndGuardReplay →
// FanOut), and every write sink.

package relay

import (
	"context"
	"errors"
	"strconv"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampcost"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// EndpointResolver resolves a signed Offer.exchange domain to the Exchange's
// self-advertised ExchangeService origin by reading the top-level endpoint of
// its /.well-known/ramp.json (WellKnownManifest.endpoint).
// *helpers.WellKnownEndpointResolver satisfies it. The registry never supplies
// the endpoint — that is the Offer.exchange routing invariant: the
// endpoint always comes from the exchange's own manifest; the registry is only
// a trust allowlist. A locally-owned structural port, per the resolve exemplar.
type EndpointResolver interface {
	ResolveEndpoint(ctx context.Context, host string) (string, error)
}

// ExecuteCaller dispatches one broker-signed ExecuteTransaction sub-request to
// an Exchange endpoint. xclient.ExchangeCaller satisfies it; the narrow local
// port keeps this package off the full caller surface.
type ExecuteCaller interface {
	ExecuteTransaction(
		ctx context.Context, endpoint string, req *rampv1.TransactionRequest,
	) (*rampv1.TransactionResponse, error)
}

// Group carries one exchange's resolved endpoint and the subset of items (in
// original order) that route to it. Opaque to the transport adapter: it flows
// from ResolveGroups into FanOut unmodified.
type Group struct {
	domain   string
	endpoint string
	items    []*rampv1.TransactionItem
}

// Batch owns the execute-relay fan-out: per-group trust + well-known
// resolution + SSRF admission, the fan-out itself, and the order-preserving
// merge. It composes the shared Core (SSRF allowlist, audit).
type Batch struct {
	core      Core
	endpoints EndpointResolver
	exchange  ExecuteCaller
}

// NewBatch wires the batch fan-out over the shared relay core.
func NewBatch(core Core, endpoints EndpointResolver, exchange ExecuteCaller) Batch {
	return Batch{core: core, endpoints: endpoints, exchange: exchange}
}

// ResolveGroups groups the items by offer.exchange (preserving original order
// within each group) and resolves+trust+SSRF-checks every distinct exchange.
// It rejects the WHOLE request (returning the typed error, auditing the
// rejected endpoint) if any item lacks an offer.exchange or any exchange is
// untrusted/unresolvable/off-allowlist — the trust admission gate runs to
// completion BEFORE any fan-out side effect.
func (b Batch) ResolveGroups(
	ctx context.Context, bd Boundary, txReq *rampv1.TransactionRequest,
) ([]Group, *broker.Error) {
	order := make([]string, 0)
	byDomain := map[string][]*rampv1.TransactionItem{}
	for i, item := range txReq.GetItems() {
		domain := item.GetOffer().GetExchange()
		if domain == "" {
			return nil, broker.Newf(broker.KindInvalidArgument,
				"item %d: offer.exchange required to route an execute relay", i).
				WithField("offer.exchange").WithMeta("item_index", strconv.Itoa(i))
		}
		if _, seen := byDomain[domain]; !seen {
			order = append(order, domain)
		}
		byDomain[domain] = append(byDomain[domain], item)
	}

	groups := make([]Group, 0, len(order))
	for _, domain := range order {
		endpoint, err := b.resolveGroupEndpoint(ctx, domain)
		if err != nil {
			b.core.Audit(ctx, bd, "REJECTED_ENDPOINT", domain, err)
			return nil, err
		}
		groups = append(groups, Group{domain: domain, endpoint: endpoint, items: byDomain[domain]})
	}
	return groups, nil
}

// resolveGroupEndpoint resolves ONE group's domain to its endpoint (trust +
// well-known via ResolveExchangeEndpoint) AND re-checks it against the
// registry SSRF allowlist (Core.EndpointAllowed) — the same post-resolve guard
// the discover admission applies. Returns a typed broker.Error so the caller
// owns the whole-request rejection.
func (b Batch) resolveGroupEndpoint(ctx context.Context, domain string) (string, *broker.Error) {
	endpoint, err := b.ResolveExchangeEndpoint(ctx, domain)
	if err != nil {
		return "", err
	}
	allowed, aerr := b.core.EndpointAllowed(ctx, endpoint)
	if aerr != nil {
		return "", broker.Wrapf(broker.KindInternal, aerr, "exchange registry")
	}
	if !allowed {
		return "", UnregisteredEndpointError(endpoint)
	}
	return endpoint, nil
}

// ResolveExchangeEndpoint resolves ONE offer.exchange domain to its advertised
// Exchange endpoint: the TRUST allowlist gate (GetByDomain — a signed offer
// from an Exchange the registry does not trust is refused) followed by the
// endpoint from THAT exchange's own /.well-known/ramp.json (the Offer.exchange
// routing invariant; the registry never supplies the endpoint). The
// post-resolve registry SSRF re-check stays with Core.EndpointAllowed.
func (b Batch) ResolveExchangeEndpoint(ctx context.Context, domain string) (string, *broker.Error) {
	if _, err := b.core.exchanges.GetByDomain(ctx, domain); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			// Trust gate: a signed offer naming an Exchange the registry does
			// not know. Distinct axis (domain, not resolved endpoint) and
			// message from the SSRF-gate reject, so it keeps its own
			// constructor; the offending identity rides as typed metadata
			// under "field" (ADR-019) rather than only in the Message string.
			return "", broker.Newf(broker.KindInvalidArgument,
				"offer.exchange %q is not a registered exchange", domain).
				WithField("offer.exchange")
		}
		return "", broker.Wrapf(broker.KindInternal, err, "exchange registry")
	}
	endpoint, err := b.endpoints.ResolveEndpoint(ctx, domain)
	if err != nil {
		kind := broker.KindUpstreamUnavailable
		if errors.Is(err, resolvers.ErrNoEndpoint) {
			kind = broker.KindInvalidArgument
		}
		return "", broker.Wrapf(kind, err, "resolve offer.exchange %q via well-known", domain)
	}
	return endpoint, nil
}

// FanOut sends ONE broker-signed sub-request per exchange group and merges the
// per-group items[] back into one TransactionResponse in ORIGINAL item order.
// A whole-group transport failure synthesises per-item denials for that
// group's offer_ids (non-atomic). The shared agent_identity_hash is carried
// from the first non-empty group's response; the batch total_cost is
// aggregated per-currency over every group's authoritative per-item costs
// — the broker is the only component that sees every exchange
// response in a fan-out, so the aggregate is structurally its responsibility,
// and a single scalar is emitted only when the whole batch shares one
// currency.
func (b Batch) FanOut(
	ctx context.Context, bd Boundary, txReq *rampv1.TransactionRequest, groups []Group,
) *rampv1.TransactionResponse {
	resultByOffer := map[string]*rampv1.TransactionResultItem{}
	var agentHash string
	for _, g := range groups {
		sub := &rampv1.TransactionRequest{
			Ver:            txReq.GetVer(),
			IdempotencyKey: txReq.GetIdempotencyKey(),
			Requester:      txReq.GetRequester(),
			Items:          g.items,
		}
		resp, err := b.exchange.ExecuteTransaction(ctx, g.endpoint, sub)
		if err != nil {
			b.core.Audit(ctx, bd, "RELAY_UPSTREAM_ERROR", g.endpoint, err)
			collectGroupDenials(resultByOffer, g.items)
			continue
		}
		for _, it := range resp.GetItems() {
			resultByOffer[it.GetOfferId()] = it
		}
		if agentHash == "" {
			agentHash = resp.GetAgentIdentityHash()
		}
	}
	merged := mergeResults(txReq.GetItems(), resultByOffer, agentHash)
	// Aggregate the whole-batch total over the AUTHORITATIVE per-item costs,
	// never a latched single group's subtotal. A malformed upstream amount
	// omits the scalar (per-item items[].cost stay authoritative) rather than
	// failing an otherwise-successful batch.
	total, err := rampcost.BatchTotal(merged.GetItems())
	if err != nil {
		reqctx.FromContext(ctx).WarnContext(ctx, "broker.batch.total_cost_aggregation_failed",
			"err", err.Error())
	}
	merged.TotalCost = total
	return merged
}

// unavailableItem builds the per-item CONTENT_UNAVAILABLE denial used when an
// offer_id has no fan-out result — a whole group whose call failed at the
// transport layer, or an exchange that returned fewer items than were sent. It
// keeps the synthesized denial shape identical across both back-fill paths
// (collectGroupDenials and mergeResults).
func unavailableItem(offerID string) *rampv1.TransactionResultItem {
	reason := rampv1.DenialReason_DENIAL_REASON_CONTENT_UNAVAILABLE
	return &rampv1.TransactionResultItem{OfferId: offerID, DenialReason: &reason}
}

// collectGroupDenials synthesises a per-item CONTENT_UNAVAILABLE denial for
// every offer_id in a group whose entire fan-out call failed at the transport
// layer, so the merged response preserves the original item cardinality +
// order rather than dropping the unreachable exchange's items (non-atomic).
func collectGroupDenials(
	into map[string]*rampv1.TransactionResultItem, items []*rampv1.TransactionItem,
) {
	for _, it := range items {
		offerID := it.GetOffer().GetOfferId()
		into[offerID] = unavailableItem(offerID)
	}
}

// mergeResults reassembles one TransactionResponse.items[] in the ORIGINAL
// TransactionItem order, keyed by offer_id (fan-out is grouped and may
// complete out of order). An offer_id with no result (an exchange that
// returned fewer items than sent) is back-filled with a CONTENT_UNAVAILABLE
// denial so the response cardinality always matches the request.
func mergeResults(
	items []*rampv1.TransactionItem,
	resultByOffer map[string]*rampv1.TransactionResultItem,
	agentHash string,
) *rampv1.TransactionResponse {
	merged := make([]*rampv1.TransactionResultItem, 0, len(items))
	for _, it := range items {
		offerID := it.GetOffer().GetOfferId()
		if res, ok := resultByOffer[offerID]; ok {
			merged = append(merged, res)
			continue
		}
		merged = append(merged, unavailableItem(offerID))
	}
	return &rampv1.TransactionResponse{
		Ver:               rampproto.Ver,
		Items:             merged,
		AgentIdentityHash: agentHash,
	}
}
