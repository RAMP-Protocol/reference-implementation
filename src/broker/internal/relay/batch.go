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
// be registry-trusted, well-known-resolvable, AND still routable (trust not
// withdrawn, last health probe passed) BEFORE any fan-out side effect. If ANY group fails, the
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
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampcost"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramproute"
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
// within each group) and resolves+trust+admission-checks every distinct
// exchange. It rejects the WHOLE request if any item lacks an offer.exchange or
// any exchange is untrusted, unresolvable, withdrawn or down — the gate runs to
// completion BEFORE any fan-out side effect. Refusals are audited where their
// reason is known: resolution failures here, registry verdicts in the admission
// mapping both routes share.
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
		endpoint, err := b.resolveGroupEndpoint(ctx, bd, domain)
		if err != nil {
			return nil, err
		}
		groups = append(groups, Group{domain: domain, endpoint: endpoint, items: byDomain[domain]})
	}
	return groups, nil
}

// resolveGroupEndpoint decides whether the relay may deal with ONE group's
// exchange at all, and only then resolves where that exchange is.
//
// The order is the point. Every refusal is settled from the registry row alone,
// so all of them are answered before the broker sends the exchange a single
// byte. A withdrawn exchange used to have its well-known fetched and only then
// be refused, which contradicted the registry's own rule that a BLOCKED row gets
// no traffic at all. It also let a resolution failure win the race: if the
// withdrawn exchange was unreachable too, the agent got a retryable "try again"
// for a decision the operator had already made permanently, filed under the
// SSRF-shaped audit action, while the discover route answered the same row
// finally and without a fetch.
//
// The audit sits here rather than in the caller because only here is the reason
// known. A caller auditing every failure alike had to pick one action, and it
// picked REJECTED_ENDPOINT — which records an address the operator never
// authorized, the shape an SSRF attempt takes. Every execute relay is a batch,
// so that filed every routine outage under the attack-shaped record.
//
// The admission is read off the row the trust gate already fetched by DOMAIN,
// not a second lookup keyed on the resolved endpoint. The endpoint comes from
// the Exchange's own well-known and the resolver has vetted it as anchored to
// that domain; keying on it instead made the decision depend on the registry's
// endpoint column agreeing with the well-known, so an Exchange with a stale
// column was refused as unregistered while discovery served it.
func (b Batch) resolveGroupEndpoint(
	ctx context.Context, bd Boundary, domain string,
) (string, *broker.Error) {
	ex, err := b.trustedExchange(ctx, domain)
	if err != nil {
		// Nothing is resolved yet, so every audit here can only name the domain;
		// every other relay audit names the resolved endpoint. The action comes
		// from the error's Kind, so a registry fault on the broker's side is not
		// recorded against the exchange.
		b.core.Audit(ctx, bd, AuditAction(err), domain, err)
		return "", err
	}
	// Named by the domain for the same reason: the refusal is decided before
	// anything is resolved, so there is no endpoint to name yet.
	if rerr := b.core.RefuseAdmission(ctx, bd, admissionOf(ex), domain); rerr != nil {
		return "", rerr
	}
	if terr := refuseUntrustedForExecute(ex); terr != nil {
		b.core.Audit(ctx, bd, "REJECTED_AUTHZ", domain, terr)
		return "", terr
	}
	endpoint, err := b.resolveAdvertisedEndpoint(ctx, domain)
	if err != nil {
		b.core.Audit(ctx, bd, AuditAction(err), domain, err)
		return "", err
	}
	return endpoint, nil
}

// refuseUntrustedForExecute is the EXECUTE-side trust gate: money only moves to
// an exchange an operator reviewed.
//
// Separate from the registry's routability verdict on purpose. That verdict
// answers blocked, down or live — the health question, one answer for every
// caller — and cannot express this one, because DISCOVERED and VERIFIED are
// equally live and owe different answers on different operations. A DISCOVERED
// exchange is one the broker found named in some publisher's ramp.json and
// nobody has approved; it may quote prices, which is comparison shopping and
// costs nothing, and it may not be paid. Anyone who can edit a publisher's
// ramp.json can otherwise put themselves in the payment path.
//
// Settled, not retryable: the answer changes when an operator promotes the
// exchange, which no amount of retrying brings about. The offending identity
// rides as typed metadata under "field", the same axis the trust gate above it
// uses — the domain, not a resolved endpoint, because none was resolved.
func refuseUntrustedForExecute(ex repo.Exchange) *broker.Error {
	if ex.TrustLevel == repo.TrustLevelVerified || ex.TrustLevel == repo.TrustLevelPreferred {
		return nil
	}
	return broker.Newf(broker.KindInvalidArgument,
		"offer.exchange %q is registered but not approved for transactions", ex.Domain).
		WithField("offer.exchange")
}

// trustedExchange is the TRUST allowlist gate: a signed offer naming an
// Exchange the registry does not know is refused. Its row carries the
// admission decision.
func (b Batch) trustedExchange(ctx context.Context, domain string) (repo.Exchange, *broker.Error) {
	ex, err := b.core.exchanges.GetByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			// Trust gate: a signed offer naming an Exchange the registry does
			// not know. Distinct axis (domain, not resolved endpoint) and
			// message from the SSRF-gate reject, so it keeps its own
			// constructor; the offending identity rides as typed metadata
			// under "field" (ADR-019) rather than only in the Message string.
			return repo.Exchange{}, broker.Newf(broker.KindInvalidArgument,
				"offer.exchange %q is not a registered exchange", domain).
				WithField("offer.exchange")
		}
		return repo.Exchange{}, broker.Wrapf(broker.KindInternal, err, "exchange registry")
	}
	return ex, nil
}

// resolveAdvertisedEndpoint reads ONE trusted Exchange's own well-known for the
// origin it advertises — the Offer.exchange routing invariant. The registry is
// a trust allowlist plus a cache of that address, kept current by the
// refresher.
func (b Batch) resolveAdvertisedEndpoint(ctx context.Context, domain string) (string, *broker.Error) {
	endpoint, err := b.endpoints.ResolveEndpoint(ctx, domain)
	if err != nil {
		// Classified by CAUSE, and the default arm is the retryable one, so every
		// VERDICT has to be named here. Reaching a manifest is a network
		// operation, and a DNS blip or a 500 from an otherwise healthy Exchange is
		// transient — reporting that as invalid-argument would tell an agent its
		// offer is bad when the offer is fine.
		//
		// The three sentinels below are the opposite case. Two of them mean the
		// manifest WAS read and either advertises no endpoint at all or advertises
		// one the resolver refuses — a host or port that is not the one serving
		// the manifest, or an endpoint carrying userinfo. The third means the
		// manifest was never reached because the domain is not a usable host, and
		// it belongs here for the same reason even though nothing was read: a
		// value that is not a host does not become one on a later attempt. The
		// registry's domain column carries no constraint that would keep such a
		// value out.
		//
		// The set is the resolver contract's, and this is the relay's answer to
		// it. The same resolver's other caller — the discovery fan-out — names
		// none of the three: every resolution failure there marks the domain
		// unhealthy and the URL reaches the agent as "not in catalog", a reason
		// about the catalog for a cause that has nothing to do with one. That is a
		// separate defect in a separate function, and fixing it needs a decision
		// this file cannot make, because no absence reason the protocol defines
		// carries "the Exchange advertises an endpoint we refuse".
		kind := broker.KindUpstreamUnavailable
		if ramproute.IsVerdict(err) {
			kind = broker.KindInvalidArgument
		}
		return "", broker.Wrapf(kind, err, "resolve offer.exchange %q via well-known", domain)
	}
	// Canonicalized before it becomes a dial target and a signature base: a
	// manifest may advertise a trailing slash, and the double-slash @target-uri
	// would then fail sig1 verification upstream.
	return repo.CanonicalEndpoint(endpoint), nil
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
		// Ver is echoed, never stamped: the agent authored and signed the request
		// this sub-request is projected from, so the version stays the agent's.
		sub := &rampv1.TransactionRequest{
			Ver:                    txReq.GetVer(),
			IdempotencyKey:         txReq.GetIdempotencyKey(),
			Requester:              txReq.GetRequester(),
			Items:                  g.items,
			AgentRequestAcceptance: txReq.GetAgentRequestAcceptance(),
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
		Ver:               helpers.ProtocolVersion,
		Items:             merged,
		AgentIdentityHash: agentHash,
	}
}
