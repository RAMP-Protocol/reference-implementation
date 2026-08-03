package resolve

import (
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// routePlan is the publisher-manifest-derived ROUTE-PER-URL plan (route-per-URL
// model). Each requested URL is routed ONLY to the exchange(s) its publisher's
// /.well-known/ramp.json names — never broadcast to every exchange. The plan
// carries:
//   - urlOrder: the requested URLs in request order, the stable response order.
//   - target: URL -> the registered+healthy exchange that serves it (the FIRST
//     manifest-named exchange that is registered and healthy). A URL whose
//     publisher names no registered+healthy exchange has no entry here — it is
//     UNROUTABLE and surfaces as a typed-absence OfferGroup.
//   - exchangeURLs: exchange domain -> the subset of URLs routed to it (query
//     each exchange with ONLY this subset, not the full batch).
//   - exchanges: exchange domain -> the registered Exchange record (endpoint,
//     trust, priority) used to issue the DiscoverResources call.
//   - exchangeOrder: deterministic exchange iteration order (first-seen),
//     keeping the concatenated response groups stable.
type routePlan struct {
	urlOrder      []string
	target        map[string]string // url -> exchange domain
	exchangeURLs  map[string][]string
	exchanges     map[string]repo.Exchange
	exchangeOrder []string
}

// buildRoutePlan derives the route-per-URL plan from the probed publisher
// manifests. For each requested URL it resolves the URL's publisher domain,
// finds that domain's manifest, and routes the URL to the FIRST manifest-named
// exchange that is registered and healthy (the routing stays
// publisher-manifest-derived — the settled invariant — but is tracked per URL
// instead of unioned flat). A URL that cannot be parsed, has no probed manifest,
// or whose manifest names no registered+healthy exchange is left unrouted (it
// becomes a typed-absence group downstream). Returns the plan and whether ANY
// URL routed to an exchange.
func (h *Service) buildRoutePlan(
	ctx context.Context, uris []string, manifests map[string]probe.Manifest,
) (*routePlan, bool) {
	p := &routePlan{
		target:       make(map[string]string, len(uris)),
		exchangeURLs: make(map[string][]string),
		exchanges:    make(map[string]repo.Exchange),
	}
	healthy := make(map[string]repo.Exchange) // memoised registered+healthy lookups
	for _, uri := range uris {
		p.urlOrder = append(p.urlOrder, uri)
		ex, ok := h.exchangeForURL(ctx, uri, manifests, healthy)
		if !ok {
			continue
		}
		p.routeURLTo(uri, ex)
	}
	return p, len(p.exchangeOrder) > 0
}

// exchangeForURL finds the registered+healthy exchange a single URL routes to:
// URL -> publisher domain -> probed manifest -> first manifest-named exchange
// that is registered and healthy. healthy memoises GetByDomain lookups across
// URLs that share an exchange.
func (h *Service) exchangeForURL(
	ctx context.Context,
	uri string,
	manifests map[string]probe.Manifest,
	healthy map[string]repo.Exchange,
) (repo.Exchange, bool) {
	domain, err := exa.DomainOf(uri)
	if err != nil {
		return repo.Exchange{}, false
	}
	manifest, ok := manifests[domain]
	if !ok {
		return repo.Exchange{}, false
	}
	for _, named := range manifest.Exchanges {
		ex, ok := h.registeredHealthy(ctx, named.Domain, healthy)
		if ok {
			return ex, true
		}
	}
	return repo.Exchange{}, false
}

// registeredHealthy resolves a manifest-named exchange domain to a queryable
// exchange record, returning it only when the domain is registered (TRUST
// allowlist), healthy, not BLOCKED, AND advertises an endpoint in its OWN
// /.well-known/ramp.json. The registry row is consulted for trust + health ONLY;
// the Endpoint is OVERWRITTEN with the well-known-resolved origin (the same
// resolver the execute path uses) so no backfilled registry endpoint is ever
// queried. Results (hit AND miss) are memoised in the supplied map for the
// resolve call. A well-known resolution failure marks the domain unroutable —
// the URLs that named it fall through to a typed-absence group.
func (h *Service) registeredHealthy(
	ctx context.Context, domain string, healthy map[string]repo.Exchange,
) (repo.Exchange, bool) {
	if ex, seen := healthy[domain]; seen {
		return ex, ex.Domain != ""
	}
	m, err := h.deps.Exchanges.GetByDomain(ctx, domain)
	if err != nil {
		if !errors.Is(err, repo.ErrNotFound) {
			reqctx.FromContext(ctx).WarnContext(ctx, "broker.routing.lookup",
				"domain", domain, "err", err)
		}
		healthy[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	if !m.Healthy || m.TrustLevel == "BLOCKED" {
		healthy[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	endpoint, err := h.deps.Endpoints.ResolveEndpoint(ctx, domain)
	if err != nil {
		reqctx.FromContext(ctx).WarnContext(ctx, "broker.routing.resolve",
			"domain", domain, "err", err)
		healthy[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	m.Endpoint = endpoint // well-known wins; registry endpoint is never queried
	healthy[domain] = m
	return m, true
}

// routeURLTo records that uri is served by ex, registering the exchange and its
// first-seen order on demand.
func (p *routePlan) routeURLTo(uri string, ex repo.Exchange) {
	if _, seen := p.exchanges[ex.Domain]; !seen {
		p.exchanges[ex.Domain] = ex
		p.exchangeOrder = append(p.exchangeOrder, ex.Domain)
	}
	p.target[uri] = ex.Domain
	p.exchangeURLs[ex.Domain] = append(p.exchangeURLs[ex.Domain], uri)
}

// assemble materialises the final per-URL OfferGroups in REQUEST order. For each
// requested URL it takes the group its routed exchange returned (finalised:
// Dedup+Rank within the group) when present, or emits a typed-absence group:
//   - a routed URL whose exchange returned no group for it falls back to
//     NOT_IN_CATALOG (the routed exchange did not catalog it);
//   - an UNROUTABLE URL (no registered+healthy exchange named) is NOT_IN_CATALOG
//     too — the broker found no exchange authorized to serve it.
//
// So every requested URL surfaces as exactly one group, never silently dropped —
// the negative-leg guarantee.
func (p *routePlan) assemble(byURL map[string]OfferGroup) []OfferGroup {
	out := make([]OfferGroup, 0, len(p.urlOrder))
	for _, uri := range p.urlOrder {
		if g, ok := byURL[uri]; ok {
			out = append(out, g.finalize())
			continue
		}
		out = append(out, OfferGroup{
			URI:           uri,
			AbsenceReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
		})
	}
	return out
}
