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
) (*routePlan, *routeScan, bool) {
	p := &routePlan{
		target:       make(map[string]string, len(uris)),
		exchangeURLs: make(map[string][]string),
		exchanges:    make(map[string]repo.Exchange),
	}
	scan := newRouteScan()
	for _, uri := range uris {
		p.urlOrder = append(p.urlOrder, uri)
		ex, ok := h.exchangeForURL(ctx, uri, manifests, scan)
		if !ok {
			continue
		}
		p.routeURLTo(uri, ex)
	}
	return p, scan, len(p.exchangeOrder) > 0
}

// routeScan is one resolve's view of the registry: the memoised lookups plus
// WHY an exchange was declined.
//
// The reason has to travel because the two kinds of decline owe different
// answers. Unregistered or BLOCKED is settled, and a URL that routes nowhere
// else really is not in this broker's catalog. Registered but down clears
// within a refresher interval, and calling that "not in catalog" tells an agent
// a permanent thing about a temporary one — the query path already answers
// TEMPORARILY_UNAVAILABLE there (noHealthyExchangeResponse).
type routeScan struct {
	// seen memoises GetByDomain results, hits AND misses, across URLs that name
	// the same exchange.
	seen map[string]repo.Exchange
	// sawTransientDecline records that at least one manifest-named exchange was
	// registered and trusted, and still could not be used right now.
	sawTransientDecline bool
}

func newRouteScan() *routeScan {
	return &routeScan{seen: make(map[string]repo.Exchange)}
}

// exchangeForURL finds the registered+healthy exchange a single URL routes to:
// URL -> publisher domain -> probed manifest -> first manifest-named exchange
// that is registered and healthy. healthy memoises GetByDomain lookups across
// URLs that share an exchange.
func (h *Service) exchangeForURL(
	ctx context.Context,
	uri string,
	manifests map[string]probe.Manifest,
	scan *routeScan,
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
		ex, ok := h.registeredHealthy(ctx, named.Domain, scan)
		if ok {
			return ex, true
		}
	}
	return repo.Exchange{}, false
}

// registeredHealthy resolves a manifest-named exchange domain to a queryable
// exchange record, returning it only when the domain is registered (TRUST
// allowlist), routable per repo.Exchange.Admission (the same rule the relay's
// SSRF admission reads), AND advertises an endpoint in its OWN
// /.well-known/ramp.json. The registry row is consulted for trust + health ONLY;
// the Endpoint is OVERWRITTEN with the well-known-resolved origin (the same
// resolver the execute path uses) so no backfilled registry endpoint is ever
// queried. Results (hit AND miss) are memoised in the supplied map for the
// resolve call. A well-known resolution failure marks the domain unroutable —
// the URLs that named it fall through to a typed-absence group.
func (h *Service) registeredHealthy(
	ctx context.Context, domain string, scan *routeScan,
) (repo.Exchange, bool) {
	if ex, seen := scan.seen[domain]; seen {
		return ex, ex.Domain != ""
	}
	m, err := h.deps.Exchanges.GetByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			logSkipRoutine(ctx, domain, skipUnregistered)
		} else {
			// A registry read that failed says nothing about the exchange, so it
			// is treated as transient like any other infrastructure fault.
			scan.sawTransientDecline = true
			reqctx.FromContext(ctx).WarnContext(ctx, "broker.routing.lookup",
				"domain", domain, "err", err)
		}
		scan.seen[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	if adm := m.Admission(); adm != repo.AdmissionLive {
		// The two ways a row can be unroutable differ in whether they clear on
		// their own, which is what the reason token records and what makes the
		// absence answer transient or settled.
		reason := skipBlocked
		if adm == repo.AdmissionDown {
			scan.sawTransientDecline = true
			reason = skipUnhealthy
		}
		logSkip(ctx, domain, reason)
		scan.seen[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	endpoint, err := h.deps.Endpoints.ResolveEndpoint(ctx, domain)
	if err != nil {
		// The exchange is registered, trusted and healthy; only its well-known
		// would not resolve, which is a network fault and clears on its own.
		scan.sawTransientDecline = true
		reqctx.FromContext(ctx).WarnContext(ctx, "broker.routing.resolve",
			"domain", domain, "err", err)
		scan.seen[domain] = repo.Exchange{}
		return repo.Exchange{}, false
	}
	m.Endpoint = endpoint // well-known wins; registry endpoint is never queried
	scan.seen[domain] = m
	return m, true
}

// Reasons a manifest-named exchange is not routable — the "reason" attribute of
// the broker.routing.skipped record, so an operator greps ONE message name for
// every decline. Two declines carry no token and get their own WARN messages: a
// failed registry read (broker.routing.lookup) and an unresolvable well-known
// (broker.routing.resolve).
const (
	// skipUnregistered: the manifest names a domain this operator has no row
	// for. Routine, publisher-driven and unbounded in cardinality, so it goes to
	// DEBUG (logSkipRoutine); the two below fire on the operator's own rows and
	// stay at INFO.
	skipUnregistered = "unregistered"
	// skipUnhealthy: a registered exchange whose last health probe failed. Worth
	// seeing even when a later exchange served the request — one of the
	// operator's own exchanges is down.
	skipUnhealthy = "unhealthy"
	// skipBlocked: a registered exchange the operator withdrew trust from. A
	// deliberate configuration state, not a fault.
	skipBlocked = "blocked"
)

// logSkip records that one of THIS operator's own exchanges was not routable.
// Fires at most once per domain per resolve, since registeredHealthy memoises
// hits and misses alike. INFO, not WARN: the request still answers 200 with a
// typed-absence group. Neither that group nor the request-level refusal names
// the exchange that dropped out, so this record is the only place an operator
// can read why routing stopped.
func logSkip(ctx context.Context, domain, reason string) {
	reqctx.FromContext(ctx).InfoContext(ctx, "broker.routing.skipped",
		"domain", domain, "reason", reason)
}

// logSkipRoutine records a decline that says nothing about this operator's
// deployment, at DEBUG. Same message name and attributes as logSkip, so one
// grep still finds every decline; only the level differs.
//
// The level differs because the volume does. logSkip fires on registry rows, so
// the operator's own configuration bounds the cardinality. This one fires on
// manifest.Exchanges[].Domain, written by a remote publisher: the document is
// capped at 64 KiB with no maxItems on the array, so one manifest can name
// hundreds of unregistered domains and per-domain memoisation does not help
// when every domain is distinct.
func logSkipRoutine(ctx context.Context, domain, reason string) {
	reqctx.FromContext(ctx).DebugContext(ctx, "broker.routing.skipped",
		"domain", domain, "reason", reason)
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
