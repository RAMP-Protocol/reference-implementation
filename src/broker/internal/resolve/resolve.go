package resolve

import (
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// endpointResolver resolves a registered exchange DOMAIN to the ExchangeService
// origin the exchange advertises in its OWN /.well-known/ramp.json (the same
// resolution mechanism the execute relay uses). *resolvers.WellKnownEndpoint
// Resolver satisfies it. The interface is declared here (not imported from
// transport) so the resolve core owns its own port and never depends on the
// transport package — the transport relay handler declares its own structurally
// identical port and both are satisfied by the shared concrete resolver at wiring.
type endpointResolver interface {
	ResolveEndpoint(ctx context.Context, host string) (string, error)
}

// Deps bundles dependencies for the resolver handler.
type Deps struct {
	Exchanges repo.ExchangeRepo
	Log       repo.SelectionLogRepo
	Discovery exa.DiscoveryClient
	Prober    *probe.Prober
	Exchange  xclient.ExchangeCaller
	Budget    budget.Service
	Signer    *signing.CoSigner
	// Endpoints resolves a registered exchange DOMAIN to the ExchangeService
	// origin the exchange advertises in its OWN /.well-known/ramp.json — the SAME
	// resolver the execute relay uses (resolvers.WellKnownEndpointResolver). The
	// broker registry is a TRUST allowlist only: it gates WHICH exchange domains
	// may be queried, never WHERE they live. Discovery and execute therefore share
	// one endpoint-resolution mechanism — no backfilled registry endpoints.
	Endpoints endpointResolver
	Clk       clock.Clock
	// Verifier sorts every discovered offer into {verified, rejected} BEFORE it
	// can reach selection (sdk/go/core.Verifier under Strict in production; the
	// seam is an interface so tests inject mode/keys). Fail-closed: nil is
	// defaulted by NewService to a verifier that rejects everything, so
	// a wiring omission surfaces as loud empty discovery, never as unverified
	// offers silently reaching the agent.
	Verifier OfferVerifier
}

// OfferVerifier is the offer-verification seam the resolve core sorts every
// discovered offer through (satisfied by sdk/go/core.Verifier).
type OfferVerifier interface {
	Sort(ctx context.Context, offers []*rampv1.Offer) core.Result
}

// unwiredVerifier is the fail-closed default: every offer is rejected until a
// real Verifier is wired, so a missing Deps.Verifier cannot silently disable
// verification.
type unwiredVerifier struct{}

func (unwiredVerifier) Sort(_ context.Context, offers []*rampv1.Offer) core.Result {
	res := core.Result{}
	for _, off := range offers {
		res.Rejected = append(res.Rejected, core.RejectedOffer{Offer: off, Reason: errVerifierUnwired})
	}
	return res
}

var errVerifierUnwired = errors.New("offer verifier not wired (Deps.Verifier is nil)")

// Service owns the Broker's resolve business core (candidate discovery →
// probe → offer selection → budget → transaction). The Connect Resolve handler
// (transport.BrokerConnectHandler) is the sole transport over it (ADR-019 —
// the bespoke POST /broker/v1/resolve route was removed).
type Service struct {
	deps Deps
}

// NewService wires the dependency-bundle handler. The outbound fetches on
// the resolve path (probe, endpoint resolution, offer verification) each carry
// their own SSRF-guarded client, injected into the Prober, Endpoints, and
// Verifier deps at the composition root — the handler holds no HTTP client of
// its own.
func NewService(d Deps) *Service {
	if d.Clk == nil {
		d.Clk = clock.System{}
	}
	if d.Verifier == nil {
		d.Verifier = unwiredVerifier{}
	}
	return &Service{deps: d}
}

// Resolve runs the Broker's resolve business core: candidate discovery → probe →
// offer verification/selection → budget pre-flight → audit, returning the
// internal Response the transport adapter maps to the wire
// DiscoveryResponse. The caller (transport.BrokerConnectHandler) has already
// validated the request and authorized the caller before this runs.
func (h *Service) Resolve(ctx context.Context, requestID string, req Request) (*Response, error) {
	domains, err := h.candidateDomains(ctx, req)
	if err != nil {
		return nil, err
	}
	manifests, probeOutcome := h.probeDomains(ctx, domains)
	if len(manifests) == 0 {
		return probeRefusalResponse(probeOutcome), nil
	}

	groups, flags, refusal, err := h.discover(ctx, req, manifests)
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return refusal, nil
	}
	out := &Response{Groups: groups}
	winner := out.Winner()
	if winner == nil {
		return noOffersResponse(flags), nil
	}
	// Audit/budget project the GLOBAL winner across the batch (the cheapest/
	// highest-trust offer of every group); the per-URI grouping is the response
	// shape, not the selection unit. ranked is the flattened winner-first set of
	// every offer across every group for the SelectionLog.
	ranked := flattenGroups(groups)
	allowed, err := h.checkBudget(ctx, req.AgentID, req.BudgetMinor, winner.Offer.Offer())
	if err != nil {
		return nil, err
	}
	if !allowed {
		h.auditSelection(ctx, requestID, req, ranked, "budget_exhausted")
		return budgetExhaustedResponse(), nil
	}

	// The cost guard is a true PER-AGENT cap. It keys on the authenticated agent
	// identity — req.AgentID, which the transport adapter canonicalized in
	// validateAndCanonicalizeRequest and authorizeAgentSelfAct then verified against the signed
	// Signature-Agent. Per-agent is a claim about the KEY, so it holds only while
	// that key is one string per agent: were the comparison widened to accept
	// several spellings without rewriting the field, one agent would hold one
	// counter per spelling, each with the full period cap. Here — on the admitted,
	// licensed-discovery path — it Records the winner's
	// projected value against that agent's period counter so spend ACCUMULATES
	// across the agent's requests (per-agent, not per-request). Recording here is
	// NOT double-billing the Exchange (ADR-021 D6): the Exchange stays the sole
	// biller at the agent's own ExecuteTransaction (the transaction_log ledger).
	// This broker counter is a separate, discovery-side guard on brokered offer
	// value per agent per period — never the billing ledger. The retired
	// broker-authored execute, which the old "never Budget.Record here" comment
	// guarded against, no longer exists.
	if err := h.deps.Budget.Record(ctx, req.AgentID, costFixed(winner.Offer.Offer())); err != nil {
		return nil, broker.Wrapf(broker.KindInternal, err, "budget record")
	}
	h.auditSelection(ctx, requestID, req, ranked, "discovered")

	out.ExchangeID = winner.Exchange.Domain

	// Licensed-discovery outcome: the ranked, already-signed Offers are returned in
	// DiscoveryResponse.offer_groups (non-empty offer_groups IS the licensed signal,
	// ADR-019 — no retrieval_endpoint is minted at resolve). The
	// evaluated candidates were just recorded in the SelectionLog (auditSelection);
	// the audit-only detail is NOT echoed to the agent.
	return out, nil
}

// flattenGroups returns every candidate across every per-URI group in
// winner-first order WITHIN each group, groups in request order. This is the
// audit view (the SelectionLog's evaluated-candidate list); the global winner
// for budget/audit is groups' best offer (Response.Winner), already at
// the front of its own group.
func flattenGroups(groups []OfferGroup) []selection.Candidate {
	var out []selection.Candidate
	for i := range groups {
		out = append(out, groups[i].Offers...)
	}
	return out
}

func (h *Service) candidateDomains(ctx context.Context, req Request) ([]string, error) {
	if uris := requestURIs(req); len(uris) > 0 {
		return urisToDomains(uris)
	}
	cands, err := h.deps.Discovery.Search(ctx, req.Query)
	if err != nil {
		return nil, broker.Wrapf(broker.KindUpstreamUnavailable, err, "exa search")
	}
	seen := make(map[string]bool, len(cands))
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		if c.Domain == "" || seen[c.Domain] {
			continue
		}
		seen[c.Domain] = true
		out = append(out, c.Domain)
	}
	if len(out) == 0 {
		return nil, broker.Newf(broker.KindNotFound, "no domains for query %q", req.Query)
	}
	return out, nil
}

// requestURIs returns the requested uri batch: the explicit URIs slice when set
// (batch fan-out), else the single scalar URI as a one-element slice (back-compat),
// else nil (the EXA query path).
func requestURIs(req Request) []string {
	if len(req.URIs) > 0 {
		return req.URIs
	}
	if req.URI != "" {
		return []string{req.URI}
	}
	return nil
}

// urisToDomains maps every requested uri to its publisher domain, de-duped (the
// fan-out probes each distinct publisher domain exactly once; a batch spanning N
// publishers yields N manifests, and buildRoutePlan then routes each URL to the
// exchange its publisher names). A single unparseable uri fails the whole
// resolve as InvalidArgument.
func urisToDomains(uris []string) ([]string, error) {
	seen := make(map[string]bool, len(uris))
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		d, err := exa.DomainOf(u)
		if err != nil {
			return nil, broker.Wrapf(broker.KindInvalidArgument, err, "parse uri").WithField("uri")
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

func (h *Service) probeDomains(
	ctx context.Context, domains []string,
) (map[string]probe.Manifest, probeOutcome) {
	out := make(map[string]probe.Manifest, len(domains))
	var outcome probeOutcome
	for _, d := range domains {
		res, err := h.deps.Prober.Probe(ctx, d)
		switch {
		case err == nil:
			out[d] = res.Manifest
		case errors.Is(err, probe.ErrManifestMissing):
			outcome.missing++
		default:
			outcome.transient++
			reqctx.FromContext(ctx).WarnContext(ctx, "broker.resolve.probe", "domain", d, "err", err)
		}
	}
	return out, outcome
}

// exchangesFor unions the registered+healthy exchanges across the search-result
// manifests for the EXA-query (broadcast) path — there are no per-URL routes to
// build, so the free-text query is relayed to every authorized exchange. Each
// exchange's endpoint is resolved via its OWN well-known (registeredHealthy),
// never from the registry's backfilled endpoint column.
func (h *Service) exchangesFor(
	ctx context.Context, manifests map[string]probe.Manifest,
) ([]repo.Exchange, bool) {
	seen := make(map[string]bool)
	healthy := make(map[string]repo.Exchange)
	var out []repo.Exchange
	for _, manifest := range manifests {
		for _, ex := range manifest.Exchanges {
			if seen[ex.Domain] {
				continue
			}
			m, ok := h.registeredHealthy(ctx, ex.Domain, healthy)
			if !ok {
				continue
			}
			seen[m.Domain] = true
			out = append(out, m)
		}
	}
	return out, len(out) > 0
}

// checkBudget reports whether the winning offer is within the caller's
// per-period budget. Budget/spend state is broker-internal: it drives this
// allow/deny decision and is recorded in the budget service, but is never
// surfaced on the agent-facing response (ADR-019). Exhaustion is
// communicated to the agent only as the typed NOT_AUTHORIZED refusal.
func (h *Service) checkBudget(
	ctx context.Context, agentID string, limit int64, offer *rampv1.Offer,
) (bool, error) {
	if agentID == "" || limit <= 0 {
		return true, nil
	}
	dec, err := h.deps.Budget.Check(ctx, agentID, limit)
	if err != nil {
		return false, broker.Wrapf(broker.KindInternal, err, "budget check")
	}
	if !dec.Allowed {
		return false, nil
	}
	if projected := dec.Consumed + costFixed(offer); projected > dec.Limit {
		return false, nil
	}
	return true, nil
}

// auditSelection records what the broker actually did — the request, the
// discovered+ranked candidate set, and the outcome. It deliberately records NO
// "winner": under the current model the broker discovers + ranks + relays, and the AGENT
// selects at execute (audited authoritatively by the exchange's
// transaction_log.offer_id). The full ranked set lives in candidate_offers.
func (h *Service) auditSelection(
	ctx context.Context, requestID string, req Request,
	ranked []selection.Candidate, outcome string,
) {
	entry := repo.SelectionLogEntry{
		LogID:     "sel-" + uuid.NewString(),
		RequestID: requestID,
		AgentID:   req.AgentID,
		Query:     orURI(req),
		Rationale: map[string]any{"outcome": outcome},
	}
	entry.CandidateOffers = candidatesToInfo(ranked)
	if err := h.deps.Log.RecordSelection(ctx, entry); err != nil {
		reqctx.FromContext(ctx).ErrorContext(ctx, "broker.resolve.record", "err", err)
	}
}

// buildResourceQuery builds one signed-forward ResourceQuery scoped to the
// supplied uris — the route-per-URL caller passes ONLY the URLs routed to the
// target exchange (NOT the full batch); the broadcast-query caller passes nil
// (the free-text query rides on req.Query, no uris). This is the single point
// where the per-exchange URL subset is stamped onto the wire.
func buildResourceQuery(
	ctx context.Context, req Request, clk clock.Clock, uris []string,
) *rampv1.ResourceQuery {
	q := &rampv1.ResourceQuery{
		Ver:       rampproto.Ver,
		Requester: buildRequester(ctx, req, clk),
	}
	// uris and acceptable_restrictions ride on the ResourceQuery message itself
	// post-overhaul; the requester is identity-only. IntendedUse is relayed as an
	// advisory FUNCTION-axis restriction — the Exchange filters by resource_id +
	// scopes only (ADR-014) and never matches it, so this is a faithful
	// passthrough, not an enforcement input.
	if len(uris) > 0 {
		q.Uris = uris
	}
	if req.IntendedUse != "" {
		q.AcceptableRestrictions = []*rampv1.AcceptableRestriction{{
			Axis:   rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			Values: []string{req.IntendedUse},
		}}
	}
	return q
}

// buildRequester populates the identity-only Requester message from the inbound
// request. uris ride on the enclosing ResourceQuery; intended_use was removed
// from the selection path (ADR-014 scope-only). The Requester carries no
// caller-written billing field — the Exchange resolves the account from the
// verified request signature, never from anything the caller sends.
func buildRequester(_ context.Context, req Request, _ clock.Clock) *rampv1.Requester {
	return &rampv1.Requester{
		Id:     req.AgentID,
		Domain: req.RequesterDom,
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
}

func orURI(req Request) string {
	if req.Query != "" {
		return req.Query
	}
	return req.URI
}

// costFixed returns the offer's TOTAL projected charge as 1e8 fixed-point int64
// (the budget gate's accounting unit, DECISION 1+3): the per-unit
// selection.OfferCharge (the same unit_cost-else-rate value the agent is billed
// and selection ranks) times the estimated_quantity. The Exchange bills
// unit_cost * max(estimated_quantity, 1) (exchange_helpers.authorizeBilling /
// exchange_batch), so the pre-flight MUST project the same product or it
// under-counts a multi-unit transaction and admits a resolve whose real charge
// exceeds the budget. estimated_quantity <= 0 (unset) clamps to 1, exactly as the
// biller does. The multiply is applied here, NOT inside OfferCharge, because
// OfferCharge is a PER-UNIT value that ranking (eCPM-like comparison) and the
// audit unit-cost field depend on staying per-unit. OfferCharge is zero-lenient
// (nil offer/pricing, unset, or unparseable -> decimal.Zero), preserving the
// prior malformed/empty -> 0 behavior. R7: this projects the pre-flight budget
// gate only — the broker no longer records spend, so there is no tx-cost path.
func costFixed(offer *rampv1.Offer) int64 {
	qty := offer.GetPricing().GetEstimatedQuantity()
	if qty < 1 {
		qty = 1
	}
	return DecimalToFixedPoint(selection.OfferCharge(offer).Mul(decimal.NewFromInt32(qty)))
}

func candidatesToInfo(cands []selection.Candidate) []CandidateInfo {
	out := make([]CandidateInfo, 0, len(cands))
	for _, c := range cands {
		uc := ""
		if c.Offer.Offer().GetPricing() != nil {
			if u := c.Offer.Offer().GetPricing().UnitCost; u != nil {
				uc = *u
			} else {
				uc = c.Offer.Offer().GetPricing().GetRate()
			}
		}
		out = append(out, CandidateInfo{
			OfferID:    c.Offer.Offer().GetOfferId(),
			ExchangeID: c.Exchange.Domain,
			UnitCost:   uc,
			TrustLevel: c.Exchange.Trust,
		})
	}
	return out
}
