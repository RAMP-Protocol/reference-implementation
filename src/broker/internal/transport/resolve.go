package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
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

// Deps bundles dependencies for the resolver handler.
type Deps struct {
	Exchanges repo.ExchangeRepo
	Log       repo.SelectionLogRepo
	Discovery exa.DiscoveryClient
	Prober    *probe.Prober
	Exchange  xclient.ExchangeCaller
	Budget    budget.Service
	Signer    *signing.CoSigner
	HTTP      *http.Client
	Clk       clock.Clock
}

// ResolveHandler serves POST /broker/v1/resolve.
type ResolveHandler struct {
	deps Deps
}

// NewResolveHandler wires the dependency-bundle handler.
func NewResolveHandler(d Deps) *ResolveHandler {
	if d.HTTP == nil {
		d.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if d.Clk == nil {
		d.Clk = clock.System{}
	}
	return &ResolveHandler{deps: d}
}

// ServeHTTP implements http.Handler for /broker/v1/resolve.
func (h *ResolveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentBodyBytes))
	if err != nil {
		writeProtoError(w, requestID, broker.Newf(broker.KindInvalidArgument, "read body: %v", err))
		return
	}
	var rr rampv1.RAMPRequest
	// DiscardUnknown so a forward-compatible SDK sending newer fields is not 400'd.
	if uerr := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &rr); uerr != nil {
		writeProtoError(w, requestID, broker.Newf(broker.KindInvalidArgument, "decode body: %v", uerr))
		return
	}
	req := rampRequestToInput(&rr)
	if verr := validateResolveRequest(req); verr != nil {
		writeProtoError(w, requestID, verr)
		return
	}
	if aerr := authorizeAgentSelfAct(r.Context(), req.AgentID); aerr != nil {
		writeProtoError(w, requestID, aerr)
		return
	}
	resp, rerr := h.resolve(r.Context(), requestID, req)
	if rerr != nil {
		writeProtoError(w, requestID, rerr)
		return
	}
	writeProtoJSON(w, http.StatusOK, toRAMPResponse(resp, requestID))
}

// authorizeAgentSelfAct enforces agent self-action: the verified RFC 9421
// keyID on the request MUST equal the caller-supplied req.AgentID. The broker
// httpsig middleware has already verified the signature before this runs; this
// check binds that verified identity to the agent the caller claims to be.
// Belt-and-braces: a missing httpsig context (caller bypassed the middleware)
// is rejected as Unauthenticated rather than treated as any caller.
func authorizeAgentSelfAct(ctx context.Context, agentID string) *broker.Error {
	v := httpsig.FromContext(ctx)
	if v == nil || v.KeyID == "" {
		return broker.Newf(broker.KindUnauthenticated, "no verified caller in request context")
	}
	if v.KeyID != agentID {
		return broker.Newf(broker.KindPermissionDenied,
			"caller %q may not act on behalf of agent %q", v.KeyID, agentID)
	}
	return nil
}

func (h *ResolveHandler) resolve(ctx context.Context, requestID string, req ResolveRequest) (*ResolveResponse, error) {
	domains, err := h.candidateDomains(ctx, req)
	if err != nil {
		return nil, err
	}
	manifests, probeOutcome := h.probeDomains(ctx, domains)
	if len(manifests) == 0 {
		return probeRefusalResponse(probeOutcome), nil
	}
	exchanges, licensed := h.exchangesFor(ctx, manifests)
	if !licensed {
		return noHealthyExchangeResponse(), nil
	}

	offers, flags, err := h.discoverOffers(ctx, requestID, req, exchanges)
	if err != nil {
		return nil, err
	}
	if len(offers) == 0 {
		return noOffersResponse(ctx, flags), nil
	}
	// RAMP-56: Discovery phase returns ranked offers to agent; execution is
	// a separate agent-originated flow via /broker/v1/exchange/execute.
	ranked := selection.Rank(selection.Dedup(offers))

	// Check budget for the winning offer before returning to agent. This
	// allows the agent to know upfront if they have budget, without executing.
	// This is a one-time pre-flight at discovery only; the broker relay
	// (/broker/v1/exchange/execute) does NOT re-check budget — the Exchange
	// enforces billing at execute time.
	winner := ranked[0]
	budgetState, allowed, err := h.checkBudget(ctx, req.LicenseID, req.BudgetMinor, winner.Offer)
	if err != nil {
		return nil, err
	}
	if !allowed {
		h.auditSelection(ctx, requestID, req, ranked, nil, "budget_exhausted")
		return budgetExhaustedResponse(budgetState), nil
	}

	h.auditSelection(ctx, requestID, req, ranked, nil, "offers_returned")

	return &ResolveResponse{
		Licensed:   true,
		Offers:     ranked,
		Candidates: candidatesToInfo(ranked),
	}, nil
}

func (h *ResolveHandler) candidateDomains(ctx context.Context, req ResolveRequest) ([]string, error) {
	if req.URI != "" {
		d, err := exa.DomainOf(req.URI)
		if err != nil {
			return nil, broker.Wrapf(broker.KindInvalidArgument, err, "parse uri")
		}
		return []string{d}, nil
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

func (h *ResolveHandler) probeDomains(
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
			reqctx.FromContext(ctx).WarnContext(ctx, "probe failed", "domain", d, "err", err)
		}
	}
	return out, outcome
}

func (h *ResolveHandler) exchangesFor(
	ctx context.Context, manifests map[string]probe.Manifest,
) ([]repo.Exchange, bool) {
	seen := make(map[string]bool)
	var out []repo.Exchange
	for _, manifest := range manifests {
		for _, ex := range manifest.Exchanges {
			if seen[ex.Domain] {
				continue
			}
			m, err := h.deps.Exchanges.GetByDomain(ctx, ex.Domain)
			if err != nil {
				if !errors.Is(err, repo.ErrNotFound) {
					reqctx.FromContext(ctx).WarnContext(ctx, "lookup exchange",
						"domain", ex.Domain, "err", err)
				}
				continue
			}
			if !m.Healthy || m.TrustLevel == "BLOCKED" {
				continue
			}
			seen[m.Domain] = true
			out = append(out, m)
		}
	}
	return out, len(out) > 0
}

func (h *ResolveHandler) discoverOffers(
	ctx context.Context, requestID string, req ResolveRequest, exchanges []repo.Exchange,
) ([]selection.Candidate, discoverFlags, error) {
	var all []selection.Candidate
	flags := discoverFlags{}
	failures := 0
	for _, ex := range exchanges {
		rq := buildResourceQuery(ctx, requestID, req, h.deps.Clk)
		sig, err := h.deps.Signer.StampIntermediary(rq)
		if err != nil {
			return nil, flags, broker.Wrapf(broker.KindInternal, err, "stamp intermediary")
		}
		callCtx := xclient.WithSignature(ctx, sig)
		resp, err := h.deps.Exchange.DiscoverResources(callCtx, ex.Endpoint, rq)
		if err != nil {
			reqctx.FromContext(ctx).WarnContext(ctx, "discover failed",
				"exchange", ex.Domain, "err", err)
			failures++
			continue
		}
		for _, offer := range resp.GetOffers() {
			all = append(all, selection.Candidate{
				Offer: offer,
				Exchange: selection.ExchangeRef{
					Domain:   ex.Domain,
					Endpoint: ex.Endpoint,
					Trust:    ex.TrustLevel,
					Priority: ex.Priority,
				},
			})
		}
		// ADR-008 D2: surface the last non-UNSPECIFIED per-OfferGroup
		// absence reason as the upstream signal. Multi-URI batch needs
		// per-URI propagation once the obligations surface specifies it.
		empty := len(resp.GetOffers()) == 0
		var upstream rampv1.OfferAbsenceReason
		for _, group := range resp.GetOfferGroups() {
			if isCredentialsRestricted(group.GetAbsenceReason()) {
				flags.scopeRestricted = true
			}
			if group.GetAbsenceReason() != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
				upstream = group.GetAbsenceReason()
			}
		}
		if empty && upstream != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
			flags.upstreamReason = upstream
		}
	}
	flags.allUpstreamFailed = failures > 0 && failures == len(exchanges)
	return all, flags, nil
}

func (h *ResolveHandler) checkBudget(
	ctx context.Context, licenseID string, limit int64, offer *rampv1.Offer,
) (*BudgetState, bool, error) {
	if licenseID == "" || limit <= 0 {
		return nil, true, nil
	}
	dec, err := h.deps.Budget.Check(ctx, licenseID, limit)
	if err != nil {
		return nil, false, broker.Wrapf(broker.KindInternal, err, "budget check")
	}
	state := &BudgetState{Limit: dec.Limit, Consumed: dec.Consumed, Remaining: dec.Remaining}
	if !dec.Allowed {
		return state, false, nil
	}
	if projected := dec.Consumed + costMinor(nil, offer); projected > dec.Limit {
		state.Remaining = dec.Limit - projected
		return state, false, nil
	}
	return state, true, nil
}

func (h *ResolveHandler) auditSelection(
	ctx context.Context, requestID string, req ResolveRequest,
	ranked []selection.Candidate, winner *rampv1.Offer, outcome string,
) {
	entry := repo.SelectionLogEntry{
		LogID:     "sel-" + uuid.NewString(),
		RequestID: requestID,
		AgentID:   req.AgentID,
		Query:     orURI(req),
		Rationale: map[string]any{"outcome": outcome},
	}
	entry.CandidateOffers = candidatesToInfo(ranked)
	if winner != nil {
		entry.WinnerOfferID = winner.GetOfferId()
		if len(ranked) > 0 {
			entry.WinnerExchange = ranked[0].Exchange.Domain
		}
	}
	if err := h.deps.Log.RecordSelection(ctx, entry); err != nil {
		reqctx.FromContext(ctx).ErrorContext(ctx, "record selection failed", "err", err)
	}
}

func buildResourceQuery(
	ctx context.Context, requestID string, req ResolveRequest, clk clock.Clock,
) *rampv1.ResourceQuery {
	q := &rampv1.ResourceQuery{
		Ver:       rampproto.Ver,
		Id:        "rq-" + uuid.NewString(),
		RequestId: stringPtr(requestID),
		Requester: buildRequester(ctx, req, clk),
	}
	return q
}

// buildRequester populates the Requester message from the inbound JSON.
func buildRequester(_ context.Context, req ResolveRequest, _ clock.Clock) *rampv1.Requester {
	r := &rampv1.Requester{
		Id:     req.AgentID,
		Domain: req.RequesterDom,
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	if req.URI != "" {
		r.Uris = []string{req.URI}
	}
	if req.IntendedUse != "" {
		r.IntendedUse = []string{req.IntendedUse}
	}
	if req.LicenseID != "" {
		lic := req.LicenseID
		r.LicenseId = &lic
	}
	return r
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func orURI(req ResolveRequest) string {
	if req.Query != "" {
		return req.Query
	}
	return req.URI
}

func costMinor(tx *rampv1.TransactionResponse, offer *rampv1.Offer) int64 {
	if tx != nil && tx.GetCost() != nil {
		return int64(tx.GetCost().GetAmount() * 100)
	}
	if offer != nil && offer.GetPricing() != nil {
		return int64(offer.GetPricing().GetRate() * 100)
	}
	return 0
}

func candidatesToInfo(cands []selection.Candidate) []CandidateInfo {
	out := make([]CandidateInfo, 0, len(cands))
	for _, c := range cands {
		var uc float64
		if c.Offer.GetPricing() != nil {
			if u := c.Offer.GetPricing().UnitCost; u != nil {
				uc = *u
			} else {
				uc = c.Offer.GetPricing().GetRate()
			}
		}
		out = append(out, CandidateInfo{
			OfferID:    c.Offer.GetOfferId(),
			ExchangeID: c.Exchange.Domain,
			UnitCost:   uc,
			TrustLevel: c.Exchange.Trust,
		})
	}
	return out
}

func validateResolveRequest(req ResolveRequest) error {
	if req.AgentID == "" {
		return broker.Newf(broker.KindInvalidArgument, "agent_id is required")
	}
	if req.Query == "" && req.URI == "" {
		return broker.Newf(broker.KindInvalidArgument, "either query or uri is required")
	}
	return enforceHopBudget(req.MaxHops)
}
