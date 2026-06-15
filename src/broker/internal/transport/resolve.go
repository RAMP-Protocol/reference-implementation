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
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
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
	ranked := selection.Rank(selection.Dedup(offers))
	winner := ranked[0]
	budgetState, allowed, err := h.checkBudget(ctx, req.LicenseID, req.BudgetMinor, winner.Offer)
	if err != nil {
		return nil, err
	}
	if !allowed {
		h.auditSelection(ctx, requestID, req, ranked, nil, "budget_exhausted")
		return budgetExhaustedResponse(budgetState), nil
	}

	txResp, err := h.executeTransaction(ctx, requestID, req, winner)
	if err != nil {
		reqctx.FromContext(ctx).ErrorContext(ctx, "execute failed", "err", err)
		return nil, err
	}
	if recordErr := h.deps.Budget.Record(ctx, req.LicenseID, costMinor(txResp, winner.Offer)); recordErr != nil {
		// Best-effort record-after-execute: the transaction is committed and the
		// agent owns the signed URL; we log and proceed. All best-effort
		// post-commit side-channel writes in this handler log at ERROR with the
		// request_id — "durable work done, side-channel record failed" is
		// alert-worthy and must stay correlatable.
		reqctx.FromContext(ctx).ErrorContext(ctx, "budget record failed", "err", recordErr)
	}
	h.relayReportUsage(ctx, winner, txResp)
	h.auditSelection(ctx, requestID, req, ranked, winner.Offer, "delivered")

	budgetState = h.postRecordBudget(ctx, req)
	return &ResolveResponse{
		Licensed:   true,
		OfferID:    winner.Offer.GetOfferId(),
		ExchangeID: winner.Exchange.Domain,
		Budget:     budgetState,
		Candidates: candidatesToInfo(ranked),
		tx:         txResp,
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

func (h *ResolveHandler) executeTransaction(
	ctx context.Context, requestID string, req ResolveRequest, winner selection.Candidate,
) (*rampv1.TransactionResponse, error) {
	tx := &rampv1.TransactionRequest{
		Ver:       "0.3",
		Id:        "tx-" + uuid.NewString(),
		OfferId:   stringPtr(winner.Offer.GetOfferId()),
		Requester: buildRequester(ctx, req, h.deps.Clk),
		RequestId: stringPtr(requestID),
	}
	if sig := winner.Offer.GetSignature(); sig != "" {
		tx.OfferSignature = stringPtr(sig)
	}
	resp, err := h.deps.Exchange.ExecuteTransaction(ctx, winner.Exchange.Endpoint, tx)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *ResolveHandler) relayReportUsage(
	ctx context.Context, winner selection.Candidate, tx *rampv1.TransactionResponse,
) {
	if winner.Offer.GetReporting() == nil || !winner.Offer.GetReporting().GetRequired() {
		return
	}
	// Use the offer's estimated_quantity as consumed quantity. The broker
	// represents the MCP relay path where actual consumption equals the
	// estimated amount billed. Full payload required for Exchange validation.
	var consumed int32
	if p := winner.Offer.GetPricing(); p != nil && p.EstimatedQuantity != nil {
		consumed = *p.EstimatedQuantity
	}
	report := &rampv1.UsageReport{
		Ver:           "0.3",
		Id:            "ur-" + uuid.NewString(),
		TransactionId: tx.GetTransactionId(),
		BillingId:     tx.GetBillingId(),
		Usage:         &rampv1.Usage{ConsumedQuantity: consumed},
	}
	if _, err := h.deps.Exchange.ReportUsage(ctx, winner.Exchange.Endpoint, report); err != nil {
		reqctx.FromContext(ctx).ErrorContext(ctx, "report usage relay failed", "err", err)
	}
}

func (h *ResolveHandler) postRecordBudget(ctx context.Context, req ResolveRequest) *BudgetState {
	if req.LicenseID == "" || req.BudgetMinor <= 0 {
		return nil
	}
	dec, err := h.deps.Budget.Check(ctx, req.LicenseID, req.BudgetMinor)
	if err != nil {
		return nil
	}
	return &BudgetState{Limit: dec.Limit, Consumed: dec.Consumed, Remaining: dec.Remaining}
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
		Ver:       "0.3",
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
