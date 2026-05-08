package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

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
	Marketplaces repo.MarketplaceRepo
	Log          repo.SelectionLogRepo
	Discovery    exa.DiscoveryClient
	Prober       *probe.Prober
	Exchange     xclient.ExchangeCaller
	Budget       budget.Service
	Signer       *signing.CoSigner
	Routes       *TransactionRouteStore
	HTTP         *http.Client
	Logger       *slog.Logger
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
	return &ResolveHandler{deps: d}
}

// ServeHTTP implements http.Handler for /broker/v1/resolve.
func (h *ResolveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	var req ResolveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, requestID, broker.Newf(broker.KindInvalidArgument, "decode body: %v", err))
		return
	}
	if err := validateResolveRequest(req); err != nil {
		writeError(w, requestID, err)
		return
	}
	resp, err := h.resolve(r.Context(), requestID, req)
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	resp.RequestID = requestID
	writeJSON(w, http.StatusOK, resp)
}

func (h *ResolveHandler) resolve(ctx context.Context, requestID string, req ResolveRequest) (*ResolveResponse, error) {
	domains, err := h.candidateDomains(ctx, req)
	if err != nil {
		return nil, err
	}
	manifests := h.probeDomains(ctx, domains)
	marketplaces, licensed := h.marketplacesFor(ctx, manifests)
	if !licensed {
		return &ResolveResponse{
			Licensed: false,
			BareURL:  firstBareURL(req, domains),
		}, nil
	}

	offers, err := h.discoverOffers(ctx, requestID, req, marketplaces)
	if err != nil {
		return nil, err
	}
	if len(offers) == 0 {
		return &ResolveResponse{
			Licensed: false,
			BareURL:  firstBareURL(req, domains),
			Error:    "no offers returned by marketplaces",
		}, nil
	}
	ranked := selection.Rank(selection.Dedup(offers))
	winner := ranked[0]

	budgetState, allowed, err := h.checkBudget(ctx, req.LicenseID, req.BudgetMinor, winner.Offer)
	if err != nil {
		return nil, err
	}
	if !allowed {
		h.auditSelection(ctx, requestID, req, ranked, nil, "budget_exhausted")
		return &ResolveResponse{
			Licensed: false,
			Error:    "budget exhausted",
			Budget:   budgetState,
		}, nil
	}

	txResp, err := h.executeTransaction(ctx, requestID, req, winner)
	if err != nil {
		h.deps.Logger.ErrorContext(ctx, "execute failed", "request_id", requestID, "err", err)
		return nil, err
	}
	signedURL := extractSignedURL(txResp)
	if h.deps.Routes != nil && txResp.GetTransactionId() != "" {
		h.deps.Routes.Put(txResp.GetTransactionId(), winner.Marketplace.Endpoint)
	}
	if recordErr := h.deps.Budget.Record(ctx, req.LicenseID, costMinor(txResp, winner.Offer)); recordErr != nil {
		h.deps.Logger.WarnContext(ctx, "budget record failed", "err", recordErr)
	}
	h.relayReportUsage(ctx, winner, txResp)
	h.auditSelection(ctx, requestID, req, ranked, winner.Offer, "delivered")
	// Single info-level line on every successful licensed resolve so
	// ledger.py can prove "Broker routed this tx" by querying CloudWatch
	// for the transaction_id. Without this line the chain is invisible
	// in the access log because MCP fetches the URL on the agent's behalf.
	h.deps.Logger.InfoContext(ctx, "resolve delivered",
		"request_id", requestID,
		"transaction_id", txResp.GetTransactionId(),
		"marketplace", winner.Marketplace.Domain,
		"agent_id", req.AgentID,
		"offer_id", winner.Offer.GetOfferId(),
	)

	budgetState = h.postRecordBudget(ctx, req)
	return &ResolveResponse{
		Licensed:      true,
		SignedURL:     signedURL,
		TransactionID: txResp.GetTransactionId(),
		OfferID:       winner.Offer.GetOfferId(),
		MarketplaceID: winner.Marketplace.Domain,
		Budget:        budgetState,
		Candidates:    candidatesToInfo(ranked),
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

func (h *ResolveHandler) probeDomains(ctx context.Context, domains []string) map[string]probe.Manifest {
	out := make(map[string]probe.Manifest, len(domains))
	for _, d := range domains {
		res, err := h.deps.Prober.Probe(ctx, d)
		if err != nil {
			h.deps.Logger.WarnContext(ctx, "probe failed", "domain", d, "err", err)
			continue
		}
		if res.Present {
			out[d] = res.Manifest
		}
	}
	return out
}

func (h *ResolveHandler) marketplacesFor(
	ctx context.Context, manifests map[string]probe.Manifest,
) ([]repo.Marketplace, bool) {
	seen := make(map[string]bool)
	var out []repo.Marketplace
	for _, manifest := range manifests {
		for _, mp := range manifest.Exchanges {
			if seen[mp.Domain] {
				continue
			}
			m, err := h.deps.Marketplaces.GetByDomain(ctx, mp.Domain)
			if err != nil {
				if !errors.Is(err, repo.ErrNotFound) {
					h.deps.Logger.WarnContext(ctx, "lookup marketplace",
						"domain", mp.Domain, "err", err)
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
	ctx context.Context, requestID string, req ResolveRequest, marketplaces []repo.Marketplace,
) ([]selection.Candidate, error) {
	var all []selection.Candidate
	for _, mp := range marketplaces {
		rq := buildResourceQuery(requestID, req)
		sig, err := h.deps.Signer.StampIntermediary(rq)
		if err != nil {
			return nil, broker.Wrapf(broker.KindInternal, err, "stamp intermediary")
		}
		callCtx := xclient.WithSignature(ctx, sig)
		resp, err := h.deps.Exchange.DiscoverResources(callCtx, mp.Endpoint, rq)
		if err != nil {
			h.deps.Logger.WarnContext(ctx, "discover failed",
				"marketplace", mp.Domain, "err", err)
			continue
		}
		for _, offer := range resp.GetOffers() {
			all = append(all, selection.Candidate{
				Offer: offer,
				Marketplace: selection.MarketplaceRef{
					Domain:   mp.Domain,
					Endpoint: mp.Endpoint,
					Trust:    mp.TrustLevel,
					Priority: mp.Priority,
				},
			})
		}
	}
	return all, nil
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
		Requester: buildRequester(req),
		RequestId: stringPtr(requestID),
	}
	if sig := winner.Offer.GetSignature(); sig != "" {
		tx.OfferSignature = stringPtr(sig)
	}
	resp, err := h.deps.Exchange.ExecuteTransaction(ctx, winner.Marketplace.Endpoint, tx)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (h *ResolveHandler) relayReportUsage(
	ctx context.Context, winner selection.Candidate, tx *rampv1.TransactionResponse,
) {
	if tx.GetTransactionId() == "" {
		return
	}
	// Always relay on a successful resolve. The previous gate keyed off
	// winner.Offer.GetReporting().GetRequired(), but the deployed Exchange
	// only sets ReportingObligation on the TransactionResponse, not on the
	// Offer message; the gate therefore short-circuited every demo run and
	// left obligations PENDING. The Broker is the natural place to close
	// this loop on the agent's behalf because it already has the tx_id and
	// marketplace endpoint in scope; the agent doesn't have to thread a
	// follow-up call.
	report := &rampv1.UsageReport{
		Ver:           "0.3",
		Id:            "ur-" + uuid.NewString(),
		TransactionId: tx.GetTransactionId(),
		BillingId:     tx.GetBillingId(),
	}
	if _, err := h.deps.Exchange.ReportUsage(ctx, winner.Marketplace.Endpoint, report); err != nil {
		h.deps.Logger.WarnContext(ctx, "report usage relay failed", "err", err, "tx_id", tx.GetTransactionId())
		return
	}
	h.deps.Logger.InfoContext(ctx, "report usage relayed",
		"transaction_id", tx.GetTransactionId(),
		"marketplace", winner.Marketplace.Domain,
	)
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
			entry.WinnerMarketplace = ranked[0].Marketplace.Domain
		}
	}
	if err := h.deps.Log.RecordSelection(ctx, entry); err != nil {
		h.deps.Logger.WarnContext(ctx, "record selection failed", "err", err)
	}
}

// -----------------------------------------------------------------------------
// Helpers.

func buildResourceQuery(requestID string, req ResolveRequest) *rampv1.ResourceQuery {
	q := &rampv1.ResourceQuery{
		Ver:       "0.3",
		Id:        "rq-" + uuid.NewString(),
		RequestId: stringPtr(requestID),
		Requester: buildRequester(req),
	}
	return q
}

func buildRequester(req ResolveRequest) *rampv1.Requester {
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

func firstBareURL(req ResolveRequest, domains []string) string {
	if req.URI != "" {
		return req.URI
	}
	if len(domains) > 0 {
		return "https://" + domains[0]
	}
	return ""
}

func orURI(req ResolveRequest) string {
	if req.Query != "" {
		return req.Query
	}
	return req.URI
}

func extractSignedURL(tx *rampv1.TransactionResponse) string {
	if tx == nil {
		return ""
	}
	if ext := tx.GetExt(); ext != nil {
		if v, ok := ext.Fields["signed_url"]; ok {
			return v.GetStringValue()
		}
	}
	return ""
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
			OfferID:       c.Offer.GetOfferId(),
			MarketplaceID: c.Marketplace.Domain,
			UnitCost:      uc,
			TrustLevel:    c.Marketplace.Trust,
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
	return nil
}
