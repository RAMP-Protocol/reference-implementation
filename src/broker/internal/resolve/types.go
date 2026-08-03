// Package resolve owns the Broker's resolve business core: candidate discovery →
// probe → offer verification → selection → budget pre-flight → audit. It is the
// layer the transport BrokerConnectHandler delegates to (mirroring the Exchange's
// transport → service split): the Connect handler decodes the wire request, maps
// it to a Request, and calls (*Service).Resolve; this package holds
// no transport/DTO concern and never imports the transport package. All offer
// cryptography is delegated to the SDK core.Verifier via the OfferVerifier seam.
package resolve

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
)

// Request is the Broker's internal resolve input, mapped from the
// canonical rampv1.DiscoveryRequest by the transport adapter's rampRequestToInput.
// Callers provide either a free-form query (EXA search) or a direct URI
// (single-domain probe); when both are present the URI takes precedence.
type Request struct {
	AgentID string `json:"agent_id"`
	Query   string `json:"query,omitempty"`
	// URI is the FIRST requested uri (== URIs[0]), retained as a scalar so the
	// single-uri call sites (validation, domain derivation fallback, audit) read
	// unchanged. The fan-out reads URIs.
	URI string `json:"uri,omitempty"`
	// URIs is the full requested batch. A single-uri request carries a
	// one-element slice; an EXA query carries none (the domains are derived from
	// the search results). candidateDomains maps EVERY uri to its publisher
	// domain so a multi-publisher batch probes every manifest, and
	// buildResourceQuery forwards the whole batch to each named exchange.
	URIs []string `json:"uris,omitempty"`
	// BudgetMinor carries the per-period budget cap as 1e8 FIXED-POINT int64
	// (8dp), NOT minor units / cents (DECISION 1+3). Money crosses the wire as a
	// canonical decimal string and is scaled by the transport adapter via
	// moneyStringToFixedPoint so the budget gate accounts fractions of a cent
	// EXACTLY while the Redis INCRBY counter stays an atomic integer. The field
	// name is retained to avoid churn; the unit is fixed-point 1e8, not minor units.
	BudgetMinor  int64  `json:"budget_minor,omitempty"`
	RequesterDom string `json:"requester_domain,omitempty"`
	// IntendedUse rides on the native Requester.intended_use proto field. The
	// Exchange filters by resource_id and scopes only (ADR-014), so there are no
	// user_type / geography fields — self-declared requester attributes are not a
	// filtering input.
	IntendedUse string `json:"intended_use,omitempty"`
	// MaxHops is the agent's RequestConstraints.max_hops self-cap on the number
	// of intermediaries permitted in its request chain. Absent = no cap. The
	// Broker enforces it before relaying (see the transport adapter's
	// enforceHopBudget).
	MaxHops *int32 `json:"max_hops,omitempty"`
}

// Response is the Broker's internal assembly DTO for a resolve outcome.
// It is not a wire type: the transport Connect Resolve handler maps it to the
// canonical rampv1.DiscoveryResponse via toDiscoveryResponse (proto-JSON).
//
// R7: Resolve is DISCOVERY-ONLY. It NEVER executes a
// transaction, NEVER records broker-side spend, and NEVER mints/forwards a signed
// retrieval URL — the Exchange is the sole executor and biller (at
// ExecuteTransaction time). The discovery outcome is the ranked, already-signed
// Offers the Broker discovered (Offers, set only on the licensed-discovery path);
// the licensed signal on the wire is NON-EMPTY DiscoveryResponse.offer_groups (not a
// retrieval_endpoint, which is no longer minted at resolve). The refusal cause is
// the typed AbsenceReason (the ADR-008 D2 OfferAbsenceReason enum) emitted on
// DiscoveryResponse.absence_reason.
//
// The agent-facing response carries NOTHING else: broker selection/billing detail
// (budget/spend state, the evaluated-candidate list) has no canonical field and is
// recorded only in the Broker's SelectionLog (auditSelection) and budget service —
// never echoed on the wire.
type Response struct {
	ExchangeID string
	// AbsenceReason is the REQUEST-level refusal cause, set only on the refusal
	// paths (no manifest, no healthy exchange, all-upstream-failed, budget). On
	// the licensed-discovery path it is UNSPECIFIED and the per-URI causes ride on
	// each Group's AbsenceReason instead.
	AbsenceReason rampv1.OfferAbsenceReason
	// Groups is the per-URL discovery outcome, one OfferGroup per REQUESTED uri,
	// keyed on the requested uri (Group.URI). Under the route-per-URL model each
	// URL is routed ONLY to the exchange(s) its publisher manifest names; the
	// Broker CONCATENATES the per-URL OfferGroups those exchanges return (no
	// cross-exchange merge — each URL is served by exactly one exchange). A URL
	// that routes to no registered+healthy exchange is carried as a typed-absence
	// group. A single-uri request yields EXACTLY ONE group (back-compat). Set only
	// on the licensed-discovery path (nil on a request-level refusal);
	// toDiscoveryResponse maps it to DiscoveryResponse.offer_groups.
	Groups []OfferGroup
}

// OfferGroup is the Broker's internal per-URL discovery group: the OfferGroup
// one exchange returned for one requested URL (route-per-URL — no cross-exchange
// merge). It carries the ranked (winner-first) offers for that URL, or — when the
// URL was absent (the exchange returned NOT_IN_CATALOG, or the URL routed to no
// exchange at all) — an empty Offers slice plus the per-URL AbsenceReason.
// toDiscoveryResponse maps it to a wire rampv1.OfferGroup with Uri +
// DiscoveryMethod(EXCHANGE) + per-group AbsenceReason set.
type OfferGroup struct {
	URI string
	// Offers is the ranked (winner-first) set of already-signed Offers for this
	// URL, deduped + ranked WITHIN the group (an exchange MAY return multiple
	// offers for one URL). Empty when the URL was absent / unroutable.
	Offers []selection.Candidate
	// AbsenceReason is the per-URL cause when Offers is empty (the routed exchange
	// returned NOT_IN_CATALOG, or the URL routed to no exchange). UNSPECIFIED when
	// the group carries offers.
	AbsenceReason rampv1.OfferAbsenceReason
	// cands is the pre-finalisation accumulator: the raw candidates collected for
	// this URL before Dedup+Rank. finalize() folds it into Offers. It is internal
	// to the discovery assembly and never read after finalize().
	cands []selection.Candidate
}

// finalize collapses the collected candidates into the ranked Offers slice
// (Dedup+Rank WITHIN the group — never cross-ranked against another URL). A group
// with no candidate keeps its AbsenceReason (the typed-absence shape).
func (g OfferGroup) finalize() OfferGroup {
	if len(g.cands) == 0 {
		g.cands = nil
		return g
	}
	g.Offers = selection.Rank(selection.Dedup(g.cands))
	g.AbsenceReason = rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED
	g.cands = nil
	return g
}

// Winner returns the ranked winner across all groups (the cheapest/highest-trust
// offer of the whole batch), or nil when no group carries an offer. Each group's
// offers are already ranked winner-first within the group, so the global winner
// is the best of the per-group winners — selection.Rank over those heads
// reproduces the prior global-rank winner for the single-uri (one-group) case
// and never under-counts the budget pre-flight for a batch. The budget gate and
// audit log both project this single global winner; the per-URI grouping is
// purely the agent-facing response shape (the batch budget under-count across
// DISTINCT uris is discovery-only pre-flight, out of S2 scope — flagged for S5).
func (r *Response) Winner() *selection.Candidate {
	heads := make([]selection.Candidate, 0, len(r.Groups))
	for i := range r.Groups {
		if len(r.Groups[i].Offers) > 0 {
			heads = append(heads, r.Groups[i].Offers[0])
		}
	}
	if len(heads) == 0 {
		return nil
	}
	return &selection.Rank(heads)[0]
}

// CandidateInfo is a lightweight audit view of evaluated offers, recorded in the
// Broker's SelectionLog (never on the agent-facing wire).
type CandidateInfo struct {
	OfferID    string `json:"offer_id"`
	ExchangeID string `json:"exchange_id"`
	// UnitCost is the offer's canonical wire money string (unit_cost, or rate as
	// fallback) — audit-only, recorded verbatim, never float-parsed here.
	UnitCost   string `json:"unit_cost"`
	TrustLevel string `json:"trust_level"`
}
