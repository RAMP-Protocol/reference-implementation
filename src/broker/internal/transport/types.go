// Package transport exposes the Broker's HTTP + Connect-Go handlers.
//
// The canonical proto-JSON resolve endpoint (RAMPRequest → RAMPResponse) is the
// primary agent entrypoint. The Connect-Go ReportUsage handler relays
// agent-originated usage reports to whichever Exchange owns the underlying
// transaction.
package transport

import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

// ResolveRequest is the Broker's internal resolve input, mapped from the
// canonical rampv1.RAMPRequest by rampRequestToInput. Callers provide either a
// free-form query (EXA search) or a direct URI (single-domain probe); when both
// are present the URI takes precedence.
type ResolveRequest struct {
	AgentID      string `json:"agent_id"`
	LicenseID    string `json:"license_id,omitempty"`
	Query        string `json:"query,omitempty"`
	URI          string `json:"uri,omitempty"`
	BudgetMinor  int64  `json:"budget_minor,omitempty"`
	RequesterDom string `json:"requester_domain,omitempty"`
	IntendedUse  string `json:"intended_use,omitempty"`
	// MaxHops is the agent's RequestConstraints.max_hops self-cap on the number
	// of intermediaries permitted in its request chain. Absent = no cap. The
	// Broker enforces it before relaying (see enforceHopBudget).
	MaxHops *int32 `json:"max_hops,omitempty"`
}

// ResolveResponse is the Broker's internal assembly DTO for a resolve outcome.
// It is no longer a wire type: ServeHTTP maps it to the canonical
// rampv1.RAMPResponse via toRAMPResponse (proto-JSON). Canonical fields are
// sourced from tx (the Exchange's TransactionResponse, set only on the licensed
// path); Broker-specific signals (licensed flag, winning offer, refusal
// error/absence-reason, budget, candidates) ride under RAMPResponse.ext with
// ramp.broker.* keys. AbsenceReason is the ADR-008 D2 OfferAbsenceReason enum
// name string (e.g. "OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE").
type ResolveResponse struct {
	Licensed      bool
	OfferID       string
	ExchangeID    string
	Budget        *BudgetState
	Error         string
	Candidates    []CandidateInfo
	AbsenceReason string
	// tx is the Exchange's TransactionResponse on the licensed path (nil on
	// refusal). toRAMPResponse reads the canonical fields from it.
	tx *rampv1.TransactionResponse
}

// BudgetState reports consumption for audit.
type BudgetState struct {
	Limit     int64 `json:"limit_minor"`
	Consumed  int64 `json:"consumed_minor"`
	Remaining int64 `json:"remaining_minor"`
}

// CandidateInfo is a lightweight audit view of evaluated offers.
type CandidateInfo struct {
	OfferID    string  `json:"offer_id"`
	ExchangeID string  `json:"exchange_id"`
	UnitCost   float64 `json:"unit_cost"`
	TrustLevel string  `json:"trust_level"`
}
