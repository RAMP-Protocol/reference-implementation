// Package transport exposes the Broker's HTTP + Connect-Go handlers.
//
// The free-form JSON resolve endpoint is the primary agent entrypoint. The
// Connect-Go ReportUsage handler relays agent-originated usage reports to
// whichever Exchange owns the underlying transaction.
package transport

// ResolveRequest is the JSON body of POST /broker/v1/resolve.
//
// Callers provide either a free-form query (EXA search) or a direct URI
// (single-domain probe). When both are provided, the URI takes precedence.
type ResolveRequest struct {
	AgentID      string `json:"agent_id"`
	LicenseID    string `json:"license_id,omitempty"`
	Query        string `json:"query,omitempty"`
	URI          string `json:"uri,omitempty"`
	BudgetMinor  int64  `json:"budget_minor,omitempty"`
	RequesterDom string `json:"requester_domain,omitempty"`
	IntendedUse  string `json:"intended_use,omitempty"`
}

// ResolveResponse is the JSON body returned by the endpoint.
type ResolveResponse struct {
	Licensed      bool            `json:"licensed"`
	SignedURL     string          `json:"signed_url,omitempty"`
	BareURL       string          `json:"bare_url,omitempty"`
	TransactionID string          `json:"transaction_id,omitempty"`
	OfferID       string          `json:"offer_id,omitempty"`
	MarketplaceID string          `json:"marketplace_id,omitempty"`
	RequestID     string          `json:"request_id"`
	Content       string          `json:"content,omitempty"`
	Budget        *BudgetState    `json:"budget,omitempty"`
	Error         string          `json:"error,omitempty"`
	Rationale     []string        `json:"rationale,omitempty"`
	Candidates    []CandidateInfo `json:"candidates,omitempty"`
}

// BudgetState reports consumption for audit.
type BudgetState struct {
	Limit     int64 `json:"limit_minor"`
	Consumed  int64 `json:"consumed_minor"`
	Remaining int64 `json:"remaining_minor"`
}

// CandidateInfo is a lightweight audit view of evaluated offers.
type CandidateInfo struct {
	OfferID       string  `json:"offer_id"`
	MarketplaceID string  `json:"marketplace_id"`
	UnitCost      float64 `json:"unit_cost"`
	TrustLevel    string  `json:"trust_level"`
}
