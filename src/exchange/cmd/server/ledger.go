package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// ledgerResponse is what `make ledger TX=<id>` consumes. Every field needed to
// align the row against a Lambda@Edge access-log entry without re-deriving
// from keys is here verbatim. Field naming mirrors the column names so the
// script can pass it straight to the table renderer.
type ledgerResponse struct {
	TransactionID      string    `json:"transaction_id"`
	TxRequestID        string    `json:"tx_request_id"`
	TenantID           string    `json:"tenant_id"`
	TenantDomain       string    `json:"tenant_domain"`
	SigningScheme      string    `json:"signing_scheme"`
	AgentID            string    `json:"agent_id"`
	OfferID            string    `json:"offer_id"`
	ResourceID         string    `json:"resource_id"`
	OfferSignature     string    `json:"offer_signature"`
	SignedURLSignature string    `json:"signed_url_signature"`
	SignedURLHashHex   string    `json:"signed_url_hash_hex"`
	Currency           string    `json:"currency"`
	UnitCost           string    `json:"unit_cost"`
	BillingID          string    `json:"billing_id"`
	Expiry             time.Time `json:"expiry"`
	CreatedAt          time.Time `json:"created_at"`

	Obligation *ledgerObligation `json:"obligation,omitempty"`
}

type ledgerObligation struct {
	ID         string    `json:"obligation_id"`
	State      string    `json:"state"`
	Deadline   time.Time `json:"deadline"`
	ReceivedAt time.Time `json:"received_at,omitempty"`
	Consumed   string    `json:"consumed,omitempty"`
}

// ledgerHandler exposes GET /admin/ledger?tx=<transaction_id> — read-only
// audit endpoint that returns enough material for `make ledger` to align an
// Exchange row against a Lambda@Edge access-log entry. Demo-only; no auth
// because the deployed ALB listener for /admin/* is already gated by an
// IP allowlist (see HANDOFF-aws-demo.md §2). Production would require the
// usual admin-token middleware.
func ledgerHandler(
	tx repo.TransactionRepo,
	ob repo.ObligationRepo,
	tenants repo.TenantRepo,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txID := r.URL.Query().Get("tx")
		if txID == "" {
			http.Error(w, "missing tx query param", http.StatusBadRequest)
			return
		}
		rec, err := tx.ByID(r.Context(), txID)
		if err != nil {
			if errors.Is(err, repo.ErrTransactionNotFound) {
				http.Error(w, "transaction not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tenant, terr := tenants.ByID(r.Context(), rec.TenantID)
		if terr != nil {
			http.Error(w, terr.Error(), http.StatusInternalServerError)
			return
		}
		out := ledgerResponse{
			TransactionID:      rec.TransactionID,
			TxRequestID:        rec.TxRequestID,
			TenantID:           rec.TenantID,
			TenantDomain:       tenant.Domain,
			SigningScheme:      string(tenant.SigningScheme),
			AgentID:            rec.AgentID,
			OfferID:            rec.OfferID,
			ResourceID:         rec.ResourceID,
			OfferSignature:     rec.OfferSignature,
			SignedURLSignature: rec.SignedURLSignature,
			SignedURLHashHex:   hex.EncodeToString(rec.SignedURLHash),
			Currency:           rec.Currency,
			UnitCost:           rec.UnitCostDecimal,
			BillingID:          rec.BillingID,
			Expiry:             rec.Expiry,
			CreatedAt:          rec.CreatedAt,
		}
		// Obligation row is optional: the Lambda@Edge fetch happens after
		// AcceptOffer, but ReportUsage may not have arrived yet. Surface
		// either state — `make ledger` distinguishes "obligation pending"
		// from "obligation reported" in the rendered table.
		if obligation, err := ob.ByTransaction(r.Context(), rec.TransactionID); err == nil {
			out.Obligation = &ledgerObligation{
				ID:         obligation.ID,
				State:      obligation.State,
				Deadline:   obligation.Deadline,
				ReceivedAt: obligation.ReceivedAt,
				Consumed:   obligation.Consumed,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
