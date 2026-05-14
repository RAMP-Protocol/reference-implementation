package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// catalogListHandler exposes GET /admin/catalog — flat JSON dump of catalog rows
// (no paging, demo-only). Pricing + licensing columns are returned as raw JSON
// so consumers see the shape the service stored.
func catalogListHandler(r repo.CatalogRepo) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		rows, err := r.ListAll(req.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type row struct {
			ResourceID     string          `json:"resource_id"`
			TenantID       string          `json:"tenant_id"`
			URI            string          `json:"uri"`
			URIPrefix      string          `json:"uri_prefix"`
			Pricing        json.RawMessage `json:"pricing"`
			LicensingRules json.RawMessage `json:"licensing_rules"`
			DeliveryMethod string          `json:"delivery_method"`
		}
		out := make([]row, 0, len(rows))
		for _, e := range rows {
			out = append(out, row{
				ResourceID: e.ResourceID, TenantID: e.TenantID,
				URI: e.URI, URIPrefix: e.URIPrefix,
				Pricing: json.RawMessage(e.PricingJSON), LicensingRules: json.RawMessage(e.LicensingJSON),
				DeliveryMethod: e.DeliveryMethod,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// catalogReloadHandler exposes POST /admin/catalog/reload for demo / E2E use.
// Triggers CatalogService.Bootstrap to rebuild the in-process radix trie from
// the current DB contents. Unauth; production would gate this behind IAM and
// require authentication.
func catalogReloadHandler(c *service.CatalogService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := c.Bootstrap(r.Context()); err != nil {
			logger.ErrorContext(r.Context(), "catalog reload failed", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
