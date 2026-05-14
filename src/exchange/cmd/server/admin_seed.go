package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// seedRequest is the body shape for POST /admin/seed — a one-shot demo helper
// that inserts tenants + agents + catalog rows and then rebuilds the radix
// trie. Gated to the admin path and intended for local / demo deployments only.
type seedRequest struct {
	Tenants []seedTenant  `json:"tenants"`
	Agents  []seedAgent   `json:"agents"`
	Catalog []seedCatalog `json:"catalog"`
}

// seedTenant maps to ramp.tenants. Duplicate inserts are tolerated (logged,
// not fatal) so re-seeding the same config is idempotent.
type seedTenant struct {
	TenantID            string `json:"tenant_id"`
	Domain              string `json:"domain"`
	HmacSecretRef       string `json:"hmac_secret_ref"`
	Ed25519KeyRef       string `json:"ed25519_key_ref"`
	SigningScheme       string `json:"signing_scheme"`
	RSAKeyRef           string `json:"rsa_key_ref"`
	CloudFrontKeyPairID string `json:"cloudfront_key_pair_id"`
}

// seedAgent registers a row in ramp.agents so transaction_log FK lookups
// resolve. Demo-only — production agents register via a separate onboarding
// flow that captures their public key for signature verification.
type seedAgent struct {
	AgentID       string `json:"agent_id"`
	PublicKey     string `json:"public_key"` // base64 (PEM strip-down) or any opaque tag
	ManifestURL   string `json:"manifest_url"`
	RequesterType string `json:"requester_type"` // AGENT | HUMAN_TOOL | SERVICE | DELEGATED | RESEARCH
}

type seedCatalog struct {
	ResourceID     string          `json:"resource_id"`
	TenantID       string          `json:"tenant_id"`
	URI            string          `json:"uri"`
	URIPrefix      string          `json:"uri_prefix"`
	Pricing        json.RawMessage `json:"pricing"`
	LicensingRules json.RawMessage `json:"licensing_rules"`
	DeliveryMethod string          `json:"delivery_method"`
}

// seedHandler orchestrates: decode → applyTenants → applyAgents → applyCatalog
// → catalog reload. Duplicate tenant inserts are tolerated (logged, not fatal);
// agent and catalog entries use Upsert so re-seeding is idempotent.
func seedHandler(queries sqlc.Querier, catalogSvc *service.CatalogService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeSeedRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		applyTenants(ctx, queries, logger, req.Tenants)
		if err := applyAgents(ctx, queries, logger, req.Agents); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := applyCatalog(ctx, queries, logger, req.Catalog); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := catalogSvc.Bootstrap(ctx); err != nil {
			logger.ErrorContext(ctx, "seed: bootstrap", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func decodeSeedRequest(r *http.Request) (seedRequest, error) {
	var req seedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return seedRequest{}, err
	}
	return req, nil
}

// applyTenants inserts tenant rows. Duplicate-key errors are logged and skipped
// so re-seeding an already-present tenant is safe.
func applyTenants(ctx context.Context, queries sqlc.Querier, logger *slog.Logger, tenants []seedTenant) {
	for _, t := range tenants {
		scheme := sqlc.RampSigningScheme(t.SigningScheme)
		if scheme == "" {
			scheme = sqlc.RampSigningSchemeED25519
		}
		_, err := queries.InsertTenant(ctx, sqlc.InsertTenantParams{
			TenantID:            t.TenantID,
			Domain:              t.Domain,
			HmacSecretRef:       t.HmacSecretRef,
			Ed25519KeyRef:       t.Ed25519KeyRef,
			ReportingPolicy:     []byte("{}"),
			SigningScheme:       scheme,
			RsaKeyRef:           pgtype.Text{String: t.RSAKeyRef, Valid: t.RSAKeyRef != ""},
			CloudfrontKeyPairID: pgtype.Text{String: t.CloudFrontKeyPairID, Valid: t.CloudFrontKeyPairID != ""},
		})
		if err != nil {
			logger.WarnContext(ctx, "seed: insert tenant skipped", "tenant_id", t.TenantID, "err", err)
		}
	}
}

// applyAgents upserts agent rows. Returns the first error encountered so the
// handler can surface it as 500; successful upserts prior to the error are
// committed (Upsert is idempotent so re-seeding recovers cleanly).
func applyAgents(ctx context.Context, queries sqlc.Querier, logger *slog.Logger, agents []seedAgent) error {
	for _, a := range agents {
		rt := sqlc.RampRequesterType(a.RequesterType)
		if rt == "" {
			rt = sqlc.RampRequesterTypeAGENT
		}
		if _, err := queries.UpsertAgent(ctx, sqlc.UpsertAgentParams{
			AgentID:       a.AgentID,
			PublicKey:     []byte(a.PublicKey),
			ManifestUrl:   pgtype.Text{String: a.ManifestURL, Valid: a.ManifestURL != ""},
			RequesterType: rt,
		}); err != nil {
			logger.ErrorContext(ctx, "seed: upsert agent", "agent_id", a.AgentID, "err", err)
			return err
		}
	}
	return nil
}

// applyCatalog upserts catalog entries. Returns the first error encountered.
func applyCatalog(ctx context.Context, queries sqlc.Querier, logger *slog.Logger, catalog []seedCatalog) error {
	for _, c := range catalog {
		pricing := []byte(c.Pricing)
		if len(pricing) == 0 {
			pricing = []byte("{}")
		}
		rules := []byte(c.LicensingRules)
		if len(rules) == 0 {
			rules = []byte("{}")
		}
		dm := sqlc.RampDeliveryMethod(c.DeliveryMethod)
		if dm == "" {
			dm = sqlc.RampDeliveryMethodDIRECT
		}
		if _, err := queries.UpsertCatalogEntry(ctx, sqlc.UpsertCatalogEntryParams{
			ResourceID:     c.ResourceID,
			TenantID:       c.TenantID,
			Uri:            c.URI,
			UriPrefix:      c.URIPrefix,
			Pricing:        pricing,
			LicensingRules: rules,
			DeliveryMethod: dm,
		}); err != nil {
			logger.ErrorContext(ctx, "seed: upsert catalog", "resource_id", c.ResourceID, "err", err)
			return err
		}
	}
	return nil
}
