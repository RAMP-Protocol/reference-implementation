// Package repo wraps sqlc's fat Querier interface with narrow per-domain
// interfaces. Services depend only on the interface they need; wiring
// composes them at startup (CLAUDE.md rule: interface segregation at ports).
package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// Tenant is the domain-layer view of a tenant row. Decouples the service from
// sqlc-generated pgtype values so tests can construct fixtures without touching
// the DB layer.
type Tenant struct {
	ID                  string
	Domain              string
	Ed25519KeyRef       string
	HMACSecretRef       string // retained for compatibility; never used for URL signing
	SigningScheme       string
	RSAKeyRef           string
	CloudFrontKeyPairID string
	// ReportingPolicy carries the raw tenants.reporting_policy JSONB. The
	// service decodes it (e.g. for default required_fields) close to the
	// callsite that needs the shape; storing as []byte keeps this repo type
	// shape-agnostic so adding a policy key does not ripple through every
	// service that reads a tenant.
	ReportingPolicy []byte
	// AllowBrokerRelay is the per-tenant opt-in for broker-on-behalf
	// reporting. When false, ReportUsage requires the verified httpsig
	// keyID to equal the obligation's agent_id; when true, a registered
	// BROKER caller is also accepted.
	AllowBrokerRelay bool
}

// TenantRepo is the narrow contract the Exchange service needs.
type TenantRepo interface {
	ByID(ctx context.Context, tenantID string) (Tenant, error)
	ByDomain(ctx context.Context, domain string) (Tenant, error)
}

// NewTenantRepo composes a TenantRepo over the fat sqlc.Querier.
func NewTenantRepo(q sqlc.Querier) TenantRepo { return &tenantRepo{q: q} }

type tenantRepo struct{ q sqlc.Querier }

// ErrTenantNotFound is returned when a tenant lookup has no match.
var ErrTenantNotFound = errors.New("repo: tenant not found")

func (r *tenantRepo) ByID(ctx context.Context, tenantID string) (Tenant, error) {
	row, err := r.q.GetTenantByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tenant{}, ErrTenantNotFound
		}
		return Tenant{}, fmt.Errorf("get tenant by id: %w", err)
	}
	return tenantFromRow(row), nil
}

func (r *tenantRepo) ByDomain(ctx context.Context, domain string) (Tenant, error) {
	row, err := r.q.GetTenantByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tenant{}, ErrTenantNotFound
		}
		return Tenant{}, fmt.Errorf("get tenant by domain: %w", err)
	}
	return tenantFromRow(row), nil
}

func tenantFromRow(row sqlc.RampTenant) Tenant {
	return Tenant{
		ID:                  row.TenantID,
		Domain:              row.Domain,
		Ed25519KeyRef:       row.Ed25519KeyRef,
		HMACSecretRef:       row.HmacSecretRef,
		SigningScheme:       string(row.SigningScheme),
		RSAKeyRef:           textOrEmpty(row.RsaKeyRef),
		CloudFrontKeyPairID: textOrEmpty(row.CloudfrontKeyPairID),
		ReportingPolicy:     row.ReportingPolicy,
		AllowBrokerRelay:    row.AllowBrokerRelay,
	}
}

func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
