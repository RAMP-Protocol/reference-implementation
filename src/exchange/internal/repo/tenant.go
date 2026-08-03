// Package repo wraps sqlc's fat Querier interface with narrow per-domain
// interfaces. Services depend only on the interface they need; wiring
// composes them at startup — interface segregation at the ports.
//
// Error convention: exported sentinels carry a "repo:" prefix (e.g.
// ErrTenantNotFound); operational wrap errors do not — they read as a bare verb
// phrase ("get tenant by id: %w") because the call stack already localizes them.
// New code follows this split rather than prefixing wraps.
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
	// FeeRateBps is the tenant-level default platform commission in integer
	// basis points (1 bp = 0.01%), resolved at Authorize. A per-(tenant,
	// resource_owner) override (FeeOverrideRepo) supersedes it where present.
	// Server-side commercial term, never on the wire.
	FeeRateBps int
	// FeeRateNotes is optional operator commentary attached to the fee rate.
	// nil is SQL NULL (no note); a non-nil pointer is the stored note. The
	// admin SetTenantFeeRate write path sets it as a full replace.
	FeeRateNotes *string
	// ActivateNewAgentsByDefault is the per-tenant policy for whether a newly
	// registered agent starts active in the billing system-of-record. TRUE by
	// default; set out of band like the other tenant configuration columns.
	ActivateNewAgentsByDefault bool
}

// TenantReadRepo is the read-only tenant contract the agent hot path depends on:
// ExchangeService (ByID) and CatalogService (ByDomain) resolve a tenant with no
// write capability in their dependency surface (interface segregation,
// Architecture Rule 3).
type TenantReadRepo interface {
	ByID(ctx context.Context, tenantID string) (Tenant, error)
	ByDomain(ctx context.Context, domain string) (Tenant, error)
}

// TenantWriteRepo is the admin control-plane write contract (AdminService only).
// Both ports take an explicit pgx.Tx so the caller commits the setter and its
// audit-log row in one transaction (Architecture Rule 7), and return rows-affected
// so a call for a missing tenant is a detectable no-op rather than a silent
// success.
type TenantWriteRepo interface {
	// SetFeeRate replaces the tenant-level default commission (basis points) and
	// its operator note in one write. A nil notes clears the column to NULL.
	// Returns ErrFeeRateOutOfRange if bps violates the 0 <= bps < 10000 CHECK.
	SetFeeRate(ctx context.Context, tx pgx.Tx, tenantID string, bps int, notes *string) (int64, error)
	// SetReportingPolicy replaces the reporting_policy JSONB for a tenant.
	SetReportingPolicy(ctx context.Context, tx pgx.Tx, tenantID string, policyJSON []byte) (int64, error)
}

// NewTenantReadRepo composes the read-only tenant ports over the fat sqlc.Querier.
func NewTenantReadRepo(q sqlc.Querier) TenantReadRepo { return &tenantRepo{q: q} }

// NewTenantWriteRepo composes the admin write ports over the fat sqlc.Querier.
// Same concrete *tenantRepo as NewTenantReadRepo — the split is at the interface,
// not the implementation.
func NewTenantWriteRepo(q sqlc.Querier) TenantWriteRepo { return &tenantRepo{q: q} }

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

func (r *tenantRepo) SetFeeRate(
	ctx context.Context, tx pgx.Tx, tenantID string, bps int, notes *string,
) (int64, error) {
	v, err := guardFeeRateBps(bps)
	if err != nil {
		return 0, err
	}
	n, err := sqlc.New(tx).SetTenantFeeRateBps(ctx, sqlc.SetTenantFeeRateBpsParams{
		TenantID:     tenantID,
		FeeRateBps:   v,
		FeeRateNotes: pgTextPtr(notes),
	})
	return n, mapFeeWriteErr(err, "set tenant fee rate")
}

func (r *tenantRepo) SetReportingPolicy(
	ctx context.Context, tx pgx.Tx, tenantID string, policyJSON []byte,
) (int64, error) {
	n, err := sqlc.New(tx).SetTenantReportingPolicy(ctx, sqlc.SetTenantReportingPolicyParams{
		TenantID:        tenantID,
		ReportingPolicy: policyJSON,
	})
	if err != nil {
		return 0, fmt.Errorf("set tenant reporting policy: %w", err)
	}
	return n, nil
}

func tenantFromRow(row sqlc.RampTenant) Tenant {
	return Tenant{
		ID:                         row.TenantID,
		Domain:                     row.Domain,
		Ed25519KeyRef:              row.Ed25519KeyRef,
		HMACSecretRef:              row.HmacSecretRef,
		SigningScheme:              string(row.SigningScheme),
		RSAKeyRef:                  textOrEmpty(row.RsaKeyRef),
		CloudFrontKeyPairID:        textOrEmpty(row.CloudfrontKeyPairID),
		ReportingPolicy:            row.ReportingPolicy,
		AllowBrokerRelay:           row.AllowBrokerRelay,
		FeeRateBps:                 int(row.FeeRateBps),
		FeeRateNotes:               textFromPG(row.FeeRateNotes),
		ActivateNewAgentsByDefault: row.ActivateNewAgentsByDefault,
	}
}

func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
