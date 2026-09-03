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
	"math/big"

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
	// DefaultAgentCredit is the one-time credit the Register flow grants a
	// freshly registered agent, denominated in the deployment ledger currency.
	// Zero (the column default) disables the grant. Never nil for a row read
	// through this repo; representable exactly at ledger asset scale 8 (the
	// write guard enforces it). Server-side commercial term, never on the wire.
	DefaultAgentCredit *big.Rat
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
	// SetDefaultAgentCredit replaces the per-tenant default credit granted to a
	// newly registered agent (deployment ledger currency; 0 disables the
	// grant). Reached only through AdminService.SetDefaultAgentCredit — the
	// boot-time env seeding (EXCHANGE_DEFAULT_AGENT_CREDIT) routes through the
	// service so the write commits with its audit row; there is no admin RPC.
	// Returns ErrDefaultCreditInvalid for a nil or negative amount, an amount
	// finer than ledger asset scale 8, or one too large for the column — whether
	// the Go-side guard catches it or the column's CHECK backstop rejects it.
	SetDefaultAgentCredit(ctx context.Context, tx pgx.Tx, tenantID string, credit *big.Rat) (int64, error)
	// SetActivateNewAgentsByDefault flips whether a newly registered agent
	// starts active in the billing system-of-record. The column defaults to
	// TRUE on insert, so this is only needed to opt a tenant out. No admin RPC
	// writes it yet, so this port is currently the highest surface that reaches
	// the column.
	SetActivateNewAgentsByDefault(ctx context.Context, tx pgx.Tx, tenantID string, active bool) (int64, error)
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
	return tenantFromRow(row)
}

func (r *tenantRepo) ByDomain(ctx context.Context, domain string) (Tenant, error) {
	row, err := r.q.GetTenantByDomain(ctx, domain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tenant{}, ErrTenantNotFound
		}
		return Tenant{}, fmt.Errorf("get tenant by domain: %w", err)
	}
	return tenantFromRow(row)
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
	return n, mapCheckWriteErr(err, "set tenant fee rate", ErrFeeRateOutOfRange)
}

func (r *tenantRepo) SetDefaultAgentCredit(
	ctx context.Context, tx pgx.Tx, tenantID string, credit *big.Rat,
) (int64, error) {
	v, err := guardDefaultAgentCredit(credit)
	if err != nil {
		return 0, err
	}
	n, err := sqlc.New(tx).SetTenantDefaultAgentCredit(ctx, sqlc.SetTenantDefaultAgentCreditParams{
		TenantID:           tenantID,
		DefaultAgentCredit: v,
	})
	return n, mapCheckWriteErr(err, "set tenant default agent credit", ErrDefaultCreditInvalid)
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

func (r *tenantRepo) SetActivateNewAgentsByDefault(
	ctx context.Context, tx pgx.Tx, tenantID string, active bool,
) (int64, error) {
	n, err := sqlc.New(tx).SetTenantActivateNewAgentsByDefault(ctx,
		sqlc.SetTenantActivateNewAgentsByDefaultParams{
			TenantID:                   tenantID,
			ActivateNewAgentsByDefault: active,
		})
	if err != nil {
		return 0, fmt.Errorf("set tenant activate_new_agents_by_default: %w", err)
	}
	return n, nil
}

func tenantFromRow(row sqlc.RampTenant) (Tenant, error) {
	// Propagate the NUMERIC decode error rather than swallowing it: a money
	// field must never be silently zeroed by a decode failure. The column's
	// CHECK excludes negative and NaN values, but a decode failure here means
	// the store and the reader disagree, and that must surface, not degrade
	// to "grant disabled".
	credit, err := ratFromNumeric(row.DefaultAgentCredit)
	if err != nil {
		return Tenant{}, fmt.Errorf("decode default_agent_credit for tenant %q: %w", row.TenantID, err)
	}
	return Tenant{
		ID:                         row.TenantID,
		Domain:                     row.Domain,
		Ed25519KeyRef:              row.Ed25519KeyRef,
		SigningScheme:              string(row.SigningScheme),
		RSAKeyRef:                  textOrEmpty(row.RsaKeyRef),
		CloudFrontKeyPairID:        textOrEmpty(row.CloudfrontKeyPairID),
		ReportingPolicy:            row.ReportingPolicy,
		AllowBrokerRelay:           row.AllowBrokerRelay,
		FeeRateBps:                 int(row.FeeRateBps),
		FeeRateNotes:               textFromPG(row.FeeRateNotes),
		ActivateNewAgentsByDefault: row.ActivateNewAgentsByDefault,
		DefaultAgentCredit:         credit,
	}, nil
}

func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
