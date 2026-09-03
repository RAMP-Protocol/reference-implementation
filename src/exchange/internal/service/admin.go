package service

import (
	"context"
	"errors"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// AdminService implements the admin control-plane setters (SetTenantFeeRate,
// SetReportingPolicy). It is deliberately separate from ExchangeService: the
// operator/config plane is delineated from the agent hot path (ADR-022), and the
// setters share none of the hot-path dependencies. Both setters are full-replace,
// last-writer-wins, and write their audit row in the SAME transaction as the
// mutation — so an unknown-tenant no-op persists nothing.
type AdminService struct {
	tenants repo.TenantWriteRepo
	audit   repo.AuditRepo
	tx      db.TxRunner
}

// AdminDeps bundles the AdminService wiring.
type AdminDeps struct {
	Tenants  repo.TenantWriteRepo
	Audit    repo.AuditRepo
	TxRunner db.TxRunner
}

// NewAdminService assembles the admin service.
func NewAdminService(d AdminDeps) *AdminService {
	return &AdminService{tenants: d.Tenants, audit: d.Audit, tx: d.TxRunner}
}

// NewAdminServiceFromPool assembles the admin service straight from a pool +
// queries — the composition-root convenience shared by cmd/server and the
// integration harness so the repo/PoolRunner wiring lives in one place. The
// AdminService itself still depends only on the narrow repo/TxRunner ports.
func NewAdminServiceFromPool(pool *pgxpool.Pool, queries *sqlc.Queries) *AdminService {
	return NewAdminService(AdminDeps{
		Tenants:  repo.NewTenantWriteRepo(queries),
		Audit:    repo.NewAuditRepo(queries),
		TxRunner: db.PoolRunner{Pool: pool},
	})
}

// AdminCaller carries the coarse attribution the audit row records: the caller's
// source address (from the Connect peer), the correlation id, and an optional
// actor.
//
// Actor is nil on the RPC path, because v1 has no authenticated operator
// identity to record. It is NOT always nil: a boot-time write has no network
// peer and no request, so the process names itself instead (bootAdminCaller in
// the composition root). Registration, on the agent plane, always has one — the
// request signature identifies the agent that registered.
type AdminCaller struct {
	SourceAddr string
	RequestID  string
	Actor      *string
}

// FeeRateValues is the fee-rate payload shared by the write and its RPC read-back:
// under full replace the persisted/echoed values ARE the validated input, so one
// type serves both directions (mirrors ADR-022 §1's nested shared-payload
// envelope). Notes nil clears the note.
type FeeRateValues struct {
	TenantID   string  `json:"tenant_id"`
	FeeRateBps int     `json:"fee_rate_bps"`
	Notes      *string `json:"notes,omitempty"`
}

// ReportingPolicyValues is the reporting-policy payload shared by the write and its
// RPC read-back (full replace; one type both directions, per ADR-022 §1).
type ReportingPolicyValues struct {
	TenantID          string   `json:"tenant_id"`
	RequiredFields    []string `json:"required_fields,omitempty"`
	QuantityTolerance *float64 `json:"quantity_tolerance,omitempty"`
	WindowSeconds     *int32   `json:"window_seconds,omitempty"`
}

// SetTenantFeeRate replaces the tenant-level default commission and its note, and
// records the change. Bounds are enforced upstream by the protovalidate
// interceptor, so the service does not re-check them; it owns persistence + audit.
func (s *AdminService) SetTenantFeeRate(
	ctx context.Context, caller AdminCaller, in FeeRateValues,
) (FeeRateValues, error) {
	detail, err := marshalAuditDetail(in)
	if err != nil {
		return FeeRateValues{}, err
	}
	err = s.runSetter(ctx, caller, in.TenantID, "SetTenantFeeRate", detail, func(tx pgx.Tx) (int64, error) {
		n, werr := s.tenants.SetFeeRate(ctx, tx, in.TenantID, in.FeeRateBps, in.Notes)
		if werr != nil {
			return 0, mapSetterError(werr, repo.ErrFeeRateOutOfRange, "fee rate out of range", "set tenant fee rate")
		}
		return n, nil
	})
	if err != nil {
		return FeeRateValues{}, err
	}
	return in, nil
}

// SetReportingPolicy validates the required_fields membership, replaces the
// tenant's reporting_policy JSONB, and records the change. Ranges/pattern/length/
// uniqueness are enforced upstream by protovalidate; the service adds only the
// known-field membership check the wire pattern cannot express.
func (s *AdminService) SetReportingPolicy(
	ctx context.Context, caller AdminCaller, in ReportingPolicyValues,
) (ReportingPolicyValues, error) {
	if verr := ValidateRequiredFieldNames(in.RequiredFields); verr != nil {
		return ReportingPolicyValues{}, verr
	}
	policyJSON, err := encodeReportingPolicy(in.RequiredFields, in.QuantityTolerance, in.WindowSeconds)
	if err != nil {
		return ReportingPolicyValues{}, exchange.Wrap(exchange.KindInternal, err, "encode reporting policy")
	}
	detail, err := marshalAuditDetail(in)
	if err != nil {
		return ReportingPolicyValues{}, err
	}
	err = s.runSetter(ctx, caller, in.TenantID, "SetReportingPolicy", detail, func(tx pgx.Tx) (int64, error) {
		n, werr := s.tenants.SetReportingPolicy(ctx, tx, in.TenantID, policyJSON)
		if werr != nil {
			return 0, mapSetterError(werr, nil, "", "set reporting policy")
		}
		return n, nil
	})
	if err != nil {
		return ReportingPolicyValues{}, err
	}
	return in, nil
}

// defaultAgentCreditAudit is the audit-detail payload for a default-agent-credit
// replace. Credit is the decimal rendering of the applied amount at the ledger
// asset scale, so the JSONB stays readable without a rational-number decoder.
type defaultAgentCreditAudit struct {
	TenantID string `json:"tenant_id"`
	Credit   string `json:"default_agent_credit"`
}

// SetDefaultAgentCredit replaces the tenant's default agent credit and records
// the change. There is no admin RPC for this setter — the only caller is the
// boot-time EXCHANGE_DEFAULT_AGENT_CREDIT seeding, which routes through here so
// the write and its audit row commit in one transaction like every other write
// on the tenant admin plane.
func (s *AdminService) SetDefaultAgentCredit(
	ctx context.Context, caller AdminCaller, tenantID string, credit *big.Rat,
) error {
	detail, err := marshalAuditDetail(defaultAgentCreditAudit{
		TenantID: tenantID,
		Credit:   money.DecimalString(credit),
	})
	if err != nil {
		return err
	}
	return s.runSetter(ctx, caller, tenantID, "SetDefaultAgentCredit", detail, func(tx pgx.Tx) (int64, error) {
		n, werr := s.tenants.SetDefaultAgentCredit(ctx, tx, tenantID, credit)
		if werr != nil {
			return 0, mapSetterError(werr, repo.ErrDefaultCreditInvalid,
				"default agent credit invalid", "set tenant default agent credit")
		}
		return n, nil
	})
}

// runSetter executes a setter mutation and its audit row in one transaction.
// write returns rows-affected; a 0 becomes KindNotFound and rolls back, so no
// audit row is written for a missing tenant. This is the shared skeleton both
// setters funnel through (single transactional boundary, one audit-append shape).
func (s *AdminService) runSetter(
	ctx context.Context,
	caller AdminCaller,
	tenantID, action string,
	detail []byte,
	write func(tx pgx.Tx) (int64, error),
) error {
	return s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		n, err := write(tx)
		if err != nil {
			return err
		}
		if n == 0 {
			return exchange.Newf(exchange.KindNotFound, "tenant %q not found", tenantID)
		}
		return appendAudit(ctx, tx, s.audit, repo.AuditEntry{
			Actor:      caller.Actor,
			SourceAddr: caller.SourceAddr,
			Action:     action,
			Detail:     detail,
			TenantID:   tenantID,
			RequestID:  requestIDPtr(caller.RequestID),
		})
	})
}

// mapSetterError wraps a tenant-setter write error for transport: the repo's
// validation sentinel (nil when the setter has none) maps to KindInvalidRequest,
// anything else to KindInternal, each with its op string. Every runSetter write
// funnels through here so the sentinel-vs-internal split is spelled once.
func mapSetterError(err, sentinel error, invalidOp, internalOp string) error {
	if sentinel != nil && errors.Is(err, sentinel) {
		return exchange.Wrap(exchange.KindInvalidRequest, err, invalidOp)
	}
	return exchange.Wrap(exchange.KindInternal, err, internalOp)
}
