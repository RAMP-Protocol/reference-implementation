package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
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
// actor. v1 has no authenticated operator identity, so Actor is nil in practice.
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
			return 0, mapFeeWriteError(werr)
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
			return 0, exchange.Wrap(exchange.KindInternal, werr, "set reporting policy")
		}
		return n, nil
	})
	if err != nil {
		return ReportingPolicyValues{}, err
	}
	return in, nil
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
		if aerr := s.audit.Append(ctx, tx, repo.AuditEntry{
			LogID:      uuid.NewString(),
			Actor:      caller.Actor,
			SourceAddr: caller.SourceAddr,
			Action:     action,
			Detail:     detail,
			TenantID:   tenantID,
			RequestID:  requestIDPtr(caller.RequestID),
		}); aerr != nil {
			return exchange.Wrap(exchange.KindInternal, aerr, "append audit log")
		}
		return nil
	})
}

func mapFeeWriteError(err error) error {
	if errors.Is(err, repo.ErrFeeRateOutOfRange) {
		return exchange.Wrap(exchange.KindInvalidRequest, err, "fee rate out of range")
	}
	return exchange.Wrap(exchange.KindInternal, err, "set tenant fee rate")
}

func marshalAuditDetail(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "marshal audit detail")
	}
	return b, nil
}

func requestIDPtr(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}
