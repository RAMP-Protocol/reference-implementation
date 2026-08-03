package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// AuditEntry is the domain view of an admin control-plane change to append. Actor
// and RequestID are optional (nil → SQL NULL): v1 has no authenticated operator
// identity, and request_id is absent only if no X-Request-ID reached the handler.
type AuditEntry struct {
	LogID      string
	Actor      *string
	SourceAddr string
	Action     string
	Detail     []byte // JSONB of applied values
	TenantID   string
	RequestID  *string
}

// AuditRecord is the domain view of a persisted audit_log row (read side).
type AuditRecord struct {
	LogID      string
	Actor      *string
	SourceAddr string
	Action     string
	Detail     []byte
	TenantID   string
	RequestID  *string
	CreatedAt  time.Time
}

// AuditRepo is the append-only admin audit log. Append takes an explicit pgx.Tx
// so the row commits in the same transaction as the setter it records
// (Architecture Rule 7); ByTenant is the read path used for change
// reconstruction and integration side-effect assertions.
type AuditRepo interface {
	Append(ctx context.Context, tx pgx.Tx, e AuditEntry) error
	ByTenant(ctx context.Context, tenantID string) ([]AuditRecord, error)
}

// NewAuditRepo composes an AuditRepo over the sqlc.Querier (used for reads; the
// append binds a tx-scoped querier via sqlc.New(tx)).
func NewAuditRepo(q sqlc.Querier) AuditRepo { return &auditRepo{q: q} }

type auditRepo struct{ q sqlc.Querier }

func (r *auditRepo) Append(ctx context.Context, tx pgx.Tx, e AuditEntry) error {
	err := sqlc.New(tx).AppendAuditLog(ctx, sqlc.AppendAuditLogParams{
		LogID:      e.LogID,
		Actor:      pgTextPtr(e.Actor),
		SourceAddr: e.SourceAddr,
		Action:     e.Action,
		Detail:     e.Detail,
		TenantID:   e.TenantID,
		RequestID:  pgTextPtr(e.RequestID),
	})
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

func (r *auditRepo) ByTenant(ctx context.Context, tenantID string) ([]AuditRecord, error) {
	rows, err := r.q.AuditLogByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("audit log by tenant: %w", err)
	}
	out := make([]AuditRecord, 0, len(rows))
	for i := range rows {
		out = append(out, auditFromRow(rows[i]))
	}
	return out, nil
}

func auditFromRow(row sqlc.RampAuditLog) AuditRecord {
	rec := AuditRecord{
		LogID:      row.LogID,
		Actor:      textFromPG(row.Actor),
		SourceAddr: row.SourceAddr,
		Action:     row.Action,
		Detail:     row.Detail,
		TenantID:   row.TenantID,
		RequestID:  textFromPG(row.RequestID),
	}
	if row.CreatedAt.Valid {
		rec.CreatedAt = row.CreatedAt.Time
	}
	return rec
}
