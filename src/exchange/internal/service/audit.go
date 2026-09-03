package service

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// The audit-log mechanics both write paths share. The admin setters and agent
// registration append to the same table from two different transactions, and
// what they have in common is exactly what is below: minting the row id,
// appending inside the caller's transaction, giving a failed append one domain
// boundary, and encoding the applied-values payload. Everything else about a
// row — who acted, from where, under which action, with what detail shape —
// differs per caller and is built at the call site.
//
// This is a file of its own rather than a corner of either write path, because
// a helper kept beside one caller and reached into from the other is how the
// duplicate append this file retires got written in the first place.
//
// Note what is deliberately NOT shared: the transaction skeleton. A setter that
// affects zero rows means the tenant does not exist, so it fails and rolls back
// with no row written. A registration that loses the guarded update means a
// concurrent caller registered the account first, so it succeeds and commits
// with no row written. Same "wrote nothing" outcome, opposite meanings — and a
// single skeleton parameterised over both would hide the difference rather than
// name it.

// appendAudit writes one audit row inside the caller's transaction and gives a
// failed append the domain kind and operation the transport needs.
//
// It mints LogID itself, which is why a caller's repo.AuditEntry literal has no
// LogID field: the id is always a fresh UUID and no caller has a reason to
// choose one. A value set on e.LogID is overwritten.
func appendAudit(ctx context.Context, tx pgx.Tx, a repo.AuditRepo, e repo.AuditEntry) error {
	e.LogID = uuid.NewString()
	if err := a.Append(ctx, tx, e); err != nil {
		return exchange.Wrap(exchange.KindInternal, err, "append audit log")
	}
	return nil
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
