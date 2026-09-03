package service

import (
	"context"
	"errors"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// EvidenceView is everything the operator evidence read returns for one
// transaction: the append-once evidence row, the transaction-log facts beside
// it, and the reporting obligation if the transaction minted one.
//
// It is a read-only projection assembled from three repositories. Nothing here
// is derived or recomputed — a value the caller sees is a value the store
// holds, which is the property that makes the row usable as evidence.
type EvidenceView struct {
	Evidence    repo.EvidenceRecord
	Transaction repo.TransactionRecord
	// Obligation is nil when the transaction minted none — a reachable state, not
	// only a defensive one: a term whose pricing meters nothing owes no usage
	// report and writes no obligation row. A read that finds none must say so
	// instead of rendering a zero one, on a surface whose only purpose is
	// stating what happened.
	Obligation *repo.Obligation
}

// EvidenceReadService serves the operator-plane evidence read. It is separate
// from AdminService, which owns the control-plane setters: this service reads
// three tables and writes nothing, so it needs neither the transaction runner
// nor the audit repository those setters depend on.
type EvidenceReadService struct {
	evidence     repo.EvidenceRepo
	transactions repo.TransactionRepo
	obligations  repo.ObligationRepo
}

// NewEvidenceReadService composes the read service over the generated queries.
// The service itself holds only the three narrow repository ports; this is the
// composition-root convenience cmd/server and the integration harness share, so
// the repo wiring is written once.
func NewEvidenceReadService(queries sqlc.Querier) *EvidenceReadService {
	return &EvidenceReadService{
		evidence:     repo.NewEvidenceRepo(queries),
		transactions: repo.NewTransactionRepo(queries),
		obligations:  repo.NewObligationRepo(queries),
	}
}

// TransactionEvidenceCrossTenant returns the evidence view for one transaction,
// whatever tenant owns it.
//
// The cross-tenant scope is what the operator plane is for: an operator
// investigating a delivery holds a transaction id and no tenant id, and the
// plane is reachable only from the internal listener behind its network
// allowlist. A counterparty-facing read would have to be tenant-scoped instead,
// because counterparty agents legitimately hold transaction ids and the id alone
// must not open a row this sensitive.
func (s *EvidenceReadService) TransactionEvidenceCrossTenant(
	ctx context.Context, transactionID string,
) (EvidenceView, error) {
	// admin:cross_tenant — the operator plane has no per-tenant scope.
	evidence, err := s.evidence.ByTransactionCrossTenant(ctx, transactionID)
	if err != nil {
		if errors.Is(err, repo.ErrEvidenceNotFound) {
			return EvidenceView{}, exchange.Newf(exchange.KindNotFound,
				"no evidence for transaction %q", transactionID)
		}
		return EvidenceView{}, exchange.Wrap(exchange.KindInternal, err, "read transaction evidence")
	}

	transaction, err := s.transactions.ByID(ctx, transactionID)
	if err != nil {
		if errors.Is(err, repo.ErrTransactionNotFound) {
			// The evidence row's transaction_id is a foreign key onto
			// transaction_log with ON DELETE RESTRICT, so a miss here means the
			// two tables disagree rather than that the caller asked for
			// something absent. Refuse rather than render half a chain.
			return EvidenceView{}, exchange.Wrap(exchange.KindInternal, err,
				"evidence row has no transaction_log row")
		}
		return EvidenceView{}, exchange.Wrap(exchange.KindInternal, err, "read transaction log")
	}

	view := EvidenceView{Evidence: evidence, Transaction: transaction}

	obligation, err := s.obligations.ByTransaction(ctx, transactionID)
	switch {
	case errors.Is(err, repo.ErrObligationNotFound):
		// Left nil: the transaction minted no obligation.
	case err != nil:
		return EvidenceView{}, exchange.Wrap(exchange.KindInternal, err, "read reporting obligation")
	default:
		view.Obligation = &obligation
	}
	return view, nil
}
