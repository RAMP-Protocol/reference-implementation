package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceclient"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// Gather reads all three legs. Only the Exchange leg can fail the whole run:
// without the evidence row there is no transaction to render. The other two
// record why they came back empty and let the render proceed, because a chain
// missing its delivery witness still shows everything the Exchange and the
// agent signed.
func Gather(ctx context.Context, cfg Config) (Sources, error) {
	resp, err := fetchEvidence(ctx, cfg)
	if err != nil {
		return Sources{}, err
	}
	// Validate ran inside fetchEvidence, so Evidence and TransactionState are
	// non-nil here. Obligation may be nil, and reaching that is ordinary: a term
	// whose pricing meters nothing is a one-time perpetual sale, and the
	// Exchange mints no reporting obligation for it. The renderer states the
	// absence rather than assuming a duty, which is what keeps such a
	// transaction from rendering as an obligation in state "".
	s := Sources{
		Evidence:    resp.Evidence,
		Transaction: resp.TransactionState,
		Obligation:  resp.ObligationState,
	}
	s.Selection, s.SelectionAbsence = fetchSelection(ctx, cfg, s.Evidence)
	s.Delivery, s.DeliveryAbsence = fetchDelivery(ctx, cfg, s)
	return s, nil
}

// fetchEvidence reads the append-once row over the Exchange's admin plane.
//
// The request, the status check, the decode and Validate all live in
// internal/evidenceclient, outside both service trees, so the same code the
// operator runs here is the code an integration test drives against the real
// admin handler. This wrapper exists only to unpack Config.
func fetchEvidence(ctx context.Context, cfg Config) (*evidenceview.Response, error) {
	return evidenceclient.Fetch(ctx, cfg.AdminURL, cfg.TransactionID, cfg.Timeout)
}

// fetchSelection reads the Broker's own record of having offered this offer.
//
// It reads through the production repository interface, over a direct database
// connection, because the Broker has no operator read surface for its selection
// audit yet — no RPC serves selection_log, so there is no service to call. When
// one exists this leg becomes a client call and the database connection, the
// tunnel it needs, and this comment all go away. Going through the repository
// rather than issuing SQL here is what keeps the query, the tenant of its
// index, and the JSONB decoding in the one place that owns them.
func fetchSelection(
	ctx context.Context, cfg Config, e *evidenceview.Evidence,
) (*repo.SelectionLogEntry, string) {
	if cfg.BrokerDBURL == "" {
		return nil, "not read: no Broker database URL configured, so the routing leg was skipped"
	}
	agent, err := agentid.FromDirectory(e.RequesterID)
	if err != nil {
		return nil, fmt.Sprintf("not read: the signed requester id %q does not name a directory host: %v",
			e.RequesterID, err)
	}
	pool, err := db.Open(ctx, db.Config{DSN: cfg.BrokerDBURL}, slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, "not read: " + err.Error()
	}
	defer pool.Close()

	// The evidence row's own write time bounds the search: the Broker offered
	// the offer before the Exchange executed against it, never after.
	entry, err := repo.NewSelectionLogRepo(pool).LatestOfferingOffer(
		ctx, agent, e.OfferID, e.CreatedAt, cfg.BrokerWindow,
	)
	if err != nil {
		return nil, "not read: " + err.Error()
	}
	if entry == nil {
		return nil, fmt.Sprintf(
			"no selection recorded: the Broker logged no decision offering %s to %s in the %s before this transaction",
			e.OfferID, agent, cfg.BrokerWindow)
	}
	return entry, ""
}

// fetchDelivery sweeps the edge logs for the record carrying this transaction's
// URL digest.
func fetchDelivery(ctx context.Context, cfg Config, s Sources) (*DeliveryRecord, string) {
	if cfg.EdgeLogGroup == "" {
		return nil, "not read: no edge log group configured, so the delivery leg was skipped"
	}
	digest := hexOf(s.Transaction.SignedURLHash)
	if digest == "" {
		return nil, "not applicable: this transaction minted no signed URL, so there is no digest to search for"
	}
	// The evidence row cannot predate the delivery, and CloudWatch wants a
	// lower bound; a small margin before the row absorbs clock skew between the
	// Exchange and the edge.
	since := s.Evidence.CreatedAt.Add(-cfg.EdgeSkew)
	record, err := FindDelivery(ctx, cfg.AWS, cfg.EdgeLogGroup, cfg.EdgeRegions, digest, since)
	if err != nil {
		return nil, "not read: " + err.Error()
	}
	if record == nil {
		return nil, fmt.Sprintf(
			"no delivery recorded: no edge record carries digest %s in %d regions since %s "+
				"(CloudWatch ingestion lags, and a point of presence outside the swept list would not be found)",
			digest, len(cfg.EdgeRegions), since.UTC().Format(time.RFC3339))
	}
	return record, ""
}
