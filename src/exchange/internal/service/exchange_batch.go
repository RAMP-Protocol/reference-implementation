// Batch ExecuteTransaction path (items[] batch path).
//
// A TransactionRequest carrying items[] (offer absent) is the first-class batch
// shape: each item carries its own full signed Offer + detached AgentAcceptance,
// while requester + idempotency_key are SHARED across the whole request (the
// agent signs every item's acceptance over that shared requester + key). The
// Exchange executes each item independently and NON-ATOMICALLY: a per-item
// business denial (bad signature, expired offer, billing denied, …) becomes that
// item's TransactionResultItem.denial_reason and the loop continues; only an
// envelope-invalid or internal error aborts the whole batch.
//
// The load-bearing fix: each item persists under a DERIVED per-item
// key idempotency_key+":"+offer_id, used BOTH as the durable idempotency_key
// (transaction_log.idempotency_key TEXT UNIQUE — distinct offer_ids ⇒ distinct
// values, no UNIQUE violation) AND as the billing Authorize/Record/Release dedup
// key (so N items under one shared request key each charge independently). The
// request-level idempotency_key is UNCHANGED for VerifyOfferAcceptance (what the
// agent signed) and is carried byte-identical into every item's verify. The
// derived key is Exchange-internal persistence/billing ONLY — never fed to the
// acceptance verify.

package service

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampcost"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// executeBatch runs the items[] batch path (the SOLE ExecuteTransaction
// pipeline; N=1 is a one-element batch): validate the shared envelope, return the
// ORIGINAL result on a replayed request key, load the shared agent identity ONCE,
// then execute each item collect-and-continue. Per-item business denials stay
// in-body; an envelope/internal failure aborts the whole batch.
//
// Request-level idempotency replay: a resent idempotency_key returns the ORIGINAL
// TransactionResponse rather than re-executing (ramp.proto conformance —
// "a replay returns the original result rather than re-executing"). The check is
// done DURABLY off the persisted transaction_log rows (replayBatchResponse), so it
// returns the same original result whether the replay hits this process or another
// after a restart/failover — no in-memory cache is consulted. The
// transaction_log.idempotency_key UNIQUE constraint (keyed on the DERIVED per-item
// key) remains underneath as the last-resort double-charge backstop for a genuine
// race that slips past the pre-check.
func (s *ExchangeService) executeBatch(
	ctx context.Context, req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	if err := s.validateBatchRequest(req); err != nil {
		return nil, err
	}
	agentID, billingRef, err := s.resolveAgentID(ctx, req)
	if err != nil {
		return nil, err
	}
	// Idempotent-replay: a resent idempotency_key returns the ORIGINAL response
	// rather than re-executing (ramp.proto conformance). The lookup is durable —
	// done directly off the persisted transaction_log rows — so a replay
	// reconstructs the original result identically regardless of which instance
	// serves it or whether the original process is still running. There is no
	// in-memory idempotency cache; the persisted rows are the sole source of truth.
	//
	// The stored result carries a signed retrieval URL bound to the ORIGINAL
	// agent's identity; the derived probe key (idempotency_key:offer_id) is a
	// client-chosen token, not a bearer secret. replayBatchResponse therefore
	// serves the stored result ONLY to a caller that proves possession of that
	// agent key (body offer-acceptance) — a foreign principal presenting the pair
	// is refused with PermissionDenied, never handed the URL.
	if resp, replay, err := s.replayBatchResponse(ctx, req, agentID); err != nil {
		return nil, err
	} else if replay {
		return resp, nil
	}
	// The correlation id + provenance are request-scoped, so they are resolved
	// ONCE here at the service boundary and carried to persistence as data. No
	// layer below reaches into the context for a value it writes.
	correlation := resolveRequestCorrelation(ctx)
	results := make([]*rampv1.TransactionResultItem, 0, len(req.GetItems()))
	var sharedThumbprint string
	var lastTxID string
	for _, item := range req.GetItems() {
		res, thumb, execErr := s.executeBatchItem(ctx, req, item, agentID, billingRef, correlation)
		if execErr != nil {
			// A non-denial (envelope-invalid / internal) failure aborts the whole
			// batch; a classified denial is folded into the in-body result.
			denied, ok := batchDenialResult(item, execErr)
			if !ok {
				return nil, execErr
			}
			results = append(results, denied)
			continue
		}
		if sharedThumbprint == "" {
			sharedThumbprint = thumb
		}
		lastTxID = res.GetTransactionId()
		results = append(results, res)
	}
	// The VALIDATED outcome line is emitted once per successful batch
	// (at least one item persisted) through the request-scoped logger. The durable
	// transaction_log rows (loaded by replayBatchResponse on a resent key) are the
	// sole record of a replay — no in-memory LRU is consulted, so the same original
	// result is returned whether the replay hits this process or another (post
	// restart/failover).
	if lastTxID != "" {
		s.logOutcome(ctx, "execute_transaction", "VALIDATED",
			Caller{KeyID: agentID, Kind: CallerAgent, AgentID: agentID}, nil, agentID, lastTxID, nil)
	}
	return buildBatchTxResponse(results, sharedThumbprint)
}

// validateBatchRequest checks the batch envelope invariants: the shared
// idempotency_key + requester, and each item's offer signature + agent
// acceptance signature. A missing envelope field is KindInvalidRequest and
// aborts the whole batch (it is malformed, not a per-item business denial).
func (s *ExchangeService) validateBatchRequest(req *rampv1.TransactionRequest) error {
	if req.GetIdempotencyKey() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "idempotency_key required").WithField("idempotency_key")
	}
	if len(req.GetIdempotencyKey()) > maxIdempotencyKeyLen {
		return exchange.Newf(exchange.KindInvalidRequest,
			"idempotency_key exceeds %d bytes", maxIdempotencyKeyLen).WithField("idempotency_key")
	}
	if req.GetRequester().GetId() == "" {
		return exchange.Newf(exchange.KindInvalidRequest, "requester.id required")
	}
	if len(req.GetRequester().GetDomain()) > maxRequesterDomainLen {
		return exchange.Newf(exchange.KindInvalidRequest,
			"requester.domain exceeds %d bytes", maxRequesterDomainLen).WithField("requester.domain")
	}
	// At least one item is required: an empty items[] is a malformed envelope, not
	// an empty-but-valid batch (mirrors the broker C3 guard). Rejecting here
	// prevents returning an empty TransactionResponse for a body that carried no
	// work.
	if len(req.GetItems()) == 0 {
		return exchange.Newf(exchange.KindInvalidRequest, "at least one item required")
	}
	for i, item := range req.GetItems() {
		if item.GetOffer().GetSignature() == "" {
			return exchange.Newf(exchange.KindInvalidRequest, "item %d: offer signature required", i)
		}
		if item.GetAgentAcceptance().GetSignature() == "" {
			return exchange.Newf(exchange.KindInvalidRequest, "item %d: agent_acceptance signature required", i)
		}
	}
	return nil
}

// executeBatchItem runs one batch item through the SAME single-offer pipeline
// (resolveOfferForTx → authorizeExecute → resolveBilling → mintSignedURL →
// persistTransaction), reusing them verbatim by re-projecting the item onto a
// per-item synthetic TransactionRequest that carries the SHARED envelope
// (idempotency_key + requester) plus THIS item's offer + acceptance at the top
// level — so VerifyOfferAcceptance binds the request-level key the agent signed.
// Billing + persistence use the DERIVED per-item key.   On success it
// returns the result item (which itself carries the per-item cost) and the agent
// thumbprint; on failure the classifying error (denial vs abort decided by the
// caller).
func (s *ExchangeService) executeBatchItem(
	ctx context.Context, req *rampv1.TransactionRequest, item *rampv1.TransactionItem,
	agentID, billingRef string, correlation requestCorrelation,
) (*rampv1.TransactionResultItem, string, error) {
	// Re-project the item onto a per-item synthetic 1-item TransactionRequest that
	// carries the SHARED envelope (idempotency_key + requester) + THIS item — so
	// the shared pipeline (resolveOfferForTx / verifyAgentAcceptance read items[0])
	// runs verbatim and VerifyOfferAcceptance binds the request-level key the agent
	// signed. Billing + persistence use the DERIVED per-item key.
	itemReq := &rampv1.TransactionRequest{
		Ver:            req.GetVer(),
		IdempotencyKey: req.GetIdempotencyKey(),
		Requester:      req.GetRequester(),
		Items:          []*rampv1.TransactionItem{item},
	}
	resolved, err := s.resolveOfferForTx(itemReq)
	if err != nil {
		return nil, "", err
	}
	tenant, err := s.tenants.ByID(ctx, resolved.entry.TenantID)
	if err != nil {
		return nil, "", exchange.Wrap(exchange.KindInternal, err, "load tenant")
	}
	caller, binding, err := s.authorizeExecute(ctx, itemReq, agentID, tenant)
	if err != nil {
		return nil, "", err
	}
	// Deny an agent holding an overdue reporting obligation before any funds are
	// reserved (v1.1 reporting-overdue gate): after authorization, before billing.
	// Checked per item because a multi-exchange batch's items can resolve to
	// different tenants, and the overdue rule is per (tenant, agent).
	if oerr := s.denyIfReportingOverdue(ctx, caller, &tenant, agentID); oerr != nil {
		return nil, "", oerr
	}
	// Resolve the effective commission at Authorize, where the tenant (hence its
	// default rate) and THIS item's catalog entry resource owner are both in
	// scope. The resolved rate and owner ride onto the hold so a settling adapter
	// freezes the revenue/fee split from one transaction's truth without a
	// database read; non-splitting adapters ignore them. Resolved per item
	// because each item's entry can name a different owner (and hence a
	// different override), same reasoning as the per-item tenant load above.
	// resolved.entry.ResourceOwnerID is non-empty for every entry created after
	// migration 000018 — the catalog push gate requires owner attestation before
	// an entry can be transacted; rows predating that migration must be
	// backfilled before settlement (see the operations doc).
	override, err := s.feeOverrides.ByOwner(ctx, tenant.ID, resolved.entry.ResourceOwnerID)
	if err != nil {
		return nil, "", exchange.Wrap(exchange.KindInternal, err, "resolve fee override")
	}
	feeRateBps := ResolveFeeRateBps(tenant.FeeRateBps, override)
	// Derived per-item dedup key: distinct offer_ids ⇒ distinct keys, so neither
	// the idempotency_key UNIQUE backstop nor the billing dedup collapses the items.
	derivedKey := req.GetIdempotencyKey() + ":" + item.GetOffer().GetOfferId()
	result, err := s.runBatchItemBilling(ctx, batchItemBilling{
		tenant: tenant, resolved: resolved, itemReq: itemReq, item: item,
		agentID: agentID, billingRef: billingRef, binding: binding, derivedKey: derivedKey,
		resourceOwnerID: resolved.entry.ResourceOwnerID, feeRateBps: feeRateBps,
		correlation: correlation,
	})
	if err != nil {
		return nil, "", err
	}
	return result, binding.thumbprint, nil
}

// batchItemBilling names the inputs runBatchItemBilling consumes so the call
// stays under the per-function arg cap.
type batchItemBilling struct {
	tenant   repo.Tenant
	resolved resolvedOffer
	itemReq  *rampv1.TransactionRequest
	item     *rampv1.TransactionItem
	agentID  string
	// billingRef is the paying account handle read from the agent's row (ADR-021
	// D5). The paid path charges it; an empty ref denies the item (unregistered).
	billingRef string
	binding    agentBinding
	derivedKey string
	// resourceOwnerID is the item entry's owner-attested payee; feeRateBps is
	// the effective commission resolved at Authorize. Both ride the hold so the
	// settlement split is frozen per item (see executeBatchItem).
	resourceOwnerID string
	feeRateBps      int
	// correlation is the request-scoped id + provenance pair executeBatch
	// resolved, passed through to the evidence row.
	correlation requestCorrelation
}

// runBatchItemBilling reserves funds, mints the signed URL, builds the per-item
// result, and persists the transaction for ONE batch item under the DERIVED
// per-item key, mirroring the single-offer hot path (authorize → sign → persist →
// record) with the same release-on-failure ordering. The result item is built
// BEFORE persist (over a pre-minted transaction_id) and serialized into
// transaction_log.result_payload on the SAME INSERT, so a committed row always
// carries its original result — a replay returns it verbatim with no re-execution
// (ramp.proto idempotency conformance). Record runs after persist so the
// idempotency_key UNIQUE backstop fires before a duplicate charge can land.
func (s *ExchangeService) runBatchItemBilling(
	ctx context.Context, in batchItemBilling,
) (*rampv1.TransactionResultItem, error) {
	// Free-resource path (ADR-009 D2): a zero unit_cost bypasses the billing
	// adapter entirely — no Authorize, no Record, no Release. PricingDoc.IsFree is
	// the single unit_cost==0 predicate; it drives the Authorize gate here, the
	// Record gate below, AND the obligation's required_fields (buildPersistIntent
	// drops the unsatisfiable billing_id requirement), so the free/paid decision can
	// never disagree across those sites. auth stays zero-valued on the free path, so
	// billing_id persists NULL (ADR-009 D5) and the wire field is omitted
	// (buildBatchResultItem carries the empty handle through as an absent proto3
	// scalar); the WAL row and signed URL below are still issued. On the paid path
	// the resolved commission (resourceOwnerID, feeRateBps) rides onto the hold so a
	// settling adapter freezes the revenue/fee split at Authorize.
	free := in.resolved.pricing.IsFree()
	var auth billing.AuthorizeResult
	if !free {
		var bErr error
		auth, bErr = s.resolveBilling(ctx, billingResolution{
			tenantID: in.tenant.ID, billingRef: in.billingRef,
			pricing: in.resolved.pricing, idempotencyKey: in.derivedKey,
			resourceOwnerID: in.resourceOwnerID, feeRateBps: in.feeRateBps,
		})
		if bErr != nil {
			return nil, bErr
		}
	}
	signed, err := s.mintSignedURL(ctx, in.tenant, in.resolved.entry, in.binding.thumbprint)
	if err != nil {
		s.releaseHold(ctx, auth.BillingID, in.derivedKey, "url sign failed")
		return nil, err
	}
	// Mint the transaction_id and build the result item BEFORE the INSERT so the
	// serialized item lands on the same row in the same transaction.
	txID := uuid.NewString()
	result := buildBatchResultItem(in.item, in.resolved.entry, txID, auth.BillingID, signed, in.resolved.pricing)
	payload, err := protobuf.Marshal(result)
	if err != nil {
		s.releaseHold(ctx, auth.BillingID, in.derivedKey, "marshal result failed")
		return nil, exchange.Wrap(exchange.KindInternal, err, "marshal transaction result")
	}
	rec, err := s.persistTransaction(ctx, persistInput{
		tenant: in.tenant, entry: in.resolved.entry, pricing: in.resolved.pricing,
		req: in.itemReq, item: in.item, agentID: in.agentID, auth: auth, signed: signed,
		agentHash: in.binding.digest, agentPublicKey: in.binding.pub,
		agentDiscoveryURL: in.binding.discoveryURL, idempotencyKey: in.derivedKey,
		offerCanonicalBytes:      in.resolved.offerCanonicalBytes,
		acceptanceCanonicalBytes: in.binding.acceptanceBytes,
		correlation:              in.correlation,
		transactionID:            txID, resultPayload: payload,
	})
	if err != nil {
		s.releaseHold(ctx, auth.BillingID, in.derivedKey, "persist failed")
		return nil, err
	}
	// Record settles the hold best-effort, AFTER the WAL commit and outside any shared
	// transaction. A Record error is logged, not surfaced: the transaction is already
	// committed and the agent owns the URL. A process crash in this window (row
	// committed, Record never attempted) leaves the hold to expire natively — a
	// bounded, one-sided under-charge (deterministic ids prevent any double-charge).
	// The settlement-completeness reconciliation sweep that would re-post such rows is
	// deferred post-v1 (ADR-011 "Out of scope"). Paid path only, keyed off the same
	// `free` predicate as Authorize (ADR-009 D2): the free path never authorized, so
	// there is nothing to confirm.
	if !free {
		if rErr := s.billing.Record(ctx, auth.BillingID, int64(in.resolved.pricing.EstQty), in.derivedKey); rErr != nil {
			s.logBillingRecordFailed(ctx, rec.TransactionID, auth.BillingID, rErr)
		}
	}
	return result, nil
}

// buildBatchResultItem assembles one successful TransactionResultItem mirroring
// buildTxResponse: it carries the item's offer_id, transaction/billing ids, the
// per-item cost, the signed retrieval endpoint + its expiry, and the per-item
// reporting obligation. Built BEFORE persist over the pre-minted transaction_id
// and billing_id so the item can be serialized onto its own transaction_log row.
// Money is rendered in EXACT decimal then the canonical wire string, never float.
func buildBatchResultItem(
	item *rampv1.TransactionItem, entry repo.CatalogEntry, transactionID, billingID string,
	signed helpers.SignedURL, pricing PricingDoc,
) *rampv1.TransactionResultItem {
	title := entry.ResourceID
	endpoint := signed.URL
	qty := decimal.NewFromInt32(maxInt32(pricing.EstQty, 1))
	amountStr, aErr := helpers.FormatMoney(pricing.UnitCost.Mul(qty))
	ucStr, uErr := helpers.FormatMoney(pricing.UnitCost)
	var cost *rampv1.Cost
	if aErr == nil && uErr == nil {
		cost = &rampv1.Cost{Amount: amountStr, Currency: pricing.Currency, UnitCost: &ucStr}
	}
	return &rampv1.TransactionResultItem{
		OfferId:           item.GetOffer().GetOfferId(),
		TransactionId:     transactionID,
		BillingId:         billingID,
		ResourceTitle:     &title,
		Cost:              cost,
		ExpiresAt:         timestamppb.New(signed.Expiry),
		RetrievalEndpoint: &endpoint,
		DeliveryMethod:    rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ReportingObligation: &rampv1.ReportingObligation{
			Required: true,
			Endpoint: strPtr("/ramp.v1.ExchangeService/ReportUsage"),
		},
	}
}

// buildBatchTxResponse assembles the wire TransactionResponse for a batch:
// items[] in original order, the SHARED agent_identity_hash set ONCE (requester
// is request-scoped, so all items bind to one thumbprint), and the aggregate
// total_cost computed per-currency over the authoritative per-item costs
// (rampcost.BatchTotal — the SAME primitive the broker fan-out uses). A
// single-currency batch carries the exact sum; a mixed-currency batch carries no
// scalar (rely on items[].cost); a batch where every item was denied carries no
// thumbprint and no total — all correct zero-value shapes.
func buildBatchTxResponse(
	items []*rampv1.TransactionResultItem, agentThumbprint string,
) (*rampv1.TransactionResponse, error) {
	total, err := rampcost.BatchTotal(items)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "aggregate batch total_cost")
	}
	return &rampv1.TransactionResponse{
		Ver:               rampproto.Ver,
		Items:             items,
		AgentIdentityHash: agentThumbprint,
		TotalCost:         total,
	}, nil
}

// batchDenialResult classifies a per-item execution error: a denial Kind
// (DenialReasonForKind ok) becomes an in-body TransactionResultItem carrying the
// denial_reason and offer_id; any other Kind (envelope-invalid / internal /
// not-found) returns ok=false so the caller aborts the whole batch.
func batchDenialResult(
	item *rampv1.TransactionItem, err error,
) (*rampv1.TransactionResultItem, bool) {
	reason, ok := DenialReasonForKind(err)
	if !ok {
		return nil, false
	}
	r := reason
	return &rampv1.TransactionResultItem{
		OfferId:      item.GetOffer().GetOfferId(),
		DenialReason: &r,
	}, true
}
