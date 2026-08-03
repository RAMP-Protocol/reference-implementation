// Request-level idempotent replay for the items[] batch path.
//
// A resent idempotency_key returns the ORIGINAL TransactionResponse rather than
// re-executing (ramp.proto conformance). The check is done DURABLY off the
// persisted transaction_log rows, so the same original result comes back whether
// the replay hits this process or another after a restart/failover. It lives
// beside the batch pipeline rather than inside it because the two answer
// different questions: executeBatch asks "what does this request produce", this
// file asks "has this request already produced it".

package service

import (
	"bytes"
	"context"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	protobuf "google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// replayBatchResponse detects a request-level idempotency replay durably and, on
// a hit, reconstructs the ORIGINAL TransactionResponse from the persisted
// transaction_log rows (ramp.proto: "a replay returns the original result rather
// than re-executing"). For each item in the resent request it loads the row under
// the DERIVED per-item key (idempotency_key:offer_id) and deserializes the
// persisted result_payload back into the original TransactionResultItem.
//
// Returns (resp, true, nil) when EVERY item resolves to a row carrying a
// result_payload AND the caller proves possession of the agent key those rows are
// bound to — the reconstructed original response, returned with NO billing
// Authorize/Record. Returns (nil, false, nil) when NO item has a persisted row —
// this is a fresh request, not a replay. Returns a KindIdempotent error (the safe
// AlreadyExists refusal) ONLY for a legacy pre-migration row whose result_payload
// is NULL and therefore cannot be reconstructed, or for a partially-persisted
// replay where some-but-not-all items resolved — neither can be returned verbatim.
//
// Ownership gate: the probe keys purely on the client-chosen idempotency_key:
// offer_id, so a bare hit proves nothing about WHO is calling. Because the stored
// result carries a signed retrieval URL bound to the original agent's identity,
// serving it to any caller that merely presents the pair would leak that URL. On a
// full-replay hit the caller must therefore prove possession of the bound agent
// key via the BODY offer-acceptance signature (verifyAgentAcceptance), and the
// thumbprint that proof derives must equal every persisted row's
// agent_identity_hash. requester.id alone is insufficient — it is caller-supplied.
// A mismatch (or an acceptance that does not verify) is KindPermissionDenied, and
// the stored result is never returned. The PoP verification runs ONLY on a hit, so
// the common fresh path (persisted == 0) still verifies acceptance exactly once,
// later, in executeBatchItem.
func (s *ExchangeService) replayBatchResponse(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string,
) (*rampv1.TransactionResponse, bool, error) {
	items := make([]*rampv1.TransactionResultItem, 0, len(req.GetItems()))
	rowHashes := make([][]byte, 0, len(req.GetItems()))
	persisted := 0
	for _, item := range req.GetItems() {
		derivedKey := req.GetIdempotencyKey() + ":" + item.GetOffer().GetOfferId()
		rec, err := s.transactions.ByIdempotencyKey(ctx, derivedKey)
		if errors.Is(err, repo.ErrTransactionNotFound) {
			continue
		}
		if err != nil {
			return nil, false, exchange.Wrap(exchange.KindInternal, err, "idempotent replay probe")
		}
		persisted++
		if len(rec.ResultPayload) == 0 {
			// Legacy pre-migration row: no stored result to return verbatim. Fall
			// back to the safe AlreadyExists refusal (never a re-execution).
			return nil, false, exchange.Newf(exchange.KindIdempotent,
				"idempotency_key already processed: %s", rec.TransactionID)
		}
		result := &rampv1.TransactionResultItem{}
		if err := protobuf.Unmarshal(rec.ResultPayload, result); err != nil {
			return nil, false, exchange.Wrap(exchange.KindInternal, err, "decode persisted transaction result")
		}
		items = append(items, result)
		rowHashes = append(rowHashes, rec.AgentIdentityHash)
	}
	if persisted == 0 {
		return nil, false, nil // not a replay
	}
	if persisted != len(req.GetItems()) {
		// A partial replay (some items persisted, some not) cannot be returned as a
		// verbatim original response; refuse safely rather than re-execute the rest.
		return nil, false, exchange.Newf(exchange.KindIdempotent,
			"idempotency_key already processed (partial)")
	}
	// Ownership gate — a replay is served only to the row's proven owner. Verify
	// the caller's body offer-acceptance (proof of possession of the bound agent
	// key) and require its thumbprint to match every persisted row's binding.
	binding, err := s.verifyAgentAcceptance(ctx, req, agentID)
	if err != nil {
		return nil, false, err
	}
	for _, h := range rowHashes {
		if !bytes.Equal(binding.digest, h) {
			return nil, false, exchange.Newf(exchange.KindPermissionDenied,
				"idempotency_key belongs to a different agent")
		}
	}
	resp, err := buildBatchTxResponse(items, binding.thumbprint)
	if err != nil {
		return nil, false, err
	}
	return resp, true, nil
}
