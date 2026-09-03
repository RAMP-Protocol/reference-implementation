// The finalized request-level response: storing it, reading it back, and
// deciding what a request that did not win its own claim is served.
//
// executeBatch writes the response onto the request claim write-once before the
// RPC returns; everything else here reads that store. It is kept beside — not
// inside — the per-item replay probe because the two are different sources for
// one answer: the probe rebuilds an original from the transaction_log rows,
// while this file serves the original the winner actually returned, denials
// included. serveLostClaim is where the two are ordered against each other.

package service

import (
	"context"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	protobuf "google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// finalizedWaitPolls and finalizedPollInterval pace awaitFinalizedResponse: a
// claim loser polls for the winner's finalized response every interval, at
// most finalizedWaitPolls times (~3s total). The bound counts polls rather
// than reading a clock: this is IO pacing for a concurrent writer, not
// business time, so it must not depend on the injected clock (which a
// DeterministicClock test never advances) — and ADR-008 D1 forbids time.Now.
const (
	finalizedWaitPolls    = 60
	finalizedPollInterval = 50 * time.Millisecond
)

// serveLostClaim answers a request that did NOT win the claim for its own
// (agent, key, item set): an exact retry, or the loser of a concurrent
// duplicate. It consults three sources in cost order, and only reaches the wait
// when the first two cannot answer.
//
//  1. The finalized response already stored on the claim. One read, no wait —
//     the common exact retry answers here.
//  2. The persisted per-item rows. When EVERY item resolves to a row carrying
//     its result, the original committed in full and its response can be
//     rebuilt now. replayBatchResponse rebuilds it through buildBatchTxResponse,
//     the SAME function that built the response finalization stores, over the
//     same per-item results and the same agent thumbprint — so ver, items,
//     total_cost and agent_identity_hash cannot differ from what a finalizer
//     would have written for this request.
//  3. The bounded wait. A winner still executing has not written its rows yet,
//     so no rows or a partial set is genuinely ambiguous and only waiting
//     resolves it.
//
// Probing the rows BEFORE waiting is what keeps a retry from spending the full
// bound on a finalizer that is never coming. When the original committed every
// item and then stopped before finalizing, its claim stays NULL forever; the
// rows that answer the retry were already there when the wait would have
// started, and without this order every retry pays ~3s and 61 reads to rediscover
// them.
//
// A KindIdempotent probe result — a partial row set, or a legacy row with no
// stored result — is deliberately NOT surfaced here. Both are ambiguous while a
// winner may still be running, so they fall through to the wait and the caller's
// own post-wait probe raises the safe refusal, exactly as before this ordering.
// Any other probe error (the ownership gate, an unreadable row) is final and
// surfaces immediately.
func (s *ExchangeService) serveLostClaim(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string, binding agentBinding,
) (*rampv1.TransactionResponse, bool, error) {
	if resp, ok, err := s.finalizedResponse(ctx, req, agentID, binding); err != nil || ok {
		return resp, ok, err
	}
	resp, ok, err := s.replayBatchResponse(ctx, req, binding)
	switch {
	case err == nil && ok:
		return resp, true, nil
	case err != nil && !isIdempotentReplay(err):
		return nil, false, err
	}
	return s.awaitFinalizedResponse(ctx, req, agentID, binding)
}

// finalizedResponse reads the finalized request-level response stored on this
// agent's claim, ONCE. ok=false with a nil error means the claim carries none
// yet — either the original has not finished, or it never will.
func (s *ExchangeService) finalizedResponse(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string, binding agentBinding,
) (*rampv1.TransactionResponse, bool, error) {
	payload, err := s.transactions.RequestResponse(ctx, agentID, req.GetIdempotencyKey())
	if err != nil {
		return nil, false, exchange.Wrap(exchange.KindInternal, err, "read finalized request response")
	}
	if len(payload) == 0 {
		return nil, false, nil
	}
	return s.serveFinalizedResponse(binding, payload)
}

// awaitFinalizedResponse polls for the finalized request-level response stored
// on this agent's claim and serves it when present. The first read is
// immediate; a concurrent loser then polls until the winner finalizes or the
// bound expires. ok=false with a nil error means the bound expired with no
// finalized response.
func (s *ExchangeService) awaitFinalizedResponse(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string, binding agentBinding,
) (*rampv1.TransactionResponse, bool, error) {
	for poll := 0; ; poll++ {
		resp, ok, err := s.finalizedResponse(ctx, req, agentID, binding)
		if err != nil || ok {
			return resp, ok, err
		}
		if poll >= finalizedWaitPolls {
			return nil, false, nil
		}
		select {
		case <-ctx.Done():
			return nil, false, nil
		case <-time.After(finalizedPollInterval):
		}
	}
}

// serveFinalizedResponse is the ownership-gated serve of a stored finalized
// response. The claim row is keyed by the agentID resolved from requester.id,
// which is caller-supplied — so possession of that identity's registered key was
// proven ONCE at admission and its request-level
// binding is passed in here, the same binding the per-item replay path uses. When
// the stored response carries an agent identity thumbprint (any successful item),
// it must match the proven binding; an all-denied response carries none (and no
// retrieval URLs either), so the proven possession alone gates it.
func (s *ExchangeService) serveFinalizedResponse(
	binding agentBinding, payload []byte,
) (*rampv1.TransactionResponse, bool, error) {
	// Decode target: the stored payload decides every field, Ver included — it
	// was stamped when the original response was built and marshaled.
	var resp rampv1.TransactionResponse
	if err := protobuf.Unmarshal(payload, &resp); err != nil {
		return nil, false, exchange.Wrap(exchange.KindInternal, err, "decode finalized request response")
	}
	if h := resp.GetAgentIdentityHash(); h != "" && h != binding.thumbprint {
		return nil, false, exchange.Newf(exchange.KindPermissionDenied,
			"idempotency_key belongs to a different agent")
	}
	return &resp, true, nil
}

// finalizeBatchResponse persists the finalized request-level response onto the
// claim, write-once, BEFORE the RPC returns — it is what an exact retry (and a
// concurrent-duplicate loser) replays verbatim, denials included. The
// durability invariant is strict: a successful RPC means either THIS call
// persisted the response, or a concurrent finalizer won and its STORED
// response was read back and is returned instead (never this call's local
// variant, whose transaction ids could differ from what later retries will be
// served). Any unresolved failure fails the RPC — for an all-denied request
// nothing was charged, and for a batch with committed items the retry
// recovers the successes through the per-item rows; the rare mixed-batch
// finalize failure surfaces as a logged Internal with the charge committed, a
// bounded loss accepted as the price of the invariant.
func (s *ExchangeService) finalizeBatchResponse(
	ctx context.Context, req *rampv1.TransactionRequest, agentID string, resp *rampv1.TransactionResponse,
) (*rampv1.TransactionResponse, error) {
	payload, err := protobuf.Marshal(resp)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "marshal finalized request response")
	}
	won, err := s.transactions.FinalizeRequest(ctx, agentID, req.GetIdempotencyKey(), payload)
	if err != nil || won {
		return selectFinalizedBatchResponse(resp, won, nil, err, nil)
	}
	stored, readErr := s.transactions.RequestResponse(ctx, agentID, req.GetIdempotencyKey())
	return selectFinalizedBatchResponse(resp, false, stored, nil, readErr)
}

func selectFinalizedBatchResponse(
	local *rampv1.TransactionResponse,
	won bool,
	stored []byte,
	finalizeErr, readErr error,
) (*rampv1.TransactionResponse, error) {
	if finalizeErr != nil {
		return nil, exchange.Wrap(exchange.KindInternal, finalizeErr, "finalize request response")
	}
	if won {
		return local, nil
	}
	if readErr != nil {
		return nil, exchange.Wrap(exchange.KindInternal, readErr, "read winning finalized response")
	}
	if len(stored) == 0 {
		return nil, exchange.Newf(exchange.KindInternal,
			"finalized response unavailable after lost finalization")
	}
	// Decode target: the stored payload decides every field, Ver included.
	var winner rampv1.TransactionResponse
	if err := protobuf.Unmarshal(stored, &winner); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "decode winning finalized response")
	}
	return &winner, nil
}
