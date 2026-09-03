// Batch ExecuteTransaction adapter for the broker relay (batch fan-out). The wire
// half only: unmarshal + validation + the load-bearing admission ordering
// (ResolveGroups → VerifyAndGuardReplay → FanOut) + every write. The fan-out
// substance lives in the relay service layer (src/broker/internal/relay).

package transport

import (
	"net/http"
	"strconv"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
)

// serveBatch runs the batch fan-out pipeline. body is the bounded,
// already-read inbound batch body. Trust is a WHOLE-REQUEST admission gate
// (ResolveGroups): every distinct offer.exchange must resolve, be
// registry-trusted, and pass the SSRF check BEFORE any fan-out side effect —
// and BEFORE the sig1 verify + replay add, so a request rejected at admission
// never consumes its signature's replay slot.
func (h *ExchangeRelayHandler) serveBatch(w http.ResponseWriter, r *http.Request, body []byte) {
	ctx := r.Context()
	requestID := reqctx.RequestID(ctx)

	var txReq rampv1.TransactionRequest
	// DiscardUnknown so this hand-rolled route matches the tolerance every codec
	// path already gives: a caller still sending a field the protocol has since
	// removed (e.g. the reserved Requester.billing_ref) has it ignored, not 400'd.
	// The Connect codec sets DiscardUnknown by default; the bare Unmarshal here
	// did not, so this route alone rejected otherwise-forward-compatible bodies.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &txReq); err != nil {
		writeBrokerError(w, requestID, broker.Wrapf(broker.KindInvalidArgument, err,
			"parse TransactionRequest"))
		return
	}

	// items[] is REQUIRED (min 1). Execute is always-batch: with no
	// single-offer dispatch path, an empty/absent items[] would otherwise
	// resolve zero groups, fan out nothing, and return 200 with an empty
	// items[] — a silent regression vs the removed single path's 400. This is
	// the sole gate until the proto gains a repeated.min_items rule (the raw
	// relay route bypasses protovalidate's offer_xor_items CEL).
	if len(txReq.GetItems()) == 0 {
		writeBrokerError(w, requestID, broker.Newf(broker.KindInvalidArgument,
			"items[] required (min 1) to route an execute relay").WithField("items"))
		return
	}

	// Duplicate offer_ids within one request are an invalid envelope, rejected
	// here at ingress before signature admission, ResolveGroups, or any fan-out.
	// Without this scan the duplicates only fail inside their own exchange group
	// after decomposition, while a distinct item routed to another exchange
	// still executes — a malformed envelope with partial side effects. This is
	// fail-fast ingress validation only: the Exchange's own envelope validation
	// remains the authoritative enforcement of the duplicate rule. Like the
	// empty-items gate above it runs before the sig1 verify (it reveals nothing
	// but the body's own internal consistency, and a rejection here must not
	// spend the signature's replay slot).
	seen := make(map[string]int, len(txReq.GetItems()))
	for i, item := range txReq.GetItems() {
		id := item.GetOffer().GetOfferId()
		if j, dup := seen[id]; dup {
			writeBrokerError(w, requestID, broker.Newf(broker.KindInvalidArgument,
				"items %d and %d present duplicate offer_id %q; "+
					"executing the same resource twice takes two separately issued offers", j, i, id).
				WithField("items.offer.offer_id").WithMeta("item_index", strconv.Itoa(i)))
			return
		}
		seen[id] = i
	}

	// ONE whole-body sig1 verify + ONE replay add over the entire batch body
	// (endpoint "" — execute verifies as-received via BoundaryTargetURL).
	//
	// Ahead of the admission gate, so nothing about the registry is answered to a
	// caller that has not proved who it is. offer.exchange arrives in an unsigned
	// body, and the gate below answers it four different ways — never registered,
	// registered and failing its probe, registered but not approved to be paid, or
	// admitted. Answered first, that is a registry oracle anyone can query by
	// naming a domain and reading the code back.
	//
	// The cost is that a request refused for a RETRYABLE reason has now spent its
	// signature: the replay guard dedups on the signature value, so the retry the
	// 503 invites has to be re-signed. That is what a retry already does — the
	// signature covers its own created timestamp — and a byte-identical resend is
	// a replay by definition. The discover route made the same trade.
	if verr := h.core.VerifyAndGuardReplay(h, r, "", body); verr != nil {
		writeBrokerError(w, requestID, verr)
		return
	}

	// WHOLE-REQUEST admission gate: resolve + trust + SSRF EVERY distinct
	// offer.exchange BEFORE any fan-out. Any failure rejects the whole request.
	groups, berr := h.batch.ResolveGroups(ctx, h, &txReq)
	if berr != nil {
		writeBrokerError(w, requestID, berr)
		return
	}

	merged := h.batch.FanOut(ctx, h, &txReq, groups)
	h.core.Audit(ctx, h, "VALIDATED", "batch", nil)
	writeTxResponse(w, requestID, merged)
}
