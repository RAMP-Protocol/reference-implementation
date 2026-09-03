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
	"crypto/sha256"
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	protobuf "google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/transactionkey"
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
// serving it to any caller that merely presents the pair would leak that URL. The
// caller's possession of the bound agent key was already proven ONCE at admission
// (from the complete request proof, or the legacy item proof), and its binding is passed in here: the
// thumbprint/digest that binding carries must equal every persisted row's
// agent_identity_hash. requester.id alone is insufficient — it is caller-supplied.
// A mismatch is KindPermissionDenied, and the stored result is never returned.
// Reusing the admission binding (rather than re-deriving it from items[0]) is what
// keeps a valid-anywhere batch from failing its own exact retry.
func (s *ExchangeService) replayBatchResponse(
	ctx context.Context, req *rampv1.TransactionRequest, binding agentBinding,
) (*rampv1.TransactionResponse, bool, error) {
	items := make([]*rampv1.TransactionResultItem, 0, len(req.GetItems()))
	rowHashes := make([][]byte, 0, len(req.GetItems()))
	persisted := 0
	for _, item := range req.GetItems() {
		derivedKey := transactionkey.DerivedItemKey(req.GetIdempotencyKey(), item.GetOffer().GetOfferId())
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
	// Ownership gate — a replay is served only to the row's proven owner. The
	// admission binding (proof of possession of the bound agent key) must match
	// every persisted row's binding.
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

// admission is admitBatchRequest's verdict: resp+done carry a served replay
// (or a refusal via the error return); claimed reports whether this request
// holds the (agent, key) claim — executeBatch finalizes the response onto the
// claim ONLY when it does, so a request that never proved possession leaves no
// durable state behind. binding is the ONE request-level possession binding
// proven at admission (zero when possession was not proven): the ownership gate
// on the finalized-replay and legacy-replay paths reuses it, and the per-item
// loop reuses it for the concurrent-duplicate recovery, so possession is never
// recomputed from a single item at a later stage.
type admission struct {
	resp    *rampv1.TransactionResponse
	done    bool
	claimed bool
	binding agentBinding
}

// admitBatchRequest is the request-level admission gate, run before any item
// bills or persists, in a fixed order: prove requester possession → apply the
// broker-relay policy → claim or replay. The derived per-item keys alone
// cannot guard replay: offer_id is a random per-offer UUID, so a caller
// reusing one request key with a newly discovered offer produces derived keys
// that miss every persisted row.
//
// Possession first: the claim is keyed by the agentID resolved from the
// caller-supplied requester.id, so writing it without proof would let any
// transport caller durably reserve — and poison with a denial response — a
// victim's (key, item set). No possession ⇒ no claim, no replay serve, no
// finalization; the request still proceeds and every item is denied in-body
// by the per-item acceptance verification, exactly as before.
//
// Relay policy second: a broker-relayed request against a tenant that refuses
// relay must not mutate claim state or be served a stored response — see
// relayPolicyGate.
//
// Claim outcomes:
//   - WON: first use of this key by this agent. Rows from the pre-claim era
//     may still exist under the global derived keys, so the legacy per-item
//     probe still runs (it serves or refuses them, ownership-gated).
//     done=false with no response means: execute.
//   - LOST, different digest: refused before side effects — the key is bound
//     to the item set it was first used with.
//   - LOST, same digest: an exact retry, or the loser of a concurrent
//     duplicate. serveLostClaim answers it — the finalized response verbatim
//     (denials included), or a complete per-item reconstruction, or, when
//     neither is available yet, the same answer after the bounded wait. If the
//     wait also expires, fall back to the legacy per-item probe: full rows
//     reconstruct, partial rows refuse safely, zero rows execute fresh (the
//     derived-key UNIQUE constraint and hold dedup make re-execution safe).
//
// The claim is keyed per authenticated agent, so a different caller may use
// the same key value independently — with its own offers. Presenting another
// agent's exact (key, offer) pair still lands on that agent's globally-keyed
// rows in the legacy probe and is refused there (an intentional v1 limitation;
// see the ownership gate in replayBatchResponse).
func (s *ExchangeService) admitBatchRequest(
	ctx context.Context, req *rampv1.TransactionRequest, agent resolvedAgent,
) (admission, error) {
	if req.GetAgentRequestAcceptance() == nil {
		// Wire-compatible clients may omit the new complete-set proof. Keep their
		// per-item execution/recovery path, but never promote item-local authority
		// into request-level claim or finalized-response state.
		binding, ok := proveRequesterPossession(req, agent.key)
		if !ok {
			return admission{}, nil
		}
		if err := s.relayPolicyGate(ctx, req, agent); err != nil {
			return admission{}, err
		}
		// The legacy per-item probe still runs. Rows persisted under the global
		// derived keys are served or refused HERE, ownership-gated: a caller that
		// presents another agent's (idempotency_key, offer) pair is refused
		// PermissionDenied and never handed the stored signed URL. Returning
		// before this probe would drop that gate for every client that omits the
		// proof — which is every client until the SDKs emit it — and let a
		// foreign caller execute against a key it does not own.
		//
		// claimed stays false: no claim was taken, so nothing finalizes onto one.
		resp, replayed, err := s.replayBatchResponse(ctx, req, binding)
		if err != nil {
			return admission{}, err
		}
		return admission{resp: resp, done: replayed, binding: binding}, nil
	}
	binding, canonical, err := s.verifyRequestAcceptance(req, agent.key)
	if err != nil {
		return admission{}, err
	}
	if err := s.relayPolicyGate(ctx, req, agent); err != nil {
		return admission{}, err
	}
	digest := sha256.Sum256(canonical)
	won, stored, err := s.transactions.ClaimRequest(ctx, agent.id, req.GetIdempotencyKey(), digest[:])
	if err != nil {
		return admission{}, exchange.Wrap(exchange.KindInternal, err, "claim request idempotency key")
	}
	if !won && !bytes.Equal(stored, digest[:]) {
		return admission{}, exchange.Newf(exchange.KindIdempotent,
			"idempotency_key already used by this agent with a different item set")
	}
	if !won {
		if resp, ok, aerr := s.serveLostClaim(ctx, req, agent.id, binding); aerr != nil {
			return admission{}, aerr
		} else if ok {
			return admission{resp: resp, done: true, claimed: true, binding: binding}, nil
		}
	}
	resp, replayed, err := s.replayBatchResponse(ctx, req, binding)
	if err != nil {
		return admission{}, err
	}
	return admission{resp: resp, done: replayed, claimed: true, binding: binding}, nil
}

// proveRequesterPossession supplies only the legacy, no-request-proof execution
// path with an ownership binding for duplicate-row recovery. It never authorizes
// ClaimRequest or finalized-response state; only verifyRequestAcceptance can do
// that. Items with unverifiable acceptances still get their in-body denial.
func proveRequesterPossession(
	req *rampv1.TransactionRequest, key agentKey,
) (agentBinding, bool) {
	for _, item := range req.GetItems() {
		if binding, err := verifyAgentAcceptance(itemRequest(req, item), key); err == nil {
			return binding, true
		}
	}
	return agentBinding{}, false
}

// relayPolicyGate enforces the per-tenant broker-relay opt-in BEFORE any claim
// mutation or stored-response disclosure — the same authorizeTransportRelay
// rule the per-item pipeline applies, hoisted to admission so a policy-refused
// broker request can neither reserve a claim (poisoning the agent's key) nor
// be served a stored replay with its signed URLs. Agent-direct chains return
// immediately: the gate only exists for relayed transport.
//
// Every item must reach a tenant verdict; none is skipped. The verdict does NOT
// gate on expiry: on the replay path disclosure comes from the STORED response,
// whose signed URL carries its own later expiry and stays live after the offer's
// expiry passes, so an expired offer resolved via resolveRelayTenant (signature
// checked, expiry ignored) still binds to its tenant. An item that cannot be
// attributed to a tenant at all — invalid signature, or a canonical_url that
// matches no catalog entry — cannot be cleared, so the WHOLE request FAILS CLOSED
// (PermissionDenied), never skipped. Likewise, if any resolvable item's tenant
// refuses the relay, the whole request is refused (all-or-nothing admission), so a
// multi-tenant batch cannot partially execute past a refusing tenant.
func (s *ExchangeService) relayPolicyGate(
	ctx context.Context, req *rampv1.TransactionRequest, agent resolvedAgent,
) error {
	chain := classifyTransportChain(helpers.AllSignaturesFromContext(ctx))
	if !chain.hasBroker {
		return nil
	}
	// A broker may preserve the valid complete-set proof while replacing an
	// item-local acceptance. Refuse that whole relayed request before it can
	// claim/finalize a denial response; agent-direct requests keep per-item
	// signature failures as in-body denials. Every item here is checked against
	// the SAME key snapshot the complete-set proof was checked against.
	for _, item := range req.GetItems() {
		if _, err := verifyAgentAcceptance(itemRequest(req, item), agent.key); err != nil {
			return err
		}
	}
	for _, item := range req.GetItems() {
		tenantID, ok := s.resolveRelayTenant(item)
		if !ok {
			relayErr := exchange.Newf(exchange.KindPermissionDenied,
				"broker %q rejected: item offer does not resolve to a tenant for relay authorization",
				chain.brokerKey)
			s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ",
				Caller{KeyID: chain.brokerKey, Kind: CallerBroker}, nil, agent.id, "", relayErr)
			return relayErr
		}
		tenant, err := s.tenants.ByID(ctx, tenantID)
		if err != nil {
			return exchange.Wrap(exchange.KindInternal, err, "load tenant for relay authorization")
		}
		if relayErr := s.authorizeTransportRelay(ctx, chain, tenant); relayErr != nil {
			s.logOutcome(ctx, "execute_transaction", "REJECTED_AUTHZ",
				Caller{KeyID: chain.brokerKey, Kind: CallerBroker}, &tenant, agent.id, "", relayErr)
			return relayErr
		}
	}
	return nil
}

// resolveRelayTenant names the tenant that owns an item's offer for the relay
// verdict, WITHOUT gating on expiry. The offer signature is checked (VerifyOffer,
// signature-only), because an expired but authentic offer still carries a
// trustworthy signed canonical_url; then that canonical_url is looked up in the
// catalog snapshot. ok=false means the item cannot be attributed to a tenant — the
// signature is invalid, the offer carries no canonical_url, or the canonical_url
// matches no catalog entry — and the relay gate fails the whole request closed
// rather than skipping it. Skipping was unsafe on the replay path: the stored
// response can disclose a still-live signed URL for an item whose offer no longer
// resolves, so "unresolvable ⇒ skip" would route that disclosure around the
// tenant's relay opt-out.
func (s *ExchangeService) resolveRelayTenant(item *rampv1.TransactionItem) (string, bool) {
	offer := item.GetOffer()
	if err := helpers.VerifyOffer(offer, offer.GetSignature(), s.offerSigner.PublicKey()); err != nil {
		return "", false
	}
	canonicalURL := offer.GetIdentity().GetCanonicalUrl()
	if canonicalURL == "" {
		return "", false
	}
	entry, ok := s.catalog.Snapshot().byURI[canonicalURL]
	if !ok {
		return "", false
	}
	return entry.TenantID, true
}

// releaseDuplicateLossHold decides the hold's fate after losing the per-item
// UNIQUE insert to a concurrent identical request. Billing Authorize is
// idempotent on the hold key WHILE a hold is live, so if the winner had not
// yet settled when we authorized, our BillingID IS the winner's live hold —
// releasing it would strip the charge off a committed, delivered transaction
// before its Record lands. But if the winner had already settled, our
// authorize opened a FRESH hold the winner knows nothing about, and keeping it
// would strand the agent's funds until natural expiry. The winner's committed
// row records which hold it settled, so compare against it: equal ⇒ shared,
// keep; different ⇒ ours alone, release. On a read failure keep the hold —
// under-releasing is money-safe (a stranded hold expires on its own), while
// over-releasing un-charges a delivered transaction.
func (s *ExchangeService) releaseDuplicateLossHold(ctx context.Context, billingID, derivedKey string) {
	if hasNoReservation(billingID) {
		return
	}
	rec, err := s.transactions.ByIdempotencyKey(ctx, derivedKey)
	if err != nil || rec.BillingID == billingID {
		return
	}
	s.releaseHold(ctx, billingID, derivedKey, "duplicate persist loss, distinct hold")
}

// isIdempotentReplay reports whether err is the KindIdempotent domain error —
// past request admission, the only source is the transaction_log UNIQUE loss
// to a concurrent identical request (classifyTxWriteError).
func isIdempotentReplay(err error) bool {
	var de *exchange.Error
	return errors.As(err, &de) && de.Kind == exchange.KindIdempotent
}
