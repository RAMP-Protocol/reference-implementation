//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestExecuteTransaction_ReplayRejectsForeignCaller pins the idempotency-replay
// caller-binding invariant: a stored replay result (including its signed
// retrieval_endpoint) is served ONLY to the same authenticated principal that
// owns the persisted transaction_log row. A DIFFERENT registered agent that
// presents the victim's (idempotency_key, offer_id) — even with its own
// perfectly valid self-signed request — must be refused with PermissionDenied
// and must receive NO retrieval_endpoint.
//
// Why this is the load-bearing check (and why a plain requester.id comparison is
// NOT enough): the exchange treats the BODY offer-acceptance signature — verified
// against the registered key of req.requester.id — as the authoritative agent
// identity, and binds the delivery URL to THAT key's RFC 7638 thumbprint,
// persisted as transaction_log.agent_identity_hash (agent_acceptance.go). The
// replay probe therefore may only return the stored URL to a caller who proves
// possession of the key whose thumbprint == the stored agent_identity_hash. The
// bug: replayBatchResponse runs BEFORE resolveAgentID + verifyAgentAcceptance
// (exchange_batch.go), so on a resent key the acceptance proof is never checked
// and the stored URL is handed to whoever presents the pair — a cross-principal
// signed-URL leak.
//
// Round-trip honesty:
//   - agent A WRITE leg: A → ExecuteTransaction RPC (real Connect HTTP) →
//     transport → service → repo → DB. Full PROTOCOL+PERSISTENCE round-trip.
//   - agent B REPLAY leg: B → the SAME ExecuteTransaction RPC surface, signed
//     with B's OWN transport + acceptance keys, reusing A's idempotency_key +
//     offer. Full PROTOCOL round-trip; asserts the rejection through the RPC.
//   - side-effect ABSENCE (A's row untouched, A not re-charged) is a PERSISTENCE
//     check via the production repo.TransactionRepo.ByIdempotencyKey (tier-2:
//     No public transaction-read RPC exists) plus
//     the billing adapter GetBalance. No raw sqlc / SQL (Testing Doctrine §9).
func TestExecuteTransaction_ReplayRejectsForeignCaller(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/replay-binding", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const idem = "tx-cross-caller-replay"

	// Agent A (the harness default caller "agent-test") executes the batch: the
	// original request succeeds and persists the transaction_log row bound to A's
	// registered-key thumbprint, with a signed retrieval endpoint.
	aRequester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	aReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      aRequester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, aRequester, idem)},
		},
	}
	aResp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(aReq))
	if err != nil {
		t.Fatalf("agent A original call must succeed: %v", err)
	}
	aItems := aResp.Msg.GetItems()
	if len(aItems) != 1 || aItems[0].GetRetrievalEndpoint() == "" {
		t.Fatalf("agent A call did not yield a signed retrieval endpoint: %+v", aItems)
	}
	balAfterA, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance(billing_ref) after A: %v", err)
	}

	// Agent B: a DIFFERENT registered agent with its OWN keypair. B legitimately
	// discovers the same offer and self-signs a well-formed acceptance under its
	// OWN identity, but reuses A's idempotency_key (a client-chosen dedup token B
	// could learn off-band — it is not a bearer secret). B's request is otherwise
	// valid; only the (idempotency_key, offer_id) pair collides with A's row.
	clientB, _, bPriv := h.addCallerWithKey(t, "agent-b", "AGENT")
	bRequester := &rampv1.Requester{
		Id: "agent-b", Domain: "agent-b.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	bReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      bRequester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, bPriv, offer, bRequester, idem)},
		},
	}
	bResp, bErr := clientB.ExecuteTransaction(ctx, connect.NewRequest(bReq))

	// INVARIANT: B must be refused — the stored result belongs to A. A replay is
	// served only to the row's owner; a foreign caller gets PermissionDenied and
	// NO signed URL. (Pre-fix, B receives A's retrieval_endpoint verbatim — the leak.)
	if bErr == nil {
		leaked := ""
		if items := bResp.Msg.GetItems(); len(items) == 1 {
			leaked = items[0].GetRetrievalEndpoint()
		}
		t.Fatalf("SECURITY: foreign caller B replayed A's key and received a response "+
			"(leaked retrieval_endpoint=%q); want PermissionDenied", leaked)
	}
	if got := connect.CodeOf(bErr); got != connect.CodePermissionDenied {
		t.Fatalf("foreign-caller replay error code = %v, want PermissionDenied (err: %v)", got, bErr)
	}

	// Side effects: A's row is untouched and A was charged exactly once. B's
	// rejected replay neither re-served nor re-billed A's transaction.
	derivedKey := idem + ":" + offer.GetOfferId()
	repoTx := repo.NewTransactionRepo(h.queries)
	if _, rerr := repoTx.ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("A's persisted row must survive B's rejected replay: %v", rerr)
	}
	balAfterB, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance(billing_ref) after B: %v", err)
	}
	if balAfterB.Value.Cmp(balAfterA.Value) != 0 {
		t.Fatalf("agent-test balance moved on B's rejected replay: %s -> %s",
			balAfterA.Value.FloatString(4), balAfterB.Value.FloatString(4))
	}
}

// TestExecuteTransaction_ReplaySpoofedRequesterIDRejected pins the sharper half of
// the ownership gate: it is NOT enough to compare the caller-supplied
// requester.id (or a thumbprint derived from it) to the stored row — requester.id
// is unauthenticated caller input. A foreign caller that SPOOFS the victim's
// requester.id still cannot forge the victim's body offer-acceptance signature
// (proof of possession of the victim's registered key), so the replay must be
// refused with NO signed URL. This guards against a future "simplification" of the
// ownership check into a bare requester.id / claimed-thumbprint compare (which
// would pass TestExecuteTransaction_ReplayRejectsForeignCaller but reopen the leak).
//
// Round-trip honesty: identical shape to the sibling test — A writes via the RPC,
// B replays via the SAME RPC signing its transport with B's key but claiming
// requester.id="agent-test"; asserted through the RPC surface + repo/billing for
// side-effect absence (Testing Doctrine §9).
func TestExecuteTransaction_ReplaySpoofedRequesterIDRejected(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/replay-spoof", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const idem = "tx-spoofed-requester-replay"

	// Agent A executes and persists the row (bound to A's identity).
	aRequester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	aReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      aRequester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, aRequester, idem)},
		},
	}
	if _, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(aReq)); err != nil {
		t.Fatalf("agent A original call must succeed: %v", err)
	}
	balAfterA, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance(billing_ref) after A: %v", err)
	}

	// Agent B signs transport with B's own key but SPOOFS requester.id="agent-test".
	// B cannot produce a valid acceptance for agent-test (it lacks A's private key),
	// so it signs the acceptance with its OWN key — which will not verify against
	// agent-test's registered key.
	clientB, _, bPriv := h.addCallerWithKey(t, "agent-b-spoof", "AGENT")
	spoofReq := &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: idem,
		Requester:      aRequester, // spoofed: claims to be agent-test
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, bPriv, offer, aRequester, idem)},
		},
	}
	spoofResp, spoofErr := clientB.ExecuteTransaction(ctx, connect.NewRequest(spoofReq))

	// INVARIANT: refused with NO signed URL. The refusal is a client-attributable
	// denial — Unauthenticated (acceptance does not verify against the claimed
	// identity's key) or PermissionDenied (thumbprint mismatch), depending on check
	// order; either is correct. What must NEVER happen is a 200 carrying A's URL.
	if spoofErr == nil {
		leaked := ""
		if items := spoofResp.Msg.GetItems(); len(items) == 1 {
			leaked = items[0].GetRetrievalEndpoint()
		}
		t.Fatalf("SECURITY: spoofed-requester.id replay was served (leaked retrieval_endpoint=%q); "+
			"want a denial with no URL", leaked)
	}
	if code := connect.CodeOf(spoofErr); code != connect.CodeUnauthenticated && code != connect.CodePermissionDenied {
		t.Fatalf("spoofed-requester.id replay error code = %v, want Unauthenticated or PermissionDenied (err: %v)",
			code, spoofErr)
	}

	// Side effects: A's row survives, A not re-charged.
	derivedKey := idem + ":" + offer.GetOfferId()
	repoTx := repo.NewTransactionRepo(h.queries)
	if _, rerr := repoTx.ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("A's persisted row must survive the spoofed replay: %v", rerr)
	}
	balAfterSpoof, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance(billing_ref) after spoof: %v", err)
	}
	if balAfterSpoof.Value.Cmp(balAfterA.Value) != 0 {
		t.Fatalf("agent-test balance moved on spoofed replay: %s -> %s",
			balAfterA.Value.FloatString(4), balAfterSpoof.Value.FloatString(4))
	}
}
