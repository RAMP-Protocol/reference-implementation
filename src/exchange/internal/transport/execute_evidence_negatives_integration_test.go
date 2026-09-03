//go:build integration

package transport_test

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Negative paths for transaction_evidence, driven through the ExecuteTransaction
// Connect-Go RPC and asserted through the production repo surface.
//
// The evidence row exists to prove BOTH parties assented. The offer half already
// has a negative path (a tampered offer field is denied SIGNATURE_INVALID) and so
// does an acceptance signed by an unregistered key. The case with no coverage at
// all was the envelope guard that refuses an item carrying NO acceptance
// signature — the one rejection that keeps an unsigned agreement from ever
// reaching persistence.
//
// Round-trip honesty: these are PERSISTENCE round-trips. The write leg drives the
// full transport→service→repo→DB stack through the public RPC; the absence leg
// reads back through repo.EvidenceRepo, the documented Testing-Doctrine §9 tier-2
// fallback. The evidence read that now exists is the operator plane's
// cross-tenant JSON endpoint on the internal listener, which is not the public
// read surface the doctrine means — and it could not carry these assertions in
// any case, because the cross-tenant probe below is exactly the tenant predicate
// that endpoint does not apply.
//
// Where "absence" is actually asserted, and where it cannot be. A DENIED item
// mints no transaction_id, so there is no evidence primary key to probe for it —
// what proves nothing was written is the transaction_log row's absence, because
// evidence is FK-bound to that row and committed in the same db.WithTx. That
// binding is not left to prose: the migration suite asserts the foreign key and
// the primary key directly. The read that CAN fail on a real key, and therefore
// the one that gives repo.ErrEvidenceNotFound an assertion path, is the
// cross-tenant probe below: a real, existing transaction_id read under a
// different tenant.

// assertNoEvidence asserts no evidence row exists for txID under tenantID.
//
// It refuses an empty txID rather than probing with it. transaction_id is a
// server-minted UUID primary key, so a query for "" matches nothing whatever the
// production code does — an absence assertion built on one passes for every
// build, correct or broken, and reads as coverage while providing none.
func assertNoEvidence(t *testing.T, h *testHarness, tenantID, txID string) {
	t.Helper()
	if txID == "" {
		t.Fatal("assertNoEvidence needs a real transaction_id; probing the empty string asserts nothing")
	}
	_, err := repo.NewEvidenceRepo(h.queries).ByTransaction(h.ctx, tenantID, txID)
	if !errors.Is(err, repo.ErrEvidenceNotFound) {
		t.Errorf("EvidenceRepo.ByTransaction(%q, %q) error = %v, want ErrEvidenceNotFound",
			tenantID, txID, err)
	}
}

// TestExecuteTransaction_EvidenceIsNotReadableFromAnotherTenant drives the tenant
// predicate on the evidence read.
//
// transaction_id is globally unique, so the predicate is not needed to find the
// right row — it is there to make Architecture Rule 4 structural rather than a
// checked-by-convention property of every future call site, on the most sensitive
// row in the schema: the full offer, both signatures, both verifying public keys,
// and a live signed URL. Every other test in this suite reads under the tenant
// that wrote the row, so without this one the predicate could be deleted and the
// branch would stay green.
func TestExecuteTransaction_EvidenceIsNotReadableFromAnotherTenant(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-tenant-scope", "0.05")
	offer := discoverOffer(t, h, uri)

	resp, err := executeSingleItem(t, h, "tx-ev-tenant-scope", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	txID := singleResultItem(t, resp).GetTransactionId()
	if txID == "" {
		t.Fatal("transaction id empty")
	}
	// The row exists and is readable under the tenant that wrote it — so the
	// refusal below is the predicate discriminating, not the row being missing.
	if rec := evidenceFor(t, h, txID); rec.TransactionID != txID {
		t.Fatalf("evidence transaction_id = %q, want %q", rec.TransactionID, txID)
	}

	otherTenantID, _ := h.addTenant(t, "evidence-scope", "agent-evidence-scope")
	assertNoEvidence(t, h, otherTenantID, txID)
}

// TestExecuteTransaction_MissingAgentAcceptanceIsRejected drives the two shapes a
// caller can present an absent acceptance in. Both are refused as a malformed
// envelope — the whole batch aborts with InvalidArgument, no item executes,
// nothing is persisted — but by DIFFERENT layers, and the test pins which:
//
//   - acceptance message omitted → the service's own envelope guard. The proto's
//     min-length rule on the signature field cannot fire, because its parent
//     message is absent. This shape is the only way to reach that guard, which is
//     why it had no coverage.
//   - acceptance present, signature empty → the protovalidate interceptor, before
//     the service sees the request at all.
//
// Together they are the rejection that makes the evidence row's agent half
// meaningful. If either regressed to a per-item denial, or to acceptance, an
// execute could commit with no proof the agent agreed to anything.
func TestExecuteTransaction_MissingAgentAcceptanceIsRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-no-acceptance", "0.05")

	cases := []struct {
		name       string
		reqKey     string
		acceptance *rampv1.AgentAcceptance
		wantInMsg  string
	}{
		{"acceptance omitted", "tx-ev-no-acceptance", nil, "agent_acceptance signature required"},
		{
			"acceptance present but unsigned", "tx-ev-empty-acceptance",
			&rampv1.AgentAcceptance{}, "agent_acceptance.signature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offer := discoverOffer(t, h, uri)
			_, err := executeItems(t, h, tc.reqKey,
				&rampv1.TransactionItem{Offer: offer, AgentAcceptance: tc.acceptance})
			assertConnectError(t, err, connect.CodeInvalidArgument, tc.wantInMsg)
			// No transaction row means no evidence row: the evidence FK targets
			// transaction_log and both writes share one db.WithTx.
			assertNoTransaction(t, h, derivedTxKey(tc.reqKey, offer))
		})
	}
}

// TestExecuteTransaction_UnregisteredKeyAcceptanceLeavesNoEvidence covers the
// other half of the acceptance criterion: an acceptance that is structurally
// valid and correctly signed, but by a key the agent registry does not hold. It
// must be denied SIGNATURE_INVALID and leave nothing behind.
//
// The denial itself is pinned elsewhere; what this adds is the persistence-side
// assertion. A denied item mints no transaction_id, so there is no evidence key
// to probe — absence is established structurally instead: no transaction_log row
// means no evidence row, because evidence carries a foreign key into that table
// and both writes share one db.WithTx.
func TestExecuteTransaction_UnregisteredKeyAcceptanceLeavesNoEvidence(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-wrong-key", "0.05")
	offer := discoverOffer(t, h, uri)

	const reqKey = "tx-ev-wrong-key"
	requester := agentRequester("agent-test")
	resp, err := executeItems(t, h, reqKey, &rampv1.TransactionItem{
		Offer:           offer,
		AgentAcceptance: mintWrongKeyAcceptanceFor(t, offer, requester, reqKey),
	})
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(reqKey, offer))

	// A denied item carries no transaction_id, and the response must not invent
	// one: an id here would mean the execute got far enough to mint it.
	if got := singleResultItem(t, resp).GetTransactionId(); got != "" {
		t.Errorf("denied item carries transaction_id %q, want none", got)
	}
}

// TestExecuteTransaction_FreePathPersistsEvidence covers the one execute path
// where intent-building branches and the evidence suite otherwise never goes.
//
// A price-zero resource bypasses the billing adapter entirely — no Authorize, no
// Record — so auth.BillingID is empty and the obligation drops its billing_id
// requirement. That is the shape most likely to leave a NOT NULL evidence column
// unfilled, and a free transaction is still a fully executed transaction whose
// agreement has to be provable.
func TestExecuteTransaction_FreePathPersistsEvidence(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-free", "0")
	offer := discoverOffer(t, h, uri)

	resp, err := executeSingleItem(t, h, "tx-ev-free", offer)
	if err != nil {
		t.Fatalf("execute free item: %v", err)
	}
	rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())

	if rec.OfferID != offer.GetOfferId() {
		t.Errorf("offer_id = %q, want %q", rec.OfferID, offer.GetOfferId())
	}
	if rec.SignedURLFull == "" {
		t.Error("signed_url_full empty on the free path")
	}
	if len(rec.AgentPublicKey) == 0 || len(rec.ExchangeSigningPublicKey) == 0 {
		t.Error("a verifying public key is missing; the row cannot re-verify standalone")
	}
	// Both proofs must hold identically to the paid path — nothing about a zero
	// price changes what was agreed or who agreed to it.
	assertOfferLegVerifies(t, rec)
	assertAcceptanceLegVerifies(t, rec)
}
