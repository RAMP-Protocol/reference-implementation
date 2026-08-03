//go:build integration

package transport_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// transaction_evidence persistence. A successful ExecuteTransaction captures the
// full signed offer + both parties' signatures + both verifying public keys into
// an append-once evidence row, so a third party can re-verify BOTH sides from the
// stored row alone — with no live service, agent registry, or Exchange key file.
//
// Round-trip honesty: this is a PERSISTENCE round-trip, not a protocol one. The
// write drives the full transport→service→repo→DB stack through the public
// Connect-Go RPCs (CatalogService.PushResources → ExchangeService.
// DiscoverResources → ExchangeService.ExecuteTransaction); the read-back stops
// at the production repository surface (repo.EvidenceRepo) — the documented
// Testing-Doctrine §9 tier-2 fallback, since no evidence-read RPC exists. Whether
// one should exist, and on which surface, is an open decision filed and linked
// from this ticket. No raw sqlc / SQL / second DB connection. The signature
// re-verification below runs entirely on the stored columns, which is exactly the
// "no external state" guarantee the row exists to provide.

// evidenceFor reads back one tenant's evidence row through the tenant-scoped
// production surface — the shape every non-admin caller uses.
func evidenceFor(t *testing.T, h *testHarness, txID string) repo.EvidenceRecord {
	t.Helper()
	rec, err := repo.NewEvidenceRepo(h.queries).ByTransaction(h.ctx, h.tenantID, txID)
	if err != nil {
		t.Fatalf("EvidenceRepo.ByTransaction(%q, %q): %v", h.tenantID, txID, err)
	}
	return rec
}

// TestExecuteTransaction_PersistsReVerifiableEvidence drives one successful
// execute and proves the evidence row re-verifies both signatures from its own
// columns.
func TestExecuteTransaction_PersistsReVerifiableEvidence(t *testing.T) {
	h := newTestHarness(t)

	uri := seedResourceWithRate(t, h, "/articles/evidence", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const reqKey = "tx-evidence"
	resp, err := executeSingleItem(t, h, reqKey, offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	txID := singleResultItem(t, resp).GetTransactionId()
	if txID == "" {
		t.Fatal("transaction id empty")
	}
	rec := evidenceFor(t, h, txID)

	// offer_id is the signed Offer.offer_id. It equals the catalog resource_id
	// (the Exchange mints and resolves offers on that key), so it duplicates
	// transaction_log.offer_id — carried here so the row reads standalone.
	if rec.OfferID != offer.GetOfferId() {
		t.Errorf("offer_id = %q, want the signed offer id %q", rec.OfferID, offer.GetOfferId())
	}
	// The acceptance signs the REQUEST-level key, not the derived per-item key.
	if rec.RequestIdempotencyKey != reqKey {
		t.Errorf("request_idempotency_key = %q, want the request-level key %q", rec.RequestIdempotencyKey, reqKey)
	}
	if rec.RequesterDomain == "" {
		t.Error("requester_domain empty; it is an AgentAcceptancePayload input and must be persisted")
	}
	// The full delivered URL is persisted, not just its hash.
	if got := itemSignedURL(t, resp); rec.SignedURLFull != got {
		t.Errorf("signed_url_full = %q, want the delivered URL %q", rec.SignedURLFull, got)
	}
	// The key's provenance rides with it: the registry overwrites a rotated key
	// in place, so after a rotation nothing else records where this one came
	// from. Compare against the registry's own current value, read through the
	// production agent surface.
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, rec.RequesterID)
	if err != nil {
		t.Fatalf("AgentRepo.ByID(%q): %v", rec.RequesterID, err)
	}
	if agent.DiscoveryURL == "" {
		t.Fatal("fixture agent has no discovery url; the provenance assertion would be vacuous")
	}
	if rec.AgentDiscoveryURL != agent.DiscoveryURL {
		t.Errorf("agent_discovery_url = %q, want the registry's %q", rec.AgentDiscoveryURL, agent.DiscoveryURL)
	}

	assertOfferLegVerifies(t, rec)
	assertAcceptanceLegVerifies(t, rec)
}

// signatureLeg names one of the two proofs an evidence row carries. Both legs
// have the identical shape — a server-derived algorithm label, a hex signature, a
// stored verifying key, and the verbatim bytes that signature covered — so one
// body checks both, and each caller keeps only the cross-check specific to it.
// Two copies of this sequence would let a fix applied to one leg leave the other
// checking the old shape, in the suite that is the sole guard on a table whose
// rows can never be corrected.
type signatureLeg struct {
	// name is the column prefix a failure message should name.
	name    string
	alg     string
	wantAlg string
	sigHex  string
	key     []byte
	signed  []byte
}

// assertLegVerifies runs a bare ed25519.Verify over stored columns only — no SDK
// helper, no canonicalisation, no proto. That is the property both canonical-bytes
// columns exist for: a verifier years from now needs the row and a signature
// library, nothing else, even if the canonical form has moved on again.
//
// The algorithm label is checked against the server's own constant rather than
// the presented one. Canonicalisation clears that field before signing, so a
// caller can present any label under an otherwise valid signature, and the
// constant is the only true statement about what was checked.
func assertLegVerifies(t *testing.T, leg signatureLeg) {
	t.Helper()
	if leg.alg != leg.wantAlg {
		t.Errorf("%s_signature_algorithm = %q, want %q", leg.name, leg.alg, leg.wantAlg)
	}
	sig, err := hex.DecodeString(leg.sigHex)
	if err != nil {
		t.Fatalf("decode %s_signature hex: %v", leg.name, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(leg.key), leg.signed, sig) {
		t.Errorf("%s signature does not re-verify against the stored key + canonical bytes", leg.name)
	}
}

// storedOffer recovers the offer from the offer_json column. Both legs cross-check
// against it: the offer leg re-canonicalises it to the signed bytes, and the
// acceptance leg rebuilds its payload from it.
func storedOffer(t *testing.T, rec repo.EvidenceRecord) *rampv1.Offer {
	t.Helper()
	var offer rampv1.Offer
	if err := protojson.Unmarshal(rec.OfferJSON, &offer); err != nil {
		t.Fatalf("unmarshal offer_json: %v", err)
	}
	return &offer
}

// assertOfferLegVerifies proves the Exchange signed THIS exact offer, using only
// stored columns: the stored key, the verbatim canonical bytes, and the hex
// signature. It also binds offer_json to that same signature — without the
// canonical-bytes comparison, offer_json (the column a dispute actually reads)
// would be constrained by nothing at all.
func assertOfferLegVerifies(t *testing.T, rec repo.EvidenceRecord) {
	t.Helper()
	assertLegVerifies(t, signatureLeg{
		name: "offer", alg: rec.OfferSignatureAlgorithm, wantAlg: helpers.OfferSignatureAlgorithm,
		sigHex: rec.OfferSignature, key: rec.ExchangeSigningPublicKey, signed: rec.OfferCanonicalBytes,
	})
	offer := storedOffer(t, rec)
	// offer_json must carry the Exchange's algorithm label POSITIVELY, not merely
	// lack a forged one. The canonical-bytes comparison below cannot cover this:
	// canonicalisation CLEARS signature_algorithm, so the field is outside that
	// check by construction. Without this line, writing an empty label into the
	// column a dispute reads passes the entire suite.
	if got := offer.GetSignatureAlgorithm(); got != helpers.OfferSignatureAlgorithm {
		t.Errorf("offer_json signature_algorithm = %q, want the Exchange constant %q",
			got, helpers.OfferSignatureAlgorithm)
	}
	reCanon, err := helpers.CanonicalOfferBytes(offer)
	if err != nil {
		t.Fatalf("re-canonicalize offer_json: %v", err)
	}
	if !bytes.Equal(reCanon, rec.OfferCanonicalBytes) {
		t.Error("offer_json does not canonicalize to the signed bytes; the two columns describe different offers")
	}
}

// assertAcceptanceLegVerifies proves the agent accepted THIS exact offer.
//
// Beyond the bare verify, it rebuilds the signed bytes from the stored payload
// inputs and the offer recovered from offer_json, proving the stored bytes are the
// ones the recorded inputs produce rather than an opaque blob taken on trust.
func assertAcceptanceLegVerifies(t *testing.T, rec repo.EvidenceRecord) {
	t.Helper()
	assertLegVerifies(t, signatureLeg{
		name: "agent_acceptance", alg: rec.AgentAcceptanceSignatureAlgorithm,
		wantAlg: helpers.AcceptanceSignatureAlgorithm, sigHex: rec.AgentAcceptanceSignature,
		key: rec.AgentPublicKey, signed: rec.AgentAcceptanceCanonicalBytes,
	})
	requester := &rampv1.Requester{
		Id: rec.RequesterID, Domain: rec.RequesterDomain,
		Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	reCanon, err := helpers.CanonicalAcceptanceBytes(storedOffer(t, rec), requester, rec.RequestIdempotencyKey)
	if err != nil {
		t.Fatalf("rebuild acceptance bytes from stored inputs: %v", err)
	}
	if !bytes.Equal(reCanon, rec.AgentAcceptanceCanonicalBytes) {
		t.Error("stored acceptance bytes are not what the stored payload inputs produce")
	}
}

// TestExecuteTransaction_EvidenceAlgorithmLabelsAreServerDerived pins the one
// property that separates a verified fact from a caller's claim. Neither
// signature covers its own signature_algorithm field — the canonical payloads
// clear it before signing — so a caller can present any label and still pass
// verification. The persisted labels must be the Exchange's own constants, in
// every column including offer_json, because the row can never be corrected.
func TestExecuteTransaction_EvidenceAlgorithmLabelsAreServerDerived(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-alg", "0.05")
	offer := discoverOfferForURI(t, h, uri)
	offer.SignatureAlgorithm = "RS256-FORGED"

	requester := agentRequester("agent-test")
	const reqKey = "tx-ev-alg"
	acceptance := signAcceptanceFor(t, h.callerPriv, offer, requester, reqKey)
	acceptance.SignatureAlgorithm = "" // an empty label still satisfies NOT NULL

	resp, err := executeItems(t, h, reqKey, &rampv1.TransactionItem{Offer: offer, AgentAcceptance: acceptance})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())

	if rec.OfferSignatureAlgorithm != helpers.OfferSignatureAlgorithm {
		t.Errorf("offer_signature_algorithm = %q, want the Exchange constant %q",
			rec.OfferSignatureAlgorithm, helpers.OfferSignatureAlgorithm)
	}
	if rec.AgentAcceptanceSignatureAlgorithm != helpers.AcceptanceSignatureAlgorithm {
		t.Errorf("agent_acceptance_signature_algorithm = %q, want the Exchange constant %q",
			rec.AgentAcceptanceSignatureAlgorithm, helpers.AcceptanceSignatureAlgorithm)
	}
	// The row still has to re-verify, and offer_json must carry the Exchange's own
	// label rather than the forged one — assertOfferLegVerifies asserts that
	// positively, which subsumes checking the forged string is merely absent.
	// Normalizing the label must not disturb the bytes the signature covered.
	assertOfferLegVerifies(t, rec)
}

// TestExecuteTransaction_EvidenceEncodesAbsentDirectoryAsEmpty pins the one
// encoding the two agent-bearing tables deliberately disagree on:
// ramp.agents.discovery_url is NULLable, while transaction_evidence
// .agent_discovery_url is NOT NULL and states absence as the empty string. An
// append-once row asserts a value for every column, so "this Exchange recorded no
// directory for this key" has to be a fact it states rather than a gap it leaves.
//
// The fixture has to be arranged deliberately: every harness-seeded agent carries
// a directory URL — which is what keeps the positive provenance assertion above
// from being vacuous, and leaves this branch with no fixture otherwise.
func TestExecuteTransaction_EvidenceEncodesAbsentDirectoryAsEmpty(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-no-directory", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	// Clear the caller's directory anchor, keeping its key so the identity↔key
	// binding still holds and the execute still succeeds. The repository maps ""
	// to SQL NULL, which is the state production reaches for an agent registered
	// without a directory.
	agents := repo.NewAgentRepo(h.queries)
	seeded, err := agents.ByID(h.ctx, "agent-test")
	if err != nil {
		t.Fatalf("AgentRepo.ByID: %v", err)
	}
	if seeded.DiscoveryURL == "" {
		t.Fatal("fixture agent already has no directory; this test would not distinguish anything")
	}
	seeded.DiscoveryURL = ""
	if _, err := agents.Upsert(h.ctx, seeded); err != nil {
		t.Fatalf("clear the caller's directory anchor: %v", err)
	}

	resp, err := executeSingleItem(t, h, "tx-ev-no-directory", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())
	if rec.AgentDiscoveryURL != "" {
		t.Errorf("agent_discovery_url = %q, want the empty string for an agent with no directory anchor",
			rec.AgentDiscoveryURL)
	}
	// The row must still re-verify: dropping the provenance does not change what
	// was agreed or which key proves it.
	assertAcceptanceLegVerifies(t, rec)
}

// derefOr renders a nullable column for a failure message. Formatting a *string
// with %v prints its ADDRESS, which is noise exactly when the message matters.
func derefOr(s *string, whenNil string) string {
	if s == nil {
		return whenNil
	}
	return *s
}

// requestIDProvenance renders the nullable request_id_minted flag as the word a
// failure message should show, so an assertion never prints a bare pointer.
func requestIDProvenance(minted *bool) string {
	switch {
	case minted == nil:
		return "<null>"
	case *minted:
		return "minted"
	default:
		return "caller-supplied"
	}
}

// TestExecuteTransaction_EvidenceCorrelatesWithTheCallerVisibleRequestID pins
// transport→service→repo→column for request_id in both directions the id can
// arrive: supplied by the caller, and minted by the Exchange.
//
// Each direction also asserts the recorded provenance. That is the whole reason
// the flag exists: a minted UUID is entirely inside the charset a caller-supplied
// id must satisfy, so the two are byte-indistinguishable in request_id alone —
// and only one of them is a server-derived fact. Asserting the id without the
// provenance would pass identically whichever value the column carried.
func TestExecuteTransaction_EvidenceCorrelatesWithTheCallerVisibleRequestID(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/evidence-reqid", "0.05")

	t.Run("caller-supplied id is the one persisted", func(t *testing.T) {
		offer := discoverOfferForURI(t, h, uri)
		const wantID = "caller-supplied-req-id"
		resp, err := executeSingleItemWithRequestID(t, h, "tx-ev-reqid-given", offer, wantID)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())
		if rec.RequestID == nil || *rec.RequestID != wantID {
			t.Errorf("request_id = %s, want the caller's %q", derefOr(rec.RequestID, "<null>"), wantID)
		}
		if got := requestIDProvenance(rec.RequestIDMinted); got != "caller-supplied" {
			t.Errorf("request_id_minted says %s, want caller-supplied — the id came off the request header", got)
		}
	})

	// The charset gate is unit-tested at the middleware; this leg proves the
	// rejection survives the whole stack down to the column. request_id is the only
	// caller-asserted value in an append-once row and the key evidence is
	// correlated on outward, so a hostile value reaching it could never be scrubbed.
	//
	// The value is over-length rather than control-character laden: Go's HTTP
	// client refuses to transmit a header carrying CR or LF, so those shapes cannot
	// reach a server over the wire at all and are covered at the middleware instead.
	// Length is the hostile property that does travel.
	t.Run("a hostile header never reaches the column", func(t *testing.T) {
		offer := discoverOfferForURI(t, h, uri)
		hostile := strings.Repeat("A", 200) + " <script> ../../etc/passwd"
		resp, err := executeSingleItemWithRequestID(t, h, "tx-ev-reqid-hostile", offer, hostile)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())
		if rec.RequestID == nil {
			t.Fatal("request_id is NULL; the hostile value was dropped but nothing replaced it")
		}
		if *rec.RequestID == hostile {
			t.Fatalf("hostile X-Request-ID %q was persisted verbatim", hostile)
		}
		if got := requestIDProvenance(rec.RequestIDMinted); got != "minted" {
			t.Errorf("request_id_minted says %s, want minted — the caller's value was rejected", got)
		}
	})

	t.Run("minted id matches the one returned to the caller", func(t *testing.T) {
		offer := discoverOfferForURI(t, h, uri)
		const reqKey = "tx-ev-reqid-minted"
		resp, err := executeSingleItem(t, h, reqKey, offer)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		// Two request-id layers wrap this handler: the outer middleware and the
		// SDK's own inside it. If the outer one does not propagate its minted id
		// onto the request, the inner mints a second value and returns THAT to
		// the caller — leaving the persisted correlation id one no client ever saw.
		returned := resp.Header().Get("X-Request-ID")
		if returned == "" {
			t.Fatal("response carries no X-Request-ID")
		}
		rec := evidenceFor(t, h, singleResultItem(t, resp).GetTransactionId())
		if rec.RequestID == nil || *rec.RequestID != returned {
			t.Errorf("request_id = %s, want the id returned to the caller %q", derefOr(rec.RequestID, "<null>"), returned)
		}
		if got := requestIDProvenance(rec.RequestIDMinted); got != "minted" {
			t.Errorf("request_id_minted says %s, want minted — no caller header was sent", got)
		}
	})
}

// TestExecuteTransaction_PartiallyDeniedBatchEvidence covers what a single-item
// test cannot: a denied item leaves no evidence behind while its sibling commits,
// and the committed row carries its own offer id and signature.
//
// It does NOT prove per-item attribution — that each row records ITS OWN item
// rather than the batch's first — and no arrangement through this surface can.
// executeBatchItem re-projects every item onto its own one-item synthetic
// request, so `items[0]` and "this item" name the same message at every index;
// a hypothetical "always record items[0]" bug is unobservable from outside.
// Reordering the batch does not help. The property is defended in code by
// persistInput carrying the item explicitly, and that is where it has to be
// reviewed. Claiming coverage here would be claiming an assertion the
// arrangement cannot make.
//
// Evidence is written only inside the same db.WithTx as the transaction_log row
// and is FK-bound to it, so the absence of the transaction row is the absence of
// the evidence row; a denied item mints no transaction_id, so there is no
// evidence PK to probe directly.
func TestExecuteTransaction_PartiallyDeniedBatchEvidence(t *testing.T) {
	h := newTestHarness(t)
	uriA := seedResourceWithRate(t, h, "/articles/evidence-batch-a", "0.05")
	uriB := seedResourceWithRate(t, h, "/articles/evidence-batch-b", "0.07")
	offerA := discoverOfferForURI(t, h, uriA)
	genuineB := discoverOfferForURI(t, h, uriB)

	// Mutate a signature-covered field on B after signing: B is denied
	// SIGNATURE_INVALID while A commits normally.
	tamperedB, ok := proto.Clone(genuineB).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	tamperedB.OfferId = genuineB.GetOfferId() + "-tampered"

	requester := agentRequester("agent-test")
	const reqKey = "tx-ev-partial"
	resp, err := executeItems(t, h, reqKey,
		&rampv1.TransactionItem{Offer: offerA, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerA, requester, reqKey)},
		&rampv1.TransactionItem{Offer: tamperedB, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, tamperedB, requester, reqKey)},
	)
	if err != nil {
		t.Fatalf("execute batch: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("response carried %d items, want 2", len(items))
	}
	if got := items[1].GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Errorf("item B denial_reason = %v, want SIGNATURE_INVALID", got)
	}

	// A's row carries A's own offer — not the batch's first item by accident,
	// which is the failure a single-item suite can never surface.
	rec := evidenceFor(t, h, items[0].GetTransactionId())
	if rec.OfferID != offerA.GetOfferId() {
		t.Errorf("offer_id = %q, want item A's own offer id %q", rec.OfferID, offerA.GetOfferId())
	}
	if rec.OfferSignature != offerA.GetSignature() {
		t.Error("evidence row carries a signature other than item A's")
	}
	assertOfferLegVerifies(t, rec)

	// B committed nothing.
	assertNoTransaction(t, h, derivedTxKey(reqKey, tamperedB))
}
