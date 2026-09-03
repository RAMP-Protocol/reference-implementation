//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// The execute path attributes a transaction to the CANONICAL directory host of
// the signed requester.id, not to the string the caller sent. That normalization
// shipped with no test at all: deleting it left the whole suite green, because
// every requester.id in the pre-existing fixtures is a bare host that normalizes
// to itself.
//
// It matters on the deployed configuration specifically. The identity service
// builds requester.id from the agent's directory ORIGIN — "scheme://host" — so in
// production the field always arrives schemed while the agents row is keyed on the
// host. Left raw, transaction_log.agent_id would hold a different string from the
// row the caller was authorized against, and its foreign key would drag a second
// registration into existence for one agent.
//
// Round-trip honesty. The execute and report legs are full protocol round-trips:
// signed Connect client → RFC 9421 gate → ExecuteTransaction / ReportUsage
// handler → service → repo → Postgres, asserted back through the same RPCs. The
// two persistence assertions at the end stop at the production REPOSITORY
// interface (Testing Doctrine §9 tier 2) because the Exchange exposes no RPC that
// reads a transaction or its evidence row back — see the note on each.

// seedSignedOfferFor pushes one priced catalog entry and discovers it back as a
// signed offer for the named agent, which is the precondition an execute needs.
// It is the self-signup flow's steps 1 and 6 with nothing added — the variable
// under test in this file is the requester.id spelling, not the catalog.
func (h *agentHarness) seedSignedOfferFor(t *testing.T, agentID string) *rampv1.Offer {
	t.Helper()
	entry := &rampv1.ResourceEntry{
		Domain: h.publisherDom, Path: "/articles/attribution",
		Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)},
	}
	h.seedPublisherEntries(t, "attribution-pub-caller.example", entry)

	discResp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester(agentID, agentID), []string{"https://" + entry.GetDomain() + entry.GetPath()})))
	if err != nil {
		t.Fatalf("seed discover: %v", err)
	}
	offers := discResp.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("seed discover returned %d offers, want 1", len(offers))
	}
	return offers[0]
}

// TestExecute_SchemedRequesterIDAttributesToCanonicalHost drives the deployed
// shape end to end: the agent registers as a bare host and then executes naming
// itself as "https://<host>".
//
// The load-bearing assertion is the ReportUsage leg. ReportUsage authorizes by
// comparing the verified caller's identity against the agent_id stored on the
// transaction's obligation, so a report signed under the BARE spelling is accepted
// only if the execute leg attributed the transaction to the canonical host. Had
// the schemed string been stored, that comparison would fail and the agent could
// never report usage against its own transaction — a break with no self-heal path.
func TestExecute_SchemedRequesterIDAttributesToCanonicalHost(t *testing.T) {
	h := newAgentHarness(t)

	const host = "schemed-requester.example"
	const schemed = "https://" + host

	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	h.publishAgent(t, host, agentPub)
	// Registers the agent for billing under the BARE host, which is what its own
	// directory names it. This is the row the schemed execute below must find.
	h.registerForBilling(t, host, agentPub, agentPriv)

	offer := h.seedSignedOfferFor(t, host)

	// Execute naming the SCHEMED spelling in requester.id, signing Signature-Agent
	// with the same spelling — the exact shape the identity service produces.
	agentClient := h.selfActingExchangeClient(schemed, agentPriv)
	idempotencyKey := "tx-" + uuid.NewString()
	// The schemed spelling is what this test varies, and it belongs on id alone.
	// domain is a bare host on the wire — it is concatenated into the URL a
	// verifier fetches the agent's key from — so a schemed value there is refused
	// for its shape, which would say nothing about the id normalisation under
	// test. The identity service sends the same pair: a bare domain, and whatever
	// spelling the caller's directory gives its id.
	requester := newRequester(schemed, host)
	execResp, err := agentClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: idempotencyKey,
		Requester: requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, agentPriv, offer, requester, idempotencyKey)},
		},
	}))
	if err != nil {
		t.Fatalf("ExecuteTransaction with requester.id %q: %v — the schemed spelling did not "+
			"resolve to the agent registered as %q", schemed, err, host)
	}
	item := singleResultItem(t, execResp)

	// The load-bearing leg: report usage signing the BARE spelling. Accepted only
	// if the transaction was attributed to the canonical host.
	bareClient := h.selfActingExchangeClient(host, agentPriv)
	repResp, err := bareClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-"+uuid.NewString(), item.GetTransactionId(), item.GetBillingId(), &rampv1.Usage{ConsumedQuantity: 1, Function: []string{"ai_input"}})))
	if err != nil {
		t.Fatalf("ReportUsage signed as %q against a transaction executed as %q: %v — "+
			"the transaction was attributed to the raw spelling, so the agent cannot "+
			"report usage against its own transaction", host, schemed, err)
	}
	if repResp.Msg.GetReportId() == "" {
		t.Fatal("accepted report carries no report_id")
	}

	// Testing Doctrine §9 tier-2 fallback. The Exchange exposes no RPC that reads a
	// transaction row back, so the ledger's attributed id is observed through the
	// production TransactionRepo interface rather than a public surface. The
	// repository is the highest surface available and the one production itself
	// uses, but it is still a corner cut, and the thing actually missing is a
	// transaction-read RPC — without one, no client can verify what it was charged
	// for, which is a product gap before it is a testing one. Tracked with the
	// change that introduces this file rather than named here, because an id in a
	// comment outlives whatever it pointed at.
	txRec, err := repo.NewTransactionRepo(h.queries).
		ByIdempotencyKey(h.ctx, idempotencyKey+":"+offer.GetOfferId())
	if err != nil {
		t.Fatalf("TransactionRepo.ByIdempotencyKey: %v", err)
	}
	if txRec.AgentID != host {
		t.Errorf("transaction_log.agent_id = %q, want %q — the ledger is keyed on the "+
			"caller's spelling, not the agent's identity", txRec.AgentID, host)
	}

	// The evidence row keeps the SIGNED bytes verbatim, which is the property that
	// makes it evidence. So the two columns are NOT byte-equal, and migration
	// 000024's column comment documents the join between them as
	// agentid.FromDirectory(requester_id) = transaction_log.agent_id. Assert both
	// halves here so code and that comment cannot drift apart again — the failure
	// mode is a forensic join silently returning nothing.
	//
	// Tier-2 fallback for the same reason, and with the same caveat, as above: no
	// RPC reads an evidence row back either.
	ev, err := repo.NewEvidenceRepo(h.queries).ByTransactionCrossTenant(h.ctx, item.GetTransactionId())
	if err != nil {
		t.Fatalf("EvidenceRepo.ByTransactionCrossTenant: %v", err)
	}
	if ev.RequesterID != schemed {
		t.Errorf("transaction_evidence.requester_id = %q, want the signed bytes %q — "+
			"evidence must attest what was signed, never a rewritten value", ev.RequesterID, schemed)
	}
	joined, err := agentid.FromDirectory(ev.RequesterID)
	if err != nil {
		t.Fatalf("the documented forensic join does not apply to the stored evidence: %v", err)
	}
	if joined != txRec.AgentID {
		t.Errorf("agentid.FromDirectory(evidence.requester_id) = %q, transaction_log.agent_id = %q — "+
			"migration 000024 documents these as equal; a forensic join now returns nothing",
			joined, txRec.AgentID)
	}
}

// TestExecute_RequesterIDNamingNoHostIsInvalidRequest is the negative path of the
// attribution above, and it is a different fault class: the caller authenticates
// fine — its Signature-Agent is a perfectly good directory — it just sent a
// requester.id that cannot be an identity. That is a malformed field, so it is
// InvalidArgument rather than an authentication failure, and the offending field
// name rides typed ErrorDetail metadata (ADR-019 §1) instead of being baked into
// a message clients would have to parse.
//
// The Broker has covered its equivalent since the gate was added; the Exchange
// side was asserted nowhere, which left the refusal free to regress into a
// KindInternal, a 200, or a row keyed on "//host".
func TestExecute_RequesterIDNamingNoHostIsInvalidRequest(t *testing.T) {
	h := newAgentHarness(t)

	const host = "no-host-requester.example"
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}
	h.publishAgent(t, host, agentPub)
	h.registerForBilling(t, host, agentPub, agentPriv)
	offer := h.seedSignedOfferFor(t, host)

	// Authenticates as the registered host; only the BODY field is unusable. "//x"
	// parses to an empty authority, so it names no host while still being a
	// non-empty string that clears the presence check upstream.
	agentClient := h.selfActingExchangeClient(host, agentPriv)
	idempotencyKey := "tx-" + uuid.NewString()
	requester := newRequester("//"+host, host)
	_, err = agentClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: idempotencyKey,
		Requester: requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, agentPriv, offer, requester, idempotencyKey)},
		},
	}))
	if err == nil {
		t.Fatal("a requester.id naming no host was accepted; it would have keyed the ledger row")
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertReportRejectionField(t, err, "requester.id")

	// The side effect is absent, not merely unreported: no transaction row exists
	// for this idempotency key. Tier-2 fallback for the reason given at the top of
	// this file — the Exchange exposes no RPC that reads a transaction back.
	if _, err := repo.NewTransactionRepo(h.queries).
		ByIdempotencyKey(h.ctx, idempotencyKey+":"+offer.GetOfferId()); err == nil {
		t.Error("a rejected execute persisted a transaction row")
	}
}
