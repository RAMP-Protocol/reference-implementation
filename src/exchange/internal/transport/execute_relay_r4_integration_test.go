//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// mintWrongKeyAcceptanceFor signs a structurally valid body acceptance over
// offer for requester/txID with a FRESH key unrelated to any registered agent —
// used to prove the Exchange verifies the acceptance against the agents-row key,
// not whatever key the request implies.
func mintWrongKeyAcceptanceFor(
	t *testing.T, offer *rampv1.Offer, requester *rampv1.Requester, txID string,
) *rampv1.AgentAcceptance {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("wrong-key gen: %v", err)
	}
	return signAcceptanceFor(t, priv, offer, requester, txID)
}

// Relay R4 (§3): the Exchange verifies
// BOTH the transport signature chain (agent + relaying broker hops, via the SDK
// multisig verifier) AND the BODY agent offer-acceptance signature
// (helpers.VerifyOfferAcceptance). The authoritative agent identity — the
// key whose RFC 7638 thumbprint binds the delivery URL — is the one proven by
// the BODY acceptance (resolved from the agent's REGISTERED key), NOT the
// transport sig. A broker may relay only when the target tenant has
// allow_broker_relay = true.
//
// Round-trip honesty: every leg drives the full transport→service→repo→DB stack
// through the public Connect-Go ExecuteTransaction RPC and asserts back through
// that same surface. Side-effect ABSENCE is observed through the production
// repository surface (repo.TransactionRepo.ByIdempotencyKey — the documented tier-2
// fallback, no public transaction-read RPC exists)
// and the billing adapter's GetBalance — never raw sqlc/SQL (Testing Doctrine
// §9/§10). Each negative asserts BOTH the connect.Code AND the absence of the
// delivery URL / billing debit / transaction row.

// executeBrokerRelay drives ExecuteTransaction through the agent+broker
// forwarding chain (sig1 agent, sig2 broker) carried by client, with a valid
// body acceptance signed by the default agent-test caller key.
func executeBrokerRelay(
	t *testing.T, h *testHarness, client rampconnect.ExchangeServiceClient,
	txID string, offer *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	// Items-only contract after the C4 collapse: a single batch item carrying the
	// offer + the agent body acceptance over the SHARED requester + idempotency
	// key. The relay multisig chain still rides on the transport (client).
	return client.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: txID,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, txID)},
		},
	}))
}

// TestExecuteRelayR4_AgentDirectAcceptanceBindsAgent is the agent-direct
// positive: a single-sig request with a valid body acceptance succeeds, the
// signed URL binds the AGENT's thumbprint (agent_identity_hash == URL agent_id),
// the signed price is charged, and a transaction row is persisted.
func TestExecuteRelayR4_AgentDirectAcceptanceBindsAgent(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/r4-direct", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const txID = "tx-r4-direct"
	resp, err := executePresented(t, h, txID, offer.GetOfferId(), offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	// The delivery URL binds the AGENT's registered (acceptance) key.
	wantThumb, err := helpers.Thumbprint(h.callerPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got := resp.Msg.GetAgentIdentityHash(); got != wantThumb {
		t.Errorf("agent_identity_hash = %q, want agent thumbprint %q", got, wantThumb)
	}
	signedURL := itemSignedURL(t, resp)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != wantThumb {
		t.Errorf("URL agent_id = %q, want agent thumbprint %q", got, wantThumb)
	}

	// Signed price charged (0.05 → balance 9.95) and a row persisted under the
	// DERIVED per-item key (items-only path).
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (signed price charged)", bal.Value.FloatString(4))
	}
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey: %v", err)
	}
	if rec.TransactionID == "" {
		t.Error("persisted transaction has empty transaction_id")
	}
}

// TestExecuteRelayR4_BrokerRelayBindsAgentNotBroker is the relay positive: an
// agent+broker transport chain with a valid body acceptance and
// allow_broker_relay = true succeeds, and the delivery URL still binds the
// AGENT's thumbprint — never the relaying broker's key.
func TestExecuteRelayR4_BrokerRelayBindsAgentNotBroker(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	uri := seedResourceWithRate(t, h, "/articles/r4-relay", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	relayClient := h.brokerRelayClient(t, "broker.relay-1.v1")
	const txID = "tx-r4-relay"
	resp, err := executeBrokerRelay(t, h, relayClient, txID, offer)
	if err != nil {
		t.Fatalf("broker-relay execute: %v", err)
	}

	wantThumb, err := helpers.Thumbprint(h.callerPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got := resp.Msg.GetAgentIdentityHash(); got != wantThumb {
		t.Errorf("agent_identity_hash = %q, want AGENT thumbprint %q (not broker)", got, wantThumb)
	}
	signedURL := itemSignedURL(t, resp)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != wantThumb {
		t.Errorf("URL agent_id = %q, want AGENT thumbprint %q (not broker)", got, wantThumb)
	}
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey: %v", err)
	}
	if rec.TransactionID == "" {
		t.Error("persisted relay transaction has empty transaction_id")
	}
}

// TestExecuteRelayR4_NonBrokerTypeRelayAdmittedWhenEnabled locks the single-gate
// relay posture (single-broker Option C): on an allow_broker_relay=true tenant a
// relay hop whose agents-row requester_type is AGENT (NOT a registered broker) is
// ADMITTED. The transport chain is classified by POSITION only; the hop's
// requester_type is deliberately never re-checked, so the tenant flag is the sole
// gate. The minted delivery URL still binds the AGENT's body-acceptance key, never
// the relay's. This is the inverse of the removed requester_type re-check gate,
// which is structurally infeasible after the WBA split (one Signature-Agent header
// cannot name a distinct directory per hop). It pairs with
// TestExecuteRelayR4_BrokerRelayDeniedWhenDisabled, the tenant-flag negative.
func TestExecuteRelayR4_NonBrokerTypeRelayAdmittedWhenEnabled(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	uri := seedResourceWithRate(t, h, "/articles/r4-nonbroker-relay", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	// The relay hop is a resolver-known key whose agents row is requester_type=AGENT.
	relayClient := h.relayClientAs(t, "relay.nonbroker-1.v1", sqlc.RampRequesterTypeAGENT)
	const txID = "tx-r4-nonbroker-relay"
	resp, err := executeBrokerRelay(t, h, relayClient, txID, offer)
	if err != nil {
		t.Fatalf("non-broker-type relay must be admitted on allow_broker_relay tenant: %v", err)
	}

	wantThumb, err := helpers.Thumbprint(h.callerPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got := resp.Msg.GetAgentIdentityHash(); got != wantThumb {
		t.Errorf("agent_identity_hash = %q, want AGENT thumbprint %q (bound to acceptance key, not relay)", got, wantThumb)
	}
	signedURL := itemSignedURL(t, resp)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse delivery URL: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != wantThumb {
		t.Errorf("URL agent_id = %q, want AGENT thumbprint %q (bound to acceptance key, not relay)", got, wantThumb)
	}
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey: %v", err)
	}
	if rec.TransactionID == "" {
		t.Error("admitted non-broker-type relay transaction has empty transaction_id")
	}
}

// TestExecuteRelayR4_BrokerOnlyAcceptanceBindsAgent is the re-package positive
// (broker-only transport): a BROKER-ONLY transport (a single broker
// sig, NO agent sig1 over the Exchange URL — exactly what the broker produces
// when it re-packages) carrying a VALID body AgentAcceptance succeeds, and the
// signed URL binds the AGENT's thumbprint (from the body acceptance), not the
// broker's. This proves the Exchange needs no agent transport signature over its
// own URL — the agent is topology-decoupled. (The negative counterpart is
// TestExecuteRelayR4_BrokerOnlyNoAcceptanceRejected.)
func TestExecuteRelayR4_BrokerOnlyAcceptanceBindsAgent(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	uri := seedResourceWithRate(t, h, "/articles/r4-broker-only-bind", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	brokerClient := h.brokerOnlyClient(t, "broker.only-bind-1.v1")
	const txID = "tx-r4-broker-only-bind"
	resp, err := executeBrokerRelay(t, h, brokerClient, txID, offer)
	if err != nil {
		t.Fatalf("broker-only execute with valid acceptance: %v", err)
	}

	wantThumb, err := helpers.Thumbprint(h.callerPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got := resp.Msg.GetAgentIdentityHash(); got != wantThumb {
		t.Errorf("agent_identity_hash = %q, want AGENT thumbprint %q (bound via body acceptance, not broker)",
			got, wantThumb)
	}
	signedURL := itemSignedURL(t, resp)
	parsed, err := url.Parse(signedURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := parsed.Query().Get("agent_id"); got != wantThumb {
		t.Errorf("URL agent_id = %q, want AGENT thumbprint %q (not broker)", got, wantThumb)
	}
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(txID, offer))
	if err != nil {
		t.Fatalf("ByIdempotencyKey: %v", err)
	}
	if rec.TransactionID == "" {
		t.Error("persisted broker-only transaction has empty transaction_id")
	}
}

// TestExecuteRelayR4_TamperedAcceptanceRejected (NEG1): the body
// offer-acceptance signature is tampered (a valid acceptance over the offer is
// mutated), so VerifyOfferAcceptance fails → Unauthenticated /
// SIGNATURE_INVALID, with no transaction persisted and no billing side effect.
func TestExecuteRelayR4_TamperedAcceptanceRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/r4-tamper-acc", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const txID = "tx-r4-tamper-acc"
	acc := h.defaultAcceptance(t, offer, txID)
	// Flip the last hex nibble of the signature → a syntactically valid but
	// cryptographically wrong acceptance over the same offer.
	sig := []byte(acc.GetSignature())
	if sig[len(sig)-1] == '0' {
		sig[len(sig)-1] = '1'
	} else {
		sig[len(sig)-1] = '0'
	}
	acc.Signature = string(sig)

	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: txID,
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		Items: []*rampv1.TransactionItem{{Offer: offer, AgentAcceptance: acc}},
	}))
	// KindSignatureInvalid is a denial-map kind → in-body per-item denial after
	// the C4 items-only collapse (Flag #1). Strength preserved: SIGNATURE_INVALID
	// + no transaction + no billing side effect.
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteRelayR4_MissingAcceptanceRejected (NEG1, envelope leg): no body
// acceptance at all is an InvalidArgument envelope rejection (validateTxRequest),
// before any crypto, with no side effect.
func TestExecuteRelayR4_MissingAcceptanceRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/r4-missing-acc", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const txID = "tx-r4-missing-acc"
	_, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: txID,
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		// item carries the offer but its agent_acceptance is deliberately omitted.
		Items: []*rampv1.TransactionItem{{Offer: offer}},
	}))
	// KindInvalidRequest is NOT in the denial map → validateBatchRequest aborts
	// the whole batch with CodeInvalidArgument before any per-item work (Flag #1).
	assertConnectError(t, err, connect.CodeInvalidArgument, "agent_acceptance")
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteRelayR4_BrokerOnlyNoAcceptanceRejected (NEG2): a broker-only
// transport (broker sig only, no agent sig1) with NO body acceptance has no
// authoritative agent and is rejected (InvalidArgument envelope), with no side
// effect. allow_broker_relay is on, isolating the rejection to the missing
// agent identity rather than the relay gate.
func TestExecuteRelayR4_BrokerOnlyNoAcceptanceRejected(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	uri := seedResourceWithRate(t, h, "/articles/r4-broker-only", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	brokerClient := h.brokerOnlyClient(t, "broker.only-1.v1")
	const txID = "tx-r4-broker-only"
	_, err := brokerClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: txID,
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		// item carries the offer but no agent acceptance → no authoritative agent
		// identity → envelope reject (KindInvalidRequest, not in the denial map).
		Items: []*rampv1.TransactionItem{{Offer: offer}},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "agent_acceptance")
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteRelayR4_BrokerRelayDeniedWhenDisabled (NEG3): a broker-relay
// transport chain with a fully valid body acceptance is refused with
// PermissionDenied when the tenant has allow_broker_relay = false, with no
// transaction persisted and no billing side effect.
func TestExecuteRelayR4_BrokerRelayDeniedWhenDisabled(t *testing.T) {
	h := newTestHarness(t)
	// allow_broker_relay defaults to FALSE — do NOT enable it.
	uri := seedResourceWithRate(t, h, "/articles/r4-relay-denied", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	relayClient := h.brokerRelayClient(t, "broker.denied-1.v1")
	const txID = "tx-r4-relay-denied"
	_, err := executeBrokerRelay(t, h, relayClient, txID, offer)
	// KindPermissionDenied is NOT in the denial map → the batch aborts with
	// CodePermissionDenied (Flag #1), not an in-body denial.
	assertConnectCode(t, err, connect.CodePermissionDenied)
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}

// TestExecuteRelayR4_WrongKeyAcceptanceRejected pins that the acceptance must be
// signed by the AGENT's REGISTERED key: a valid acceptance signed by a DIFFERENT
// key (the same offer, requester, txID) is rejected SIGNATURE_INVALID, proving
// the Exchange resolves the verifying key from the agents row, not the request.
func TestExecuteRelayR4_WrongKeyAcceptanceRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/r4-wrong-key", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	const txID = "tx-r4-wrong-key"
	// Sign the acceptance with a fresh key that is NOT agent-test's registered key.
	wrongAcc := mintWrongKeyAcceptanceFor(t, offer,
		&rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
		txID)
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: txID,
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		Items: []*rampv1.TransactionItem{{Offer: offer, AgentAcceptance: wrongAcc}},
	}))
	// Wrong-key acceptance → KindSignatureInvalid, a denial-map kind → in-body
	// per-item denial after the C4 collapse (Flag #1).
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(txID, offer))
	assertBalanceUnchanged(t, h)
}
