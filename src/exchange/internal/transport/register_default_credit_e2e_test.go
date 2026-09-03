//go:build integration

package transport_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	sharedtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// E2E for the tenant-configured default agent credit: a freshly registered
// agent is granted tenants.default_agent_credit once, through the public
// Register RPC, and can spend exactly that much on paid transactions. Money
// movement is driven end to end (Register → DiscoverResources →
// ExecuteTransaction) against the balance-bearing InMemoryAdapter; the real
// TigerBeetle ledger runs the same registration flow in
// billing_tigerbeetle_register_e2e_test.go.

// tenantArrange bundles what a tenant-configuration arrange step needs;
// bundling keeps each helper under the argument-count cap.
type tenantArrange struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	queries  *sqlc.Queries
	tenantID string
}

// setTenantDefaultCredit arranges the tenant's default agent credit through
// the production write surface — repo.NewTenantWriteRepo(...).SetDefaultAgentCredit
// inside one transaction, the same guarded writer the boot-time
// EXCHANGE_DEFAULT_AGENT_CREDIT application commits through — so the arrange
// step runs guardDefaultAgentCredit rather than reaching past it with raw sqlc.
func setTenantDefaultCredit(t *testing.T, a tenantArrange, amount string) {
	t.Helper()
	credit := sharedtestutil.MustRat(t, amount)
	writer := repo.NewTenantWriteRepo(a.queries)
	err := db.WithTx(a.ctx, a.pool, func(tx pgx.Tx) error {
		n, err := writer.SetDefaultAgentCredit(a.ctx, tx, a.tenantID, credit)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("rows affected = %d, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("set tenant default credit: %v", err)
	}
}

// setTenantActivationDefault arranges whether the tenant starts newly
// registered agents active, through repo.NewTenantWriteRepo(...).
// SetActivateNewAgentsByDefault inside one transaction.
//
// This is a repository-level arrange, one tier below the public RPC surface,
// because no admin RPC writes activate_new_agents_by_default yet. That missing
// surface is filed as its own task. The repository port is still the highest
// surface that reaches this column, so the arrange runs through the same writer
// production would use rather than reaching past it with raw sqlc.
func setTenantActivationDefault(t *testing.T, a tenantArrange, active bool) {
	t.Helper()
	writer := repo.NewTenantWriteRepo(a.queries)
	err := db.WithTx(a.ctx, a.pool, func(tx pgx.Tx) error {
		n, err := writer.SetActivateNewAgentsByDefault(a.ctx, tx, a.tenantID, active)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("rows affected = %d, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("set tenant activation default: %v", err)
	}
}

func (h *pushHarness) arrange() tenantArrange {
	return tenantArrange{ctx: h.ctx, pool: h.pool, queries: h.queries, tenantID: h.tenantID}
}

func (h *registerHarness) arrange() tenantArrange {
	return tenantArrange{ctx: h.ctx, pool: h.pool, queries: h.queries, tenantID: h.tenantID}
}

// executeAsAgent drives ExecuteTransaction for offer as the self-registered
// agent: the harness's broker-signed transport carries the call and the body
// acceptance is signed with the agent's own registered key over the exact
// requester on the wire (the R4 relay shape the self-signup e2e uses).
func executeAsAgent(
	t *testing.T, h *pushHarness, agent *registerAgent, offer *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	key := "tx-" + uuid.NewString()
	requester := newRequester(agent.id, agent.id)
	return h.exchange.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: key,
		Requester: requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, agent.priv, offer, requester, key)},
		},
	}))
}

// newAgent stands up a fresh self-signup agent through the shared
// newSignupAgent fixture: its own WBA directory origin, httpsig-gate
// registration, and a signed client.
func (h *pushHarness) newAgent(t *testing.T, agentID string) *registerAgent {
	t.Helper()
	return newSignupAgent(t, agentID, h.publishAgent, h.resolver, h.selfActingExchangeClient)
}

// discoverOffersForAgent fetches signed offers for uris as the agent.
func discoverOffersForAgent(t *testing.T, h *pushHarness, agentID string, uris ...string) []*rampv1.Offer {
	t.Helper()
	resp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester(agentID, agentID), uris)))
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	offers := resp.Msg.GetOffers()
	if len(offers) != len(uris) {
		t.Fatalf("offers len = %d, want %d", len(offers), len(uris))
	}
	return offers
}

// assertBalanceThrough asserts an agent's settled balance through the billing
// adapter's GetBalance port. No production code path reads balances — the
// Exchange exposes no balance RPC and the service never calls GetBalance — so
// this is the Testing-Doctrine §9 tier-2 fallback: the adapter port is the
// highest read surface that exists for ledger balances until a public
// account-balance read lands. Shared by the in-memory and TigerBeetle
// default-credit flows.
func assertBalanceThrough(t *testing.T, ctx context.Context, bill billing.Adapter, ref, want string) {
	t.Helper()
	bal, err := bill.GetBalance(ctx, ref)
	if err != nil {
		t.Fatalf("GetBalance(%q): %v", ref, err)
	}
	w := sharedtestutil.MustRat(t, want)
	if bal.Value.Cmp(w) != 0 {
		t.Fatalf("balance(%q) = %s, want %s", ref, bal.Value.FloatString(8), want)
	}
}

// seedThreePricedURIs pushes three 0.05-USD-priced URIs (estimated quantity 1)
// under the harness tenant and returns their URIs.
func seedThreePricedURIs(t *testing.T, h *pushHarness) []string {
	t.Helper()
	entries := []*rampv1.ResourceEntry{
		{Domain: h.publisherDom, Path: "/articles/one", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: h.publisherDom, Path: "/articles/two", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
		{Domain: h.publisherDom, Path: "/articles/three", Terms: []*rampv1.LicenseTerm{seedPricedTermEst(1)}},
	}
	h.seedPublisherEntries(t, "pub-caller.example", entries...)
	uris := make([]string, len(entries))
	for i, e := range entries {
		uris[i] = "https://" + e.GetDomain() + e.GetPath()
	}
	return uris
}

// TestRegisterDefaultCredit_GrantedOnceAndSpendable is the headline
// acceptance flow: with default_agent_credit = 0.10 on the tenant, a new agent
// registers and can buy paid content worth exactly 0.10 (two 0.05 items) end
// to end through the public RPC surface. A repeat Register between the spends
// does not credit twice — the third item is denied INSUFFICIENT_BALANCE, so
// total spendable provably stayed 0.10. The recording adapter additionally pins
// the Register billing ordering: EnsureAgentAccount first, then exactly one
// Credit under the welcome idempotency key.
func TestRegisterDefaultCredit_GrantedOnceAndSpendable(t *testing.T) {
	rec := newRecordingAdapter(billing.NewInMemoryAdapter(billing.InMemoryOptions{}))
	h := newPushHarnessWith(t, pushHarnessOptions{billing: rec})
	setTenantDefaultCredit(t, h.arrange(), "0.10")
	uris := seedThreePricedURIs(t, h)

	agent := h.newAgent(t, "credit-agent.example")
	ref := registerCaller(t, h.ctx, agent.client)
	if ref == "" {
		t.Fatal("Register returned an empty billing_ref")
	}
	// The welcome credit is on the ledger account right after Register,
	// observed through the adapter surface production reads balances from.
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0.10")
	// Ordering, directly observed: the account is created before it is
	// credited, each exactly once, and the credit carries the welcome slot key.
	events := rec.accountEventLog()
	if len(events) != 2 ||
		events[0].Method != "EnsureAgentAccount" || events[0].BillingRef != ref ||
		events[1].Method != "Credit" || events[1].BillingRef != ref {
		t.Fatalf("account events after Register = %+v, want [EnsureAgentAccount(%s) Credit(%s)]", events, ref, ref)
	}
	if wantKey := billing.WelcomeCreditKey(ref); events[1].Key != wantKey {
		t.Fatalf("Credit idempotency key = %q, want %q", events[1].Key, wantKey)
	}

	offers := discoverOffersForAgent(t, h, agent.id, uris...)

	// First 0.05 item: authorized and settled within the granted credit.
	resp, err := executeAsAgent(t, h, agent, offers[0])
	if err != nil {
		t.Fatalf("execute item 1: %v", err)
	}
	if singleResultItem(t, resp).GetRetrievalEndpoint() == "" {
		t.Fatal("item 1: retrieval_endpoint missing (expected an authorized paid transaction)")
	}

	// Repeat Register mid-spend: the fast path answers with the same ref and
	// grants nothing — proven below by spending, not by balance alone, and
	// directly by the account-call log staying at the two first-register calls.
	if again := registerCaller(t, h.ctx, agent.client); again != ref {
		t.Fatalf("repeat Register billing_ref = %q, want %q", again, ref)
	}
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0.05")
	if events := rec.accountEventLog(); len(events) != 2 {
		t.Fatalf("account events after repeat Register = %d, want 2 (fast path makes no billing calls)", len(events))
	}

	// Second 0.05 item: exhausts the credit.
	resp, err = executeAsAgent(t, h, agent, offers[1])
	if err != nil {
		t.Fatalf("execute item 2: %v", err)
	}
	if singleResultItem(t, resp).GetRetrievalEndpoint() == "" {
		t.Fatal("item 2: retrieval_endpoint missing (the second 0.05 must still fit the 0.10 credit)")
	}

	// Third item exceeds the remaining credit (0 < 0.05): denied in-body with
	// INSUFFICIENT_BALANCE. Had the repeat Register credited again, this would
	// have been authorized — the denial is what proves single-grant semantics.
	resp, err = executeAsAgent(t, h, agent, offers[2])
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0.00")
}

// TestRegisterDefaultCredit_ZeroDefaultUnchanged pins the default-off contract:
// with default_agent_credit = 0 (the column default, deliberately not set
// here), registration grants nothing and the first paid transaction is denied
// INSUFFICIENT_BALANCE — the strictly prepaid behavior from before the feature.
func TestRegisterDefaultCredit_ZeroDefaultUnchanged(t *testing.T) {
	h := newPushHarnessWith(t, pushHarnessOptions{billing: billing.NewInMemoryAdapter(billing.InMemoryOptions{})})
	uris := seedThreePricedURIs(t, h)

	agent := h.newAgent(t, "broke-agent.example")
	ref := registerCaller(t, h.ctx, agent.client)
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0")

	offers := discoverOffersForAgent(t, h, agent.id, uris[0])
	resp, err := executeAsAgent(t, h, agent, offers[0])
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)
}

// TestRegisterDefaultCredit_InactiveAccountNotGranted pins the review-hold
// policy: with default_agent_credit set but activate_new_agents_by_default
// flipped off, a fresh registration succeeds inactive and the welcome credit
// is NOT granted — the billing adapter sees the account creation and no Credit
// call, and the balance stays 0. A tenant holding new agents for review must
// not pay for every self-signup; a later manual activation is funded through
// the operator script's shared service slot instead.
func TestRegisterDefaultCredit_InactiveAccountNotGranted(t *testing.T) {
	rec := newRecordingAdapter(billing.NewInMemoryAdapter(billing.InMemoryOptions{}))
	h := newPushHarnessWith(t, pushHarnessOptions{billing: rec})
	setTenantDefaultCredit(t, h.arrange(), "0.10")
	setTenantActivationDefault(t, h.arrange(), false)

	agent := h.newAgent(t, "held-agent.example")
	resp, err := agent.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.Msg.GetActive() {
		t.Fatal("active = true, want false (tenant holds new agents for review)")
	}
	ref := resp.Msg.GetBillingRef()
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0")
	events := rec.accountEventLog()
	if len(events) != 1 || events[0].Method != "EnsureAgentAccount" {
		t.Fatalf("account events = %+v, want exactly [EnsureAgentAccount] (no Credit for an inactive account)", events)
	}
}

// creditFailingAdapter wraps a billing.Adapter and fails the first N Credit
// calls with the injected error — the adapter-boundary fault injection for
// the Register failure legs.
type creditFailingAdapter struct {
	billing.Adapter
	failures atomic.Int32
	inject   error
}

var errLedgerDown = errors.New("injected: ledger failure during credit")

func (a *creditFailingAdapter) Credit(
	ctx context.Context, billingRef string, amount billing.Amount, idempotencyKey string,
) error {
	if a.failures.Add(-1) >= 0 {
		return a.inject
	}
	return a.Adapter.Credit(ctx, billingRef, amount, idempotencyKey)
}

// TestRegisterDefaultCredit_CreditFailureFailsRegister drives the negative
// path: when the grant fails, Register fails as a whole and stores NO
// billing_ref — observed through the public GetAccountStatus RPC — so a retry
// re-enters the first-register branch and grants the credit exactly once.
func TestRegisterDefaultCredit_CreditFailureFailsRegister(t *testing.T) {
	inner := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	flaky := &creditFailingAdapter{Adapter: inner, inject: errLedgerDown}
	flaky.failures.Store(1)
	h := newPushHarnessWith(t, pushHarnessOptions{billing: flaky})
	setTenantDefaultCredit(t, h.arrange(), "0.10")

	agent := h.newAgent(t, "flaky-agent.example")
	client := agent.client

	// First Register: the injected Credit failure fails the RPC (a non-sentinel
	// adapter error maps to Internal).
	_, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("Register with failing credit: code = %v, want Internal (err=%v)", got, err)
	}
	// No billing_ref was stored: the public account-status read reports the
	// agent as never registered for paid content.
	_, err = client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("GetAccountStatus after failed Register: code = %v, want NotFound (err=%v)", got, err)
	}

	// Retry: the fault is gone, the branch replays, and the credit lands once.
	resp, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register retry: %v", err)
	}
	ref := resp.Msg.GetBillingRef()
	assertBalanceThrough(t, h.ctx, h.billing, ref, "0.10")
}

// TestRegisterDefaultCredit_CreditOutageMapsUnavailable drives the outage
// shape of the same failure leg: the persisted adapter classifies a ledger
// outage as billing.ErrBackendUnavailable, and the RPC must surface it as
// CodeUnavailable — a retryable 503-class fault, not an Internal server bug.
// The retry after the outage clears grants the credit exactly once.
func TestRegisterDefaultCredit_CreditOutageMapsUnavailable(t *testing.T) {
	inner := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	flaky := &creditFailingAdapter{Adapter: inner, inject: billing.ErrBackendUnavailable}
	flaky.failures.Store(1)
	h := newPushHarnessWith(t, pushHarnessOptions{billing: flaky})
	setTenantDefaultCredit(t, h.arrange(), "0.10")

	agent := h.newAgent(t, "outage-agent.example")
	client := agent.client

	_, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if got := connect.CodeOf(err); got != connect.CodeUnavailable {
		t.Fatalf("Register during ledger outage: code = %v, want Unavailable (err=%v)", got, err)
	}

	resp, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register retry after outage: %v", err)
	}
	assertBalanceThrough(t, h.ctx, h.billing, resp.Msg.GetBillingRef(), "0.10")
}
