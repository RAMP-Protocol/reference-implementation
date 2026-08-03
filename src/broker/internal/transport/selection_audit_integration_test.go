//go:build integration

package transport_test

// Selection-audit regression test.
//
// Restores the dropped selection-audit coverage: after a LICENSED resolve, the
// broker must have recorded a selection_log row capturing the RANKED candidate
// set and the outcome. The broker records NO "winner" — it discovers + ranks +
// relays, and the agent selects at execute (audited authoritatively by the
// exchange's transaction_log.offer_id), so the selection_log is winner-free. RAMP
// has no agent-facing reporting RPC by design, so this audit state is invisible to the typed DiscoveryResponse
// the agent sees — the only honest way to observe it today is the broker's own
// persistence surface.
//
// Round-trip honesty: the WRITE leg is a full PROTOCOL round-trip — signed
// Connect client → RFC 9421 signature → httpsig middleware → RequestIDMiddleware
// → registered BrokerService Connect handler → shared resolve core →
// auditSelection → SelectionLogRepo.RecordSelection → Postgres. The READ leg is a
// PERSISTENCE round-trip — it stops at the production repository interface
// (repo.SelectionLogRepo.ByRequestID over the sqlc Querier), NOT the protocol
// surface, because no public read RPC exists. It is NOT a protocol round-trip and
// is not claimed as one.

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// TestResolve_RecordsSelectionAudit pins the broker selection-audit invariant:
// a licensed-discovery resolve writes exactly one selection_log row, keyed by the
// request's X-Request-ID, recording the ranked candidate set and a "discovered"
// outcome (resolve is discovery-only — the audit records the discovered+ranked
// set, NOT a "winner" and NOT an executed tx).
//
// The request_id is the correlation key. The broker's RequestIDMiddleware honors
// an inbound X-Request-ID verbatim (internal/reqctx/reqctx.go:42), and
// auditSelection persists that SAME id as SelectionLogEntry.RequestID
// (resolve.go:334). X-Request-ID is NOT part of the RFC 9421 covered-component
// set, so pinning it on the outbound signed Connect call neither breaks the
// signature nor is stripped. We therefore set a deterministic X-Request-ID on the
// request and query the audit by that exact id — no reliance on the
// server-minted UUID.
func TestResolve_RecordsSelectionAudit(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const knownReqID = "req-selection-audit-test-0001"

	// WRITE leg — drive the LICENSED/delivered path over the SAME signed Connect
	// surface the other resolve tests use (mirrors resolveOverConnect, but pins a
	// deterministic X-Request-ID on the outbound request so the audit's
	// request_id is known up front).
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, "agent-1", pub)
	client := signingBrokerClient(srv.base, srv.server.URL, "agent-1", priv)
	req := connect.NewRequest(buildDiscoveryRequest("agent-1", reqOpts{
		query:       "RAMP intro",
		budgetMinor: 10000,
	}))
	req.Header().Set("X-Request-ID", knownReqID)
	out, err := client.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve returned transport error: %v", err)
	}
	if len(out.Msg.GetOfferGroups()) == 0 {
		t.Fatal("expected non-empty offer_groups (licensed-discovery flow) — wrong fixture state")
	}
	// Defensive: confirm the server honored our X-Request-ID so the read below
	// queries the right key (the middleware echoes it on the response header).
	if got := out.Header().Get("X-Request-ID"); got != knownReqID {
		t.Fatalf("response X-Request-ID = %q, want %q", got, knownReqID)
	}

	// READ leg (Testing-Doctrine §9 tier-2): no public read RPC exists for the
	// broker's selection audit — RAMP defines no reporting/record-read surface
	// (project_no_protocol_reporting_surface). We therefore observe the audit
	// through the PRODUCTION repository interface (repo.SelectionLogRepo), the
	// documented tier-2 fallback, NEVER raw SQL / sqlc.
	//
	// TODO: when the BrokerOpsService/GetResolveAudit operator RPC lands,
	// migrate this assertion from the repo (tier-2) onto that RPC (tier-1) and
	// drop this inline exemption.
	logRepo := repo.NewSelectionLogRepo(fx.pool)

	entries, err := logRepo.ByRequestID(ctx, knownReqID)
	if err != nil {
		t.Fatalf("ByRequestID(%q): %v", knownReqID, err)
	}
	if len(entries) != 1 {
		t.Fatalf("ByRequestID returned %d entries, want exactly 1", len(entries))
	}
	got := entries[0]

	if got.RequestID != knownReqID {
		t.Errorf("RequestID = %q, want %q", got.RequestID, knownReqID)
	}
	// The broker records NO "winner" (it discovers + ranks + relays; the agent
	// selects at execute, audited by the exchange's transaction_log.offer_id). What
	// the broker did is captured by candidate_offers + outcome, asserted below.

	// Outcome: auditSelection stores Rationale=map[string]any{"outcome": <outcome>}
	// and the licensed-discovery path passes "discovered" (R7 — resolve discovers
	// and ranks, it no longer delivers an executed tx).
	rationale, ok := got.Rationale.(map[string]any)
	if !ok {
		t.Fatalf("Rationale type = %T, want map[string]any", got.Rationale)
	}
	if outcome, _ := rationale["outcome"].(string); outcome != "discovered" {
		t.Errorf("Rationale[outcome] = %q, want %q", outcome, "discovered")
	}

	// The ranked candidate set was recorded. The repo reconstructs the JSONB
	// candidate_offers into typed []repo.CandidateInfo (the implement step adds
	// repo.CandidateInfo so the read stays inside the repo layer — repo must not
	// import the transport package).
	candidates, ok := got.CandidateOffers.([]repo.CandidateInfo)
	if !ok {
		t.Fatalf("CandidateOffers type = %T, want []repo.CandidateInfo", got.CandidateOffers)
	}
	if len(candidates) == 0 {
		t.Fatal("CandidateOffers is empty — the ranked candidate set was not recorded")
	}
	var sawWinner bool
	for _, c := range candidates {
		if c.OfferID == "offer-1" {
			sawWinner = true
			if c.ExchangeID != "mp.acme.example" {
				t.Errorf("candidate offer-1 ExchangeID = %q, want %q", c.ExchangeID, "mp.acme.example")
			}
		}
	}
	if !sawWinner {
		t.Errorf("ranked CandidateOffers does not contain the winning offer-1: %+v", candidates)
	}

	// Negative path (Testing Doctrine pt10): an unknown request_id yields an
	// empty slice with NO error (sqlc emit_empty_slices), never a spurious row.
	none, err := logRepo.ByRequestID(ctx, "req-does-not-exist-9999")
	if err != nil {
		t.Fatalf("ByRequestID(unknown): unexpected error %v", err)
	}
	if len(none) != 0 {
		t.Errorf("ByRequestID(unknown) returned %d entries, want 0", len(none))
	}
}

// TestResolve_SelectionAudit_CrossGroupGlobalWinner pins the model invariant
// behind the no-winner selection model: the broker DISCOVERS + RANKS + RELAYS, it does
// NOT record a "winner" — the agent selects at execute. It drives a MULTI-URI
// resolve whose GLOBAL best (the cheapest offer of the whole batch) lives in
// GROUP-1, NOT in group-0's request-order head, and asserts the selection_log
// records a winner-FREE audit whose candidate_offers SPANS BOTH provider domains
// and CONTAINS the group-1 global winner — proving flattenGroups recorded every
// group. Pre-DROP this scenario produced a self-inconsistent winner_offer_id
// (group-1 offer) / winner_exchange (group-0 domain); the DROP makes that
// disagreement structurally impossible (the columns no longer exist). The
// authoritative "which offer won" audit lives at the exchange
// (transaction_log.offer_id), where the agent's execute-time selection
// materializes.
//
// Round-trip honesty: WRITE leg is a full PROTOCOL round-trip (signed Connect
// client → RFC 9421 → httpsig → RequestIDMiddleware → BrokerService handler →
// resolve core → auditSelection → SelectionLogRepo.RecordSelection → Postgres).
// READ leg is a PERSISTENCE round-trip — the production repo.SelectionLogRepo over
// fx.pool (tier-2 documented fallback; no public read RPC exists), never raw SQL.
func TestResolve_SelectionAudit_CrossGroupGlobalWinner(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{
		providerDomain: "acme.example", // URI-1 publisher → group-0 head (offer-1 @ $0.10)
		secondary: &secondaryProvider{
			providerDomain:    "beta.example",
			exchangeDomain:    "mp.beta.example",
			offerID:           "offer-2",
			offerCost:         0.05, // strictly cheaper than offer-1 ($0.10) → GLOBAL winner, in group-1
			offerCanonicalURL: "https://beta.example/article-2",
		},
	})

	const knownReqID = "req-selection-audit-crossgroup-0001"

	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, "agent-1", pub)
	client := signingBrokerClient(srv.base, srv.server.URL, "agent-1", priv)
	req := connect.NewRequest(buildDiscoveryRequest("agent-1", reqOpts{
		uris: []string{
			"https://acme.example/article-1", // group-0 (request-order head)
			"https://beta.example/article-2", // group-1 (carries the global winner)
		},
		budgetMinor: 100000,
	}))
	req.Header().Set("X-Request-ID", knownReqID)
	out, err := client.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve returned transport error: %v", err)
	}
	if len(out.Msg.GetOfferGroups()) < 2 {
		t.Fatalf("expected 2 offer_groups (two routed URIs), got %d — wrong fixture state",
			len(out.Msg.GetOfferGroups()))
	}

	logRepo := repo.NewSelectionLogRepo(fx.pool)
	entries, err := logRepo.ByRequestID(ctx, knownReqID)
	if err != nil {
		t.Fatalf("ByRequestID(%q): %v", knownReqID, err)
	}
	if len(entries) != 1 {
		t.Fatalf("ByRequestID returned %d entries, want exactly 1", len(entries))
	}
	got := entries[0]

	candidates, ok := got.CandidateOffers.([]repo.CandidateInfo)
	if !ok {
		t.Fatalf("CandidateOffers type = %T, want []repo.CandidateInfo", got.CandidateOffers)
	}
	// The recorded candidate set SPANS BOTH provider domains (flattenGroups recorded
	// every group, not just group-0) and CONTAINS the group-1 global winner.
	exchangesSeen := make(map[string]bool, len(candidates))
	offersSeen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		exchangesSeen[c.ExchangeID] = true
		offersSeen[c.OfferID] = true
	}
	if !exchangesSeen["mp.acme.example"] || !exchangesSeen["mp.beta.example"] {
		t.Errorf("candidate_offers must span BOTH provider domains; saw %v (candidates %+v)",
			exchangesSeen, candidates)
	}
	if !offersSeen["offer-2"] {
		t.Errorf("candidate_offers must contain the group-1 global-winner offer-2; saw %+v", candidates)
	}
	// The audit row is WINNER-FREE — there is no winner field on SelectionLogEntry,
	// so the cross-group disagreement the winner-recording model risked is structurally impossible.
	rationale, ok := got.Rationale.(map[string]any)
	if !ok {
		t.Fatalf("Rationale type = %T, want map[string]any", got.Rationale)
	}
	if outcome, _ := rationale["outcome"].(string); outcome != "discovered" {
		t.Errorf("Rationale[outcome] = %q, want %q", outcome, "discovered")
	}
}
