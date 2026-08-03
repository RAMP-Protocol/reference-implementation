//go:build integration

package transport_test

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// The Broker's self-action gate compares the signed Signature-Agent directory
// against the caller-supplied requester.id. That comparison changed from an exact
// string match to a match on two canonical hosts, and the request's own agent_id
// is now rewritten to the canonical form before the resolve core runs.
//
// Nothing here reaches past a layer (Testing Doctrine §9). Every case is a signed
// Connect round-trip — signing client → RFC 9421 httpsig middleware → registered
// Resolve handler → validateAndCanonicalizeRequest → authorizeAgentSelfAct → resolve core — and
// each is observed through that same Resolve RPC plus the mock Exchange's call
// counters, which record whether the request ever left the Broker.
//
// The suite exists because reverting the change broke no test: every id in the
// pre-existing broker suite is a bare host that normalizes to itself, so the whole
// widened comparison was invisible. These cases fail if the normalization is
// removed, if it is applied to only one side, or if the canonical value is
// computed and then discarded.

// TestResolve_SchemedDirectoryActsAsBareAgentID is the widened comparison's
// positive case. The caller signs "https://agent.example" and names the bare
// "agent.example" as requester.id — two spellings of one host, constructed
// independently: the header by its outbound signer, the field by its client.
//
// Byte-exact this is an impersonation attempt and returns PermissionDenied. It
// must now succeed and reach the Exchange.
func TestResolve_SchemedDirectoryActsAsBareAgentID(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const host = "agent.example"
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, host, pub)
	// Sign the SCHEMED directory; claim the BARE host.
	client := signingBrokerClient(srv.base, srv.server.URL, "https://"+host, priv)

	_, err := client.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest(host, reqOpts{query: "RAMP intro"})))
	if err != nil {
		t.Fatalf("schemed Signature-Agent with a bare agent_id naming the same host was refused: %v", err)
	}
	if srv.exchange.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1 — the request did not clear the self-action gate",
			srv.exchange.discoverCalls)
	}
}

// TestResolve_DifferentHostStillImpersonation is the guard on the case above.
// Widening a comparison is only safe if it still separates what it was there to
// separate: two DIFFERENT hosts must stay two identities however they are spelled.
// The caller signs "https://attacker.example" and claims "victim.example".
func TestResolve_DifferentHostStillImpersonation(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, "attacker.example", pub)
	client := signingBrokerClient(srv.base, srv.server.URL, "https://attacker.example", priv)

	_, err := client.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest("victim.example", reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodePermissionDenied)
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("impersonation must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_CallerDirectoryNamingNoHostIsUnauthenticated covers the rejection
// added on the CALLER side. A signature can be valid while the directory it
// commits to is not a host at all — the spec's sf-dictionary form is the stable
// example, since no layer unwraps it. Such a caller has not established who it
// is, so it is refused as an authentication failure and nothing upstream fires.
func TestResolve_CallerDirectoryNamingNoHostIsUnauthenticated(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const host = "dict-form.example"
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, host, pub)
	client := signingBrokerClient(srv.base, srv.server.URL, `agent2="https://`+host+`"`, priv)

	_, err := client.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest(host, reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodeUnauthenticated)
	if srv.exchange.discoverCalls != 0 {
		t.Errorf("a caller whose directory names no host must not reach upstream: discover=%d",
			srv.exchange.discoverCalls)
	}
}

// TestResolve_AgentIDNamingNoHostIsInvalidArgument covers the rejection added on
// the CLAIMED side, and it is a different fault class from the one above: the
// caller authenticated fine, it just sent a requester.id that cannot be an
// identity. That is a malformed field, so it is InvalidArgument and rides the
// offending field name as typed ErrorDetail metadata (ADR-019 §1) rather than
// baked into the message.
func TestResolve_AgentIDNamingNoHostIsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const host = "well-formed.example"
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, host, pub)
	client := signingBrokerClient(srv.base, srv.server.URL, host, priv)

	_, err := client.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest("//"+host, reqOpts{query: "RAMP intro"})))
	assertConnectCodeLocal(t, err, connect.CodeInvalidArgument)
	assertBrokerErrorField(t, err, "field", "agent_id")
	if srv.exchange.discoverCalls != 0 {
		t.Errorf("a request whose agent_id names no host must not reach upstream: discover=%d",
			srv.exchange.discoverCalls)
	}
}

// TestResolve_SpellingsShareOneBudgetCounter is the reason the canonical identity
// is written BACK onto the request rather than compared and dropped.
//
// The per-agent spend counter, the selection_log row and the requester.id relayed
// to the Exchange all key on req.AgentID. Normalizing only inside the gate would
// leave every one of them keyed on the caller's spelling: authorization would say
// two spellings are one agent while the counter gave each its own bucket, so an
// agent would hold as many independent period caps as it cared to spell.
//
// Observed entirely through the public Resolve RPC. The cap admits ONE offer and
// not two, so:
//
//	call 1, bare host        -> allowed  (offer_groups populated)
//	call 2, schemed spelling -> REFUSED  (the typed NOT_AUTHORIZED absence_reason)
//
// If the two spellings held separate counters, call 2 would be allowed and this
// fails. The budget cap is caller-declared, so what this pins is exactly one
// thing: an agent cannot escape its OWN declared ceiling by respelling its id.
//
// It does NOT observe the selection_log row or the requester.id forwarded
// upstream, both of which key on the same field. The forwarded id is pinned by
// TestResolve_ForwardsCanonicalRequesterID below; the audit row has no public read
// surface and stays unpinned rather than reached for past the RPC.
func TestResolve_SpellingsShareOneBudgetCounter(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const host = "one-budget.example"
	// The fixture's offer charges unit_cost x estimated_quantity = $0.10 x 42 =
	// $4.20, so a $6.00 cap admits the first resolve and leaves the second
	// projected at $8.40, over the limit.
	const capMinor = 600

	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, host, pub)

	bare := signingBrokerClient(srv.base, srv.server.URL, host, priv)
	first, err := bare.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest(host, reqOpts{query: "RAMP intro", budgetMinor: capMinor})))
	if err != nil {
		t.Fatalf("first resolve (bare spelling, under cap): %v", err)
	}
	if len(first.Msg.GetOfferGroups()) == 0 {
		t.Fatalf("first resolve returned no offer_groups (absence_reason=%v); "+
			"it must be ALLOWED or the second call proves nothing", first.Msg.GetAbsenceReason())
	}

	// Same agent, same key, schemed spelling on BOTH the signed header and the
	// claimed requester.id — the shape an agent would use to buy a second bucket.
	schemed := signingBrokerClient(srv.base, srv.server.URL, "https://"+host, priv)
	second, err := schemed.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest("https://"+host, reqOpts{query: "RAMP intro", budgetMinor: capMinor})))
	if err != nil {
		t.Fatalf("second resolve (schemed spelling): %v", err)
	}
	if len(second.Msg.GetOfferGroups()) != 0 {
		t.Fatalf("the schemed spelling was allowed a second licensed offer under a cap that "+
			"admits one — it holds its own budget counter (offer_groups=%d)",
			len(second.Msg.GetOfferGroups()))
	}
	if got := second.Msg.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Errorf("absence_reason = %v, want NOT_AUTHORIZED (the budget refusal)", got)
	}
}

// TestResolve_ForwardsCanonicalRequesterID pins the other half of why the
// canonical identity is written BACK onto the request rather than compared and
// dropped: the value that travels upstream is the identity, not the spelling the
// caller happened to use.
//
// The caller signs and claims the schemed form throughout. The Exchange must see
// the bare host — otherwise the Exchange keys its own agent row, its transaction
// log and its billing on a spelling the Broker already decided was the same party,
// and the two services disagree about who transacted.
//
// What this guards is the leg BETWEEN the gate and the Exchange, and only that.
// Corrupting the canonical value itself is caught earlier and more loudly, because
// authorizeAgentSelfAct re-reads the same field and refuses — verified by mutation.
// So this fails for a relay that re-derives the id, forwards a different field, or
// reinstates the caller's spelling on the way out, none of which the gate can see.
//
// Observed at the mock Exchange, which is the surface the forwarded request
// actually reaches; nothing here reads past the RPC.
func TestResolve_ForwardsCanonicalRequesterID(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const host = "forwarded-id.example"
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, host, pub)

	// Schemed on the signed header AND in the claimed requester.id.
	client := signingBrokerClient(srv.base, srv.server.URL, "https://"+host, priv)
	resp, err := client.Resolve(ctx, connect.NewRequest(
		buildDiscoveryRequest("https://"+host, reqOpts{query: "RAMP intro"})))
	if err != nil {
		t.Fatalf("resolve with the schemed spelling: %v", err)
	}
	if len(resp.Msg.GetOfferGroups()) == 0 {
		t.Fatalf("resolve returned no offer_groups (absence_reason=%v); it must be ALLOWED "+
			"or nothing was forwarded to observe", resp.Msg.GetAbsenceReason())
	}
	if srv.exchange.discoverCalls != 1 {
		t.Fatalf("discover calls = %d, want 1", srv.exchange.discoverCalls)
	}
	if got := srv.exchange.lastDiscoverRequesterID; got != host {
		t.Errorf("forwarded requester.id = %q, want %q — the Broker canonicalized the "+
			"identity for its own gate but relayed the caller's spelling, so the Exchange "+
			"keys its agent row and its ledger on a different party than the Broker "+
			"authorized", got, host)
	}
}
