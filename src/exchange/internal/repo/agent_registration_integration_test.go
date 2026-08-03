//go:build integration

package repo_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid/agentidtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// These are persistence round-trips (repo → sqlc → Postgres and back) that
// arrange and assert through the production repository surfaces. No public
// RPC reads billing_ref yet — the Register handler is the pending
// public surface — so the repo interface is the sanctioned Testing Doctrine
// §9 tier-2 fallback until it lands.

// seedAgent registers an agent through the production write surface
// (AgentRepo.Upsert), the same path the httpsig registry uses.
func seedAgent(t *testing.T, ctx context.Context, agents repo.AgentRepo, id string, key byte) repo.Agent {
	t.Helper()
	a, err := agents.Upsert(ctx, repo.Agent{ID: id, PublicKey: []byte{key}, RequesterType: "AGENT"})
	if err != nil {
		t.Fatalf("seed agent %s: %v", id, err)
	}
	return a
}

// TestSetBillingRefSetsAndReturns drives the first billing_ref write for a
// fresh agent and reads it back through the same repo surface.
func TestSetBillingRefSetsAndReturns(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))
	const agentID = "agent.example.com"
	if seeded := seedAgent(t, ctx, agents, agentID, 0x01); seeded.BillingRef != "" {
		t.Fatalf("fresh agent BillingRef = %q, want empty (not registered yet)", seeded.BillingRef)
	}

	got, err := agents.SetBillingRef(ctx, agentID, "br-fresh")
	if err != nil {
		t.Fatalf("SetBillingRef: %v", err)
	}
	if got.BillingRef != "br-fresh" {
		t.Errorf("SetBillingRef returned BillingRef = %q, want %q", got.BillingRef, "br-fresh")
	}

	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID after SetBillingRef: %v", err)
	}
	if back.BillingRef != "br-fresh" {
		t.Errorf("ByID BillingRef = %q, want %q", back.BillingRef, "br-fresh")
	}
}

// TestUpsertPreservesBillingRefOnKeyRotation is the ADR-021 D3 promise: a key
// rotation re-upsert of the same agent_id replaces the public key but leaves
// the stored billing_ref intact, because UpsertAgent's update list does not
// include billing_ref.
func TestUpsertPreservesBillingRefOnKeyRotation(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))
	const agentID = "rotating.example.com"
	seedAgent(t, ctx, agents, agentID, 0x01)
	if _, err := agents.SetBillingRef(ctx, agentID, "br-rotation"); err != nil {
		t.Fatalf("SetBillingRef: %v", err)
	}

	rotated, err := agents.Upsert(ctx, repo.Agent{
		ID: agentID, PublicKey: []byte{0x02}, RequesterType: "AGENT",
	})
	if err != nil {
		t.Fatalf("Upsert with rotated key: %v", err)
	}
	if rotated.BillingRef != "br-rotation" {
		t.Errorf("Upsert returned BillingRef = %q, want preserved %q", rotated.BillingRef, "br-rotation")
	}

	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID after rotation: %v", err)
	}
	if !bytes.Equal(back.PublicKey, []byte{0x02}) {
		t.Errorf("PublicKey after rotation = %x, want 02", back.PublicKey)
	}
	if back.BillingRef != "br-rotation" {
		t.Errorf("BillingRef after rotation = %q, want preserved %q", back.BillingRef, "br-rotation")
	}
}

// TestSetBillingRefRepeatKeepsStoredRef: a second write with a different
// value is a no-op — the guarded UPDATE matches zero rows and the repo
// re-reads the row, so the originally stored ref wins (ADR-021 D4).
func TestSetBillingRefRepeatKeepsStoredRef(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))
	const agentID = "repeat.example.com"
	seedAgent(t, ctx, agents, agentID, 0x01)
	if _, err := agents.SetBillingRef(ctx, agentID, "br-first"); err != nil {
		t.Fatalf("first SetBillingRef: %v", err)
	}

	again, err := agents.SetBillingRef(ctx, agentID, "br-second")
	if err != nil {
		t.Fatalf("repeat SetBillingRef: %v", err)
	}
	if again.BillingRef != "br-first" {
		t.Errorf("repeat SetBillingRef returned %q, want stored %q", again.BillingRef, "br-first")
	}

	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID after repeat: %v", err)
	}
	if back.BillingRef != "br-first" {
		t.Errorf("stored BillingRef = %q, want unchanged %q", back.BillingRef, "br-first")
	}
}

// TestSetBillingRefUnknownAgent drives the failure path through the same
// surface: no agent row means no write and the repo's not-found error.
func TestSetBillingRefUnknownAgent(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))

	if _, err := agents.SetBillingRef(ctx, "ghost.example.com", "br-x"); !errors.Is(err, repo.ErrAgentNotFound) {
		t.Fatalf("SetBillingRef(unknown agent) error = %v, want ErrAgentNotFound", err)
	}
}

// TestTenantActivateNewAgentsByDefault reads the activation policy through
// TenantRepo: TRUE on a fresh tenant, FALSE after the flip. TenantRepo is
// read-only by design (tenant configuration is set out of band), so the flip
// goes through the sqlc SetTenantActivateNewAgentsByDefault fixture mutator —
// the established convention for tenant config columns. The tenant seed uses
// sqlc InsertTenant for the same documented reason: no public
// tenant-provisioning RPC exists yet.
func TestTenantActivateNewAgentsByDefault(t *testing.T) {
	ctx := context.Background()
	q := newTestQueries(t, ctx)
	const tenantID = "t-activation"
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: tenantID, Domain: "activation.example.com", HmacSecretRef: "h", Ed25519KeyRef: "k",
		ReportingPolicy: []byte(`{}`), SigningScheme: sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenants := repo.NewTenantReadRepo(q)

	fresh, err := tenants.ByID(ctx, tenantID)
	if err != nil {
		t.Fatalf("ByID (fresh tenant): %v", err)
	}
	if !fresh.ActivateNewAgentsByDefault {
		t.Error("fresh tenant ActivateNewAgentsByDefault = false, want true (column default)")
	}

	if err := q.SetTenantActivateNewAgentsByDefault(ctx, sqlc.SetTenantActivateNewAgentsByDefaultParams{
		TenantID: tenantID, ActivateNewAgentsByDefault: false,
	}); err != nil {
		t.Fatalf("flip activation default: %v", err)
	}
	flipped, err := tenants.ByID(ctx, tenantID)
	if err != nil {
		t.Fatalf("ByID (after flip): %v", err)
	}
	if flipped.ActivateNewAgentsByDefault {
		t.Error("ActivateNewAgentsByDefault after flip = true, want false")
	}
}

// TestAgentRepo_KeysOnCanonicalHost pins the invariant at its owner. The agents
// table is keyed on an agent's canonical directory host, and that used to hold
// only because six call sites across three layers each remembered to normalize
// before calling in — by audit rather than by construction, so the seventh caller
// would silently create the duplicate row the whole derivation exists to prevent.
//
// Written through the raw spelling, read back through several others, and the
// stored key itself asserted: Agent.ID is the column value the row came back
// with, so it is the identity, not an echo of the argument.
func TestAgentRepo_KeysOnCanonicalHost(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))

	const canonical = "repo-canon.example"
	// Every folding axis at once, on the WRITE side.
	written, err := agents.Upsert(ctx, repo.Agent{
		ID: "https://Repo-Canon.Example:0443", PublicKey: []byte{0x11}, RequesterType: "AGENT",
	})
	if err != nil {
		t.Fatalf("Upsert with a raw spelling: %v", err)
	}
	if written.ID != canonical {
		t.Fatalf("Upsert stored agent_id %q; want %q — the column holds the identity, "+
			"not the spelling the caller happened to use", written.ID, canonical)
	}

	for _, spelling := range []string{
		canonical,
		"https://repo-canon.example",
		"HTTPS://Repo-Canon.Example.",
		"repo-canon.example:443",
		"http://repo-canon.example:80",
	} {
		got, err := agents.ByID(ctx, spelling)
		if err != nil {
			t.Errorf("ByID(%q): %v — this spelling names the same agent", spelling, err)
			continue
		}
		if got.ID != canonical {
			t.Errorf("ByID(%q).ID = %q; want %q", spelling, got.ID, canonical)
		}
	}

	// A second write under yet another spelling must update the one row rather
	// than add a second: the billing ref set on the first survives, which is the
	// consequence that made duplicate rows expensive.
	if _, err := agents.SetBillingRef(ctx, "HTTPS://REPO-CANON.EXAMPLE", "br-canon"); err != nil {
		t.Fatalf("SetBillingRef under another spelling: %v", err)
	}
	again, err := agents.Upsert(ctx, repo.Agent{
		ID: "http://repo-canon.example:80", PublicKey: []byte{0x22}, RequesterType: "AGENT",
	})
	if err != nil {
		t.Fatalf("re-Upsert: %v", err)
	}
	if again.BillingRef != "br-canon" {
		t.Errorf("BillingRef = %q after re-upsert under another spelling; want %q — a second "+
			"row would have carried none", again.BillingRef, "br-canon")
	}
}

// TestAgentRepo_RefusesNonHostAgentID is the negative half. A value that names no
// host can never key a row, so the repo refuses it rather than passing it to SQL,
// where a read would miss silently and a write would create a row nothing can
// reach.
func TestAgentRepo_RefusesNonHostAgentID(t *testing.T) {
	ctx := context.Background()
	agents := repo.NewAgentRepo(newTestQueries(t, ctx))

	// The shared corpus, so a new refusal class added to agentid reaches this layer
	// without anyone remembering this file. The empty string is kept separately: it
	// is a missing value rather than a malformed one, and the corpus draws that line.
	cases := append([]agentidtest.NonHostValue{{Name: "empty", Value: ""}},
		agentidtest.NonHostValues()...)
	for _, tc := range cases {
		bad := tc.Value
		t.Run(tc.Name, func(t *testing.T) {
			if _, err := agents.ByID(ctx, bad); !errors.Is(err, repo.ErrAgentIDNotAHost) {
				t.Errorf("ByID(%q) = %v; want ErrAgentIDNotAHost", bad, err)
			}
			if _, err := agents.Upsert(ctx, repo.Agent{
				ID: bad, PublicKey: []byte{0x33}, RequesterType: "AGENT",
			}); !errors.Is(err, repo.ErrAgentIDNotAHost) {
				t.Errorf("Upsert(%q) = %v; want ErrAgentIDNotAHost — this value would have "+
					"become an agents-table key", bad, err)
			}
			if _, err := agents.SetBillingRef(ctx, bad, "br-x"); !errors.Is(err, repo.ErrAgentIDNotAHost) {
				t.Errorf("SetBillingRef(%q) = %v; want ErrAgentIDNotAHost", bad, err)
			}
		})
	}
}
