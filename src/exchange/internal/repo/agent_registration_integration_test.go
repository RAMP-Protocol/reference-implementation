//go:build integration

package repo_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid/agentidtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// These are persistence round-trips (repo → sqlc → Postgres and back) that
// arrange and assert through the production repository surfaces. They stay at
// the repository tier deliberately: what they pin is the guarded UPDATE's
// first-write-wins behaviour and its winner flag, which no RPC exposes — Register
// answers the same billing_ref to the winner and the loser, so a test driven
// through it could not tell the two apart. The accepted terms digest has no
// public read surface at all, which is filed as its own task.

// setBillingRef drives AgentRepo.SetBillingRef through a real transaction, which
// is the only way to call it: the method takes a pgx.Tx because its production
// caller writes an audit row in the same commit. It returns the same three
// values the port does, so each test reads the winner flag itself.
func setBillingRef(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool, agents repo.AgentRepo,
	agentID, billingRef string, digest *string,
) (repo.Agent, bool, error) {
	t.Helper()
	var (
		got repo.Agent
		won bool
	)
	err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var terr error
		got, won, terr = agents.SetBillingRef(ctx, tx, agentID, billingRef, digest)
		return terr
	})
	return got, won, err
}

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
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))
	const agentID = "agent.example.com"
	seeded := seedAgent(t, ctx, agents, agentID, 0x01)
	if seeded.BillingRef != "" {
		t.Fatalf("fresh agent BillingRef = %q, want empty (not registered yet)", seeded.BillingRef)
	}
	if seeded.AcceptedTermsDigest != nil {
		t.Fatalf("fresh agent AcceptedTermsDigest = %q, want nil (nothing accepted yet)",
			*seeded.AcceptedTermsDigest)
	}

	digest := "sha256:" + strings.Repeat("a", 64)
	got, won, err := setBillingRef(t, ctx, pool, agents, agentID, "br-fresh", &digest)
	if err != nil {
		t.Fatalf("SetBillingRef: %v", err)
	}
	if !won {
		t.Error("SetBillingRef reported it did not win; the first write on a fresh agent must win")
	}
	if got.BillingRef != "br-fresh" {
		t.Errorf("SetBillingRef returned BillingRef = %q, want %q", got.BillingRef, "br-fresh")
	}
	if got.AcceptedTermsDigest == nil || *got.AcceptedTermsDigest != digest {
		t.Errorf("SetBillingRef returned AcceptedTermsDigest = %v, want %q",
			got.AcceptedTermsDigest, digest)
	}

	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID after SetBillingRef: %v", err)
	}
	if back.BillingRef != "br-fresh" {
		t.Errorf("ByID BillingRef = %q, want %q", back.BillingRef, "br-fresh")
	}
	if back.AcceptedTermsDigest == nil || *back.AcceptedTermsDigest != digest {
		t.Errorf("ByID AcceptedTermsDigest = %v, want %q", back.AcceptedTermsDigest, digest)
	}
}

// TestSetBillingRefWithNoPublishedDigestStoresNull is the other half of the
// digest column's contract. An Exchange that publishes no terms digest records
// none, and the column stays NULL rather than holding an empty string — those
// are different states, and only NULL says "nothing was published to accept".
func TestSetBillingRefWithNoPublishedDigestStoresNull(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))
	const agentID = "nodigest.example.com"
	seedAgent(t, ctx, agents, agentID, 0x01)

	if _, _, err := setBillingRef(t, ctx, pool, agents, agentID, "br-nodigest", nil); err != nil {
		t.Fatalf("SetBillingRef: %v", err)
	}
	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if back.BillingRef != "br-nodigest" {
		t.Errorf("BillingRef = %q, want %q", back.BillingRef, "br-nodigest")
	}
	if back.AcceptedTermsDigest != nil {
		t.Errorf("AcceptedTermsDigest = %q, want nil", *back.AcceptedTermsDigest)
	}
}

// TestUpsertPreservesBillingRefOnKeyRotation is the ADR-021 D3 promise: a key
// rotation re-upsert of the same agent_id replaces the public key but leaves
// the stored billing_ref intact, because UpsertAgent's update list does not
// include billing_ref.
func TestUpsertPreservesBillingRefOnKeyRotation(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))
	const agentID = "rotating.example.com"
	seedAgent(t, ctx, agents, agentID, 0x01)
	digest := "sha256:" + strings.Repeat("b", 64)
	if _, _, err := setBillingRef(t, ctx, pool, agents, agentID, "br-rotation", &digest); err != nil {
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
	if back.AcceptedTermsDigest == nil || *back.AcceptedTermsDigest != digest {
		t.Errorf("AcceptedTermsDigest after rotation = %v, want preserved %q — UpsertAgent must "+
			"not touch the recorded acceptance either", back.AcceptedTermsDigest, digest)
	}
}

// TestSetBillingRefRepeatKeepsStoredRef: a second write with a different
// value is a no-op — the guarded UPDATE matches zero rows and the repo
// re-reads the row, so the originally stored ref wins (ADR-021 D4).
func TestSetBillingRefRepeatKeepsStoredRef(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))
	const agentID = "repeat.example.com"
	seedAgent(t, ctx, agents, agentID, 0x01)
	first := "sha256:" + strings.Repeat("c", 64)
	if _, won, err := setBillingRef(t, ctx, pool, agents, agentID, "br-first", &first); err != nil {
		t.Fatalf("first SetBillingRef: %v", err)
	} else if !won {
		t.Fatal("first SetBillingRef reported it did not win")
	}

	second := "sha256:" + strings.Repeat("d", 64)
	again, won, err := setBillingRef(t, ctx, pool, agents, agentID, "br-second", &second)
	if err != nil {
		t.Fatalf("repeat SetBillingRef: %v", err)
	}
	if won {
		t.Error("repeat SetBillingRef reported it won; the guarded UPDATE matched zero rows, so " +
			"its caller must not record a second registration")
	}
	if again.BillingRef != "br-first" {
		t.Errorf("repeat SetBillingRef returned %q, want stored %q", again.BillingRef, "br-first")
	}
	if again.AcceptedTermsDigest == nil || *again.AcceptedTermsDigest != first {
		t.Errorf("repeat SetBillingRef returned AcceptedTermsDigest = %v, want stored %q",
			again.AcceptedTermsDigest, first)
	}

	back, err := agents.ByID(ctx, agentID)
	if err != nil {
		t.Fatalf("ByID after repeat: %v", err)
	}
	if back.BillingRef != "br-first" {
		t.Errorf("stored BillingRef = %q, want unchanged %q", back.BillingRef, "br-first")
	}
	if back.AcceptedTermsDigest == nil || *back.AcceptedTermsDigest != first {
		t.Errorf("stored AcceptedTermsDigest = %v, want unchanged %q — both columns are written "+
			"by one guarded statement, so first-write-wins covers them together",
			back.AcceptedTermsDigest, first)
	}
}

// TestSetBillingRefUnknownAgent drives the failure path through the same
// surface: no agent row means no write and the repo's not-found error.
func TestSetBillingRefUnknownAgent(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))

	_, _, err := setBillingRef(t, ctx, pool, agents, "ghost.example.com", "br-x", nil)
	if !errors.Is(err, repo.ErrAgentNotFound) {
		t.Fatalf("SetBillingRef(unknown agent) error = %v, want ErrAgentNotFound", err)
	}
}

// TestTenantActivateNewAgentsByDefault drives the activation policy through the
// tenant repository ports: read TRUE on a fresh tenant with TenantReadRepo, flip
// it with TenantWriteRepo.SetActivateNewAgentsByDefault, read FALSE back. The
// write port is the highest surface that reaches this column — no admin RPC
// writes it — and the missing public surface is filed as its own task.
//
// The tenant seed still uses sqlc InsertTenant. That is a raw-sqlc arrange the
// Testing Doctrine forbids, held open here rather than fixed: no production
// code inserts tenants (they are provisioned by operator SQL), so a repository
// insert port would exist only for tests, and many arrange sites across the
// tree share this shape. Converting them behind a real tenant-provisioning
// surface is filed as its own task.
func TestTenantActivateNewAgentsByDefault(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	q := sqlc.New(pool)
	const tenantID = "t-activation"
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: tenantID, Domain: "activation.example.com", Ed25519KeyRef: "k",
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

	writer := repo.NewTenantWriteRepo(q)
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		n, err := writer.SetActivateNewAgentsByDefault(ctx, tx, tenantID, false)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("rows affected = %d, want 1", n)
		}
		return nil
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

	// A write for a tenant that does not exist reports 0 rows affected instead
	// of succeeding silently. This is what the query's :execrows annotation
	// buys: with :exec the call below would be indistinguishable from a real
	// update, and a typo in a tenant id would look like a working flip.
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		n, err := writer.SetActivateNewAgentsByDefault(ctx, tx, "t-does-not-exist", false)
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("rows affected = %d, want 0 for a missing tenant", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("flip activation default for a missing tenant: %v", err)
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
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))

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
	if _, _, err := setBillingRef(
		t, ctx, pool, agents, "HTTPS://REPO-CANON.EXAMPLE", "br-canon", nil,
	); err != nil {
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
	pool := newTestPool(t, ctx)
	agents := repo.NewAgentRepo(sqlc.New(pool))

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
			if _, _, err := setBillingRef(
				t, ctx, pool, agents, bad, "br-x", nil,
			); !errors.Is(err, repo.ErrAgentIDNotAHost) {
				t.Errorf("SetBillingRef(%q) = %v; want ErrAgentIDNotAHost", bad, err)
			}
		})
	}
}
