//go:build integration

package repo_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

// These tests arrange and assert through the production repository interface
// rather than through a public read surface, which is the documented fallback
// and a corner being cut. It is recorded here rather than left implicit.
//
// Part of what this file covers DOES have a public reader, and is covered
// through it in the MCP package: list membership by TestStatus_HintsAreScoped-
// ToTheCallingAgent, and the delete-on-contradiction by
// TestStatus_ForgetsAHintTheExchangeContradicts, both driving ramp_status with
// no exchange argument.
//
// Two properties have no public reader at all. Which notes survive the
// MaxExchangeRegistrations cap, and that refreshing an existing note does not
// trim the set, are invisible to every surface an agent can reach — an agent can
// hit the cap today with no way to learn its list was trimmed. That gap is the
// design signal here: it wants a public read over the bounded set, and until
// there is one these two assertions have nowhere else to go.

// anchorTime is a fixed instant the notes are written at, so a test asserts the
// value the caller chose rather than whatever the database's clock said.
var anchorTime = time.Date(2026, 8, 20, 10, 11, 12, 0, time.UTC)

// signedUp reserves a developer so its subdomain exists for the notes to hang
// off. The foreign key is the retention rule, so every test here goes through
// the same production surface that creates one.
func signedUp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	subdomain := slug + ".rampmcp.org"
	_, err := repo.NewDeveloperRepo(pool).Reserve(ctx, account.Developer{
		Issuer:    "https://login.example",
		Subject:   slug,
		Email:     slug + "@operator.example",
		Subdomain: subdomain,
	})
	if err != nil {
		t.Fatalf("Reserve %s: %v", slug, err)
	}
	return subdomain
}

func TestExchangeRegistrationRepo_RecordListForget(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)
	agent := signedUp(t, ctx, pool, "agent-one")

	// An agent that has registered nowhere reads as an empty list, not a miss.
	empty, err := r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List before any note: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("List returned %d notes for an agent with none", len(empty))
	}

	// Ordered by domain, not by insertion, so the answer is stable.
	if err = r.Record(ctx, agent, "exchange-b.example:8081", anchorTime); err != nil {
		t.Fatalf("Record b: %v", err)
	}
	if err = r.Record(ctx, agent, "exchange-a.example", anchorTime); err != nil {
		t.Fatalf("Record a: %v", err)
	}
	notes, err := r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("List returned %d notes, want 2", len(notes))
	}
	if notes[0].Exchange != "exchange-a.example" || notes[1].Exchange != "exchange-b.example:8081" {
		t.Fatalf("notes are not ordered by domain: %+v", notes)
	}
	if !notes[0].RegisteredAt.Equal(anchorTime) {
		t.Errorf("registered_at = %s, want the caller's %s", notes[0].RegisteredAt, anchorTime)
	}

	// Forgetting one leaves the other. This is the path a status call takes when
	// the Exchange itself reports no account.
	if err = r.Forget(ctx, agent, "exchange-a.example"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	notes, err = r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List after Forget: %v", err)
	}
	if len(notes) != 1 || notes[0].Exchange != "exchange-b.example:8081" {
		t.Fatalf("after forgetting one, notes = %+v", notes)
	}

	// Forgetting what is not there is a success: the caller wanted no note, and
	// there is none.
	if err = r.Forget(ctx, agent, "never-registered.example"); err != nil {
		t.Fatalf("Forget an absent note: %v", err)
	}
}

// TestExchangeRegistrationRepo_RepeatRefreshesRatherThanDuplicates pins the
// upsert. A status call refreshes the note on every confirmation, so a second
// write must move the timestamp rather than add a row — otherwise the hint list
// would grow one entry per status call.
func TestExchangeRegistrationRepo_RepeatRefreshesRatherThanDuplicates(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)
	agent := signedUp(t, ctx, pool, "agent-two")

	later := anchorTime.Add(72 * time.Hour)
	for _, at := range []time.Time{anchorTime, later} {
		if err := r.Record(ctx, agent, "exchange.example", at); err != nil {
			t.Fatalf("Record at %s: %v", at, err)
		}
	}
	notes, err := r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("two writes for one Exchange produced %d notes, want 1", len(notes))
	}
	if !notes[0].RegisteredAt.Equal(later) {
		t.Errorf("registered_at = %s, want the later %s", notes[0].RegisteredAt, later)
	}
}

// TestExchangeRegistrationRepo_NotesAreScopedToTheirAgent pins that one agent's
// notes are not another's. The list is read on a call authenticated as one
// agent, so a leak here would tell that agent where a different operator does
// business.
func TestExchangeRegistrationRepo_NotesAreScopedToTheirAgent(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)
	one := signedUp(t, ctx, pool, "agent-three")
	two := signedUp(t, ctx, pool, "agent-four")

	if err := r.Record(ctx, one, "exchange.example", anchorTime); err != nil {
		t.Fatalf("Record: %v", err)
	}
	notes, err := r.List(ctx, two)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("an agent that registered nowhere sees %+v", notes)
	}
}

// TestExchangeRegistrationRepo_NoNoteWithoutAnAgent asserts the half of the
// foreign key that this layer can drive: a note cannot exist without the
// developer account it belongs to.
//
// The other half — the notes going WITH that account when it is deleted — is the
// ON DELETE CASCADE clause, and it is not observable here. There is no
// agent-deletion flow to drive it through, and issuing a DELETE from a test
// would be arranging state past every layer that owns it. It is pinned
// structurally instead, by the guard over the migration in internal/guards.
func TestExchangeRegistrationRepo_NoNoteWithoutAnAgent(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)

	// A note for an agent that never signed up cannot be written at all: there is
	// no record for it to live as long as.
	err := r.Record(ctx, "ghost.rampmcp.org", "exchange.example", anchorTime)
	if err == nil {
		t.Fatal("a note was recorded for a subdomain no developer account owns")
	}
}

// TestExchangeRegistrationRepo_BoundedPerAgent is the cap under test. The
// exchange half of the key is a value an authenticated agent chooses per call,
// so without this bound the note set is somewhere a caller can make the table
// grow — and the status call adds a row without the agent completing a
// registration at all.
//
// Driven one past the cap, and asserting BOTH halves: the set stays at the cap,
// and what survives is the most recent rather than an arbitrary subset. The
// second half is what makes the note useful after a trim; dropping the newest
// would keep the count right and the content wrong.
func TestExchangeRegistrationRepo_BoundedPerAgent(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)
	agent := signedUp(t, ctx, pool, "agent-many")

	// One note per minute, oldest first, so "most recent" is unambiguous and does
	// not depend on how the rows happen to be stored.
	const over = account.MaxExchangeRegistrations + 1
	for i := range over {
		at := anchorTime.Add(time.Duration(i) * time.Minute)
		if err := r.Record(ctx, agent, exchangeN(i), at); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	notes, err := r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(notes) != account.MaxExchangeRegistrations {
		t.Fatalf("agent holds %d notes after %d registrations, want the cap %d",
			len(notes), over, account.MaxExchangeRegistrations)
	}
	held := make(map[string]bool, len(notes))
	for _, note := range notes {
		held[note.Exchange] = true
	}
	// The very first is the one that had to go, and the very last must be there:
	// it is the write that pushed the set over.
	if held[exchangeN(0)] {
		t.Errorf("the oldest note survived the cap; %s should have been dropped", exchangeN(0))
	}
	if !held[exchangeN(over-1)] {
		t.Errorf("the newest note is missing; %s is the write that trimmed the set", exchangeN(over-1))
	}
}

// TestExchangeRegistrationRepo_RefreshingDoesNotTrim pins that a repeat is not a
// new note. An agent sitting at the cap re-confirms one of its Exchanges on
// every status call, and a refresh that counted as an arrival would evict a
// different Exchange each time until only one was left.
func TestExchangeRegistrationRepo_RefreshingDoesNotTrim(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	r := repo.NewExchangeRegistrationRepo(pool)
	agent := signedUp(t, ctx, pool, "agent-full")

	for i := range account.MaxExchangeRegistrations {
		if err := r.Record(ctx, agent, exchangeN(i), anchorTime.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	// Re-confirm the OLDEST, which is the one a trim would drop.
	later := anchorTime.Add(24 * time.Hour)
	if err := r.Record(ctx, agent, exchangeN(0), later); err != nil {
		t.Fatalf("refresh oldest: %v", err)
	}

	notes, err := r.List(ctx, agent)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(notes) != account.MaxExchangeRegistrations {
		t.Fatalf("a refresh changed the set size to %d, want the cap %d",
			len(notes), account.MaxExchangeRegistrations)
	}
	for _, note := range notes {
		if note.Exchange == exchangeN(0) && !note.RegisteredAt.Equal(later) {
			t.Errorf("the refreshed note still reads %s, want %s", note.RegisteredAt, later)
		}
	}
}

// exchangeN names one distinct Exchange. Zero-padded so the domain order and the
// arrival order agree, which keeps a failure message readable.
func exchangeN(i int) string {
	return fmt.Sprintf("exchange-%03d.example", i)
}
