//go:build integration

package repo_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

func TestCardRepo_UpsertThenGet(t *testing.T) {
	ctx := context.Background()
	r := repo.NewCardRepo(acquireTestDB(t, ctx))
	sub := "agent-123.rampmcp.org"
	want := directory.Card{
		ClientName: "Acme Crawler",
		ClientURI:  "https://" + sub,
		Contacts:   []string{"mailto:ops@acme.example"},
		Purpose:    "ai-index",
	}

	stored, err := r.Upsert(ctx, sub, want)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !reflect.DeepEqual(stored, want) {
		t.Errorf("Upsert returned %+v, want %+v", stored, want)
	}

	got, err := r.BySubdomain(ctx, sub)
	if err != nil {
		t.Fatalf("BySubdomain: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BySubdomain returned %+v, want %+v", got, want)
	}
}

func TestCardRepo_BySubdomainNotFound(t *testing.T) {
	ctx := context.Background()
	r := repo.NewCardRepo(acquireTestDB(t, ctx))
	_, err := r.BySubdomain(ctx, "missing.rampmcp.org")
	if !errors.Is(err, directory.ErrCardNotFound) {
		t.Fatalf("BySubdomain err = %v, want ErrCardNotFound", err)
	}
}

func TestCardRepo_UpsertUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	r := repo.NewCardRepo(acquireTestDB(t, ctx))
	sub := "agent-9.rampmcp.org"
	if _, err := r.Upsert(ctx, sub, directory.Card{ClientName: "First", ClientURI: "https://" + sub, Purpose: "ai-index"}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	updated := directory.Card{ClientName: "Second", ClientURI: "https://" + sub, Contacts: []string{"mailto:new@acme.example"}, Purpose: "ai-train"}
	if _, err := r.Upsert(ctx, sub, updated); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	got, err := r.BySubdomain(ctx, sub)
	if err != nil {
		t.Fatalf("BySubdomain: %v", err)
	}
	if !reflect.DeepEqual(got, updated) {
		t.Errorf("after update got %+v, want %+v", got, updated)
	}
}

func TestCardRepo_UpsertNilContactsStoresEmpty(t *testing.T) {
	ctx := context.Background()
	r := repo.NewCardRepo(acquireTestDB(t, ctx))
	sub := "agent-nil.rampmcp.org"
	if _, err := r.Upsert(ctx, sub, directory.Card{ClientName: "NoContacts", ClientURI: "https://" + sub}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := r.BySubdomain(ctx, sub)
	if err != nil {
		t.Fatalf("BySubdomain: %v", err)
	}
	if len(got.Contacts) != 0 {
		t.Errorf("contacts = %v, want empty", got.Contacts)
	}
}
