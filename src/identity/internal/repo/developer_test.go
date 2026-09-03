//go:build integration

package repo_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

func TestDeveloperRepo_ReserveThenReadBack(t *testing.T) {
	ctx := context.Background()
	r := repo.NewDeveloperRepo(acquireTestDB(t, ctx))
	in := account.Developer{
		Issuer:    "https://zitadel.example",
		Subject:   "user-42",
		Email:     "dev@acme.example",
		Subdomain: "agent-abcd1234.rampmcp.org",
	}

	reserved, err := r.Reserve(ctx, in)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if reserved.Subdomain != in.Subdomain || reserved.Email != in.Email {
		t.Errorf("Reserve returned %+v, want subdomain/email from %+v", reserved, in)
	}
	bySubject, err := r.BySubject(ctx, in.Issuer, in.Subject)
	if err != nil {
		t.Fatalf("BySubject: %v", err)
	}
	if bySubject.Subdomain != in.Subdomain {
		t.Errorf("BySubject subdomain = %q, want %q", bySubject.Subdomain, in.Subdomain)
	}
}

func TestDeveloperRepo_BySubjectNotFound(t *testing.T) {
	ctx := context.Background()
	r := repo.NewDeveloperRepo(acquireTestDB(t, ctx))
	if _, err := r.BySubject(ctx, "https://zitadel.example", "ghost"); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("BySubject err = %v, want ErrNotFound", err)
	}
}

func TestDeveloperRepo_ReserveSubdomainTaken(t *testing.T) {
	ctx := context.Background()
	r := repo.NewDeveloperRepo(acquireTestDB(t, ctx))
	sub := "agent-shared.rampmcp.org"
	if _, err := r.Reserve(ctx, account.Developer{Issuer: "iss", Subject: "first", Subdomain: sub}); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	// A different OIDC identity trying to claim the same slug is rejected as taken,
	// which is the signal the sign-up service retries with a fresh slug on.
	_, err := r.Reserve(ctx, account.Developer{Issuer: "iss", Subject: "second", Subdomain: sub})
	if !errors.Is(err, account.ErrSubdomainTaken) {
		t.Fatalf("Reserve err = %v, want ErrSubdomainTaken", err)
	}
}

func TestDeveloperRepo_ReserveIdentityAlreadyExists(t *testing.T) {
	ctx := context.Background()
	r := repo.NewDeveloperRepo(acquireTestDB(t, ctx))
	d := account.Developer{Issuer: "iss", Subject: "same", Subdomain: "agent-one.rampmcp.org"}
	if _, err := r.Reserve(ctx, d); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	// The same OIDC identity reserving again (a concurrent sign-in that lost the
	// race) is ErrAlreadyExists, distinct from a taken slug — even with a new slug.
	d.Subdomain = "agent-two.rampmcp.org"
	if _, err := r.Reserve(ctx, d); !errors.Is(err, account.ErrAlreadyExists) {
		t.Fatalf("Reserve err = %v, want ErrAlreadyExists", err)
	}
}
