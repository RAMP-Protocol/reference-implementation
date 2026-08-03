//go:build integration

package repo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

func TestOAuthRepo_RegisterThenClientByID(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	in := oauth.Client{
		ID:           "mcp-abc",
		RedirectURIs: []string{"http://127.0.0.1:5153/callback", "http://localhost:5153/callback"},
		Name:         "Claude Code",
	}
	if _, err := r.RegisterClient(ctx, in); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := r.ClientByID(ctx, in.ID)
	if err != nil {
		t.Fatalf("ClientByID: %v", err)
	}
	if got.Name != in.Name || len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != in.RedirectURIs[0] {
		t.Errorf("ClientByID = %+v, want %+v", got, in)
	}
}

func TestOAuthRepo_ClientByIDNotFound(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	if _, err := r.ClientByID(ctx, "nope"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("ClientByID err = %v, want ErrClientNotFound", err)
	}
}

func TestOAuthRepo_IssueThenConsume(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	code := oauth.Code{
		ClientID:      "mcp-abc",
		RedirectURI:   "http://127.0.0.1:5153/callback",
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Subject:       "agent-xyz.rampmcp.org",
		ExpiresAt:     exp,
	}
	if err := r.IssueCode(ctx, "hash-1", code); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}

	got, err := r.ConsumeCode(ctx, "hash-1")
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.ClientID != code.ClientID || got.RedirectURI != code.RedirectURI ||
		got.PKCEChallenge != code.PKCEChallenge || got.Subject != code.Subject {
		t.Errorf("ConsumeCode returned %+v, want bound fields from %+v", got, code)
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("ConsumeCode expiry = %v, want %v", got.ExpiresAt, exp)
	}
}

func TestOAuthRepo_GetCodePeeksWithoutConsuming(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	code := oauth.Code{
		ClientID:      "mcp-abc",
		RedirectURI:   "http://127.0.0.1:5153/callback",
		PKCEChallenge: "chal",
		Subject:       "agent-xyz.rampmcp.org",
		ExpiresAt:     exp,
	}
	if err := r.IssueCode(ctx, "hash-peek", code); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}

	// GetCode returns the bound fields without spending the code — so a following
	// ConsumeCode still succeeds (validate-before-burn is what protects a stolen
	// code presented with a wrong verifier).
	got, err := r.GetCode(ctx, "hash-peek")
	if err != nil {
		t.Fatalf("GetCode: %v", err)
	}
	if got.ClientID != code.ClientID || got.PKCEChallenge != code.PKCEChallenge ||
		got.Subject != code.Subject || !got.ExpiresAt.Equal(exp) {
		t.Errorf("GetCode returned %+v, want bound fields from %+v", got, code)
	}
	if _, err := r.ConsumeCode(ctx, "hash-peek"); err != nil {
		t.Fatalf("ConsumeCode after peek must still redeem: %v", err)
	}
	// After the burn the row is still peekable (the peek does not filter on
	// consumed); the single-use guarantee lives in ConsumeCode, verified above.
	if _, err := r.GetCode(ctx, "hash-peek"); err != nil {
		t.Fatalf("GetCode after consume: %v", err)
	}
}

func TestOAuthRepo_GetCodeUnknownNotFound(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	if _, err := r.GetCode(ctx, "never-issued"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("GetCode err = %v, want ErrCodeNotFound", err)
	}
}

func TestOAuthRepo_ConsumeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	code := oauth.Code{
		ClientID:      "mcp-abc",
		RedirectURI:   "http://127.0.0.1:5153/callback",
		PKCEChallenge: "chal",
		Subject:       "agent-xyz.rampmcp.org",
		ExpiresAt:     time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := r.IssueCode(ctx, "hash-2", code); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	if _, err := r.ConsumeCode(ctx, "hash-2"); err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	// A replay of the same code must not redeem a second token.
	if _, err := r.ConsumeCode(ctx, "hash-2"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("second ConsumeCode err = %v, want ErrCodeNotFound", err)
	}
}

func TestOAuthRepo_ConsumeUnknownNotFound(t *testing.T) {
	ctx := context.Background()
	r := repo.NewOAuthRepo(acquireTestDB(t, ctx))
	if _, err := r.ConsumeCode(ctx, "never-issued"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("ConsumeCode err = %v, want ErrCodeNotFound", err)
	}
}
