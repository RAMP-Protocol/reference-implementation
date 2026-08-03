// Package oidcup is the upstream-OIDC leg of the sign-up flow: the Identity
// Service acts as an OAuth client of Zitadel to authenticate the developer, then
// issues its own downstream code and token. It exposes a narrow Authenticator port
// so the auth-server handlers depend on an interface a test can fake — standing up
// a real Zitadel is a Tier-B E2E concern, not a unit-test one. The production
// implementation wraps go-oidc (discovery + ID-token verification) and x/oauth2
// (authorize URL + code exchange).
package oidcup

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims is the subset of the verified upstream ID token the sign-up consumes. The
// (Issuer, Subject) pair is the developer's durable OIDC identity; Email and Name
// seed the agent's card.
type Claims struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
}

// Authenticator is the upstream port the auth-server handlers depend on.
type Authenticator interface {
	// AuthCodeURL builds the upstream authorize URL carrying state, an OIDC nonce,
	// and the S256 PKCE challenge for the upstream leg. The caller owns the PKCE
	// pair (it stashes the verifier in a cookie) and passes the challenge here.
	AuthCodeURL(state, nonce, challenge string) string
	// Exchange trades code for tokens against the upstream, verifies the ID token's
	// signature/issuer/audience, checks the nonce matches, and returns the claims.
	Exchange(ctx context.Context, code, verifier, nonce string) (Claims, error)
}

// ErrExchange marks any failure of the upstream leg — a rejected code, an ID token
// that will not verify, or a nonce mismatch (a replayed or cross-session token).
var ErrExchange = errors.New("oidcup: upstream exchange failed")

// Config wires a Zitadel authenticator.
type Config struct {
	// Issuer is the OIDC issuer URL; go-oidc discovers endpoints and the JWKS from
	// its /.well-known/openid-configuration.
	Issuer string
	// ClientID and ClientSecret are the STATIC confidential client the operator
	// pre-registers in Zitadel (Zitadel v3 has no Dynamic Client Registration, so
	// this leg cannot self-register the way our downstream clients do).
	ClientID     string
	ClientSecret string
	// RedirectURL is this service's own /callback.
	RedirectURL string
	// Scopes defaults to openid+profile+email when empty.
	Scopes []string
}

// Zitadel is the production Authenticator over go-oidc + oauth2.
type Zitadel struct {
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

var _ Authenticator = (*Zitadel)(nil)

// New builds a Zitadel authenticator, performing OIDC discovery against the issuer.
func New(ctx context.Context, cfg Config) (*Zitadel, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidcup: Issuer, ClientID, and RedirectURL are required")
	}
	// The upstream client is a static confidential client (Zitadel v3 has no DCR);
	// a missing secret otherwise fails only at the first real code exchange, so
	// require it up front rather than degrade to a public-client posture silently.
	if cfg.ClientSecret == "" {
		return nil, errors.New("oidcup: ClientSecret is required for the confidential upstream client")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcup: discover %q: %w", cfg.Issuer, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &Zitadel{
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
	}, nil
}

// AuthCodeURL implements Authenticator.
func (z *Zitadel) AuthCodeURL(state, nonce, challenge string) string {
	return z.oauth.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange implements Authenticator.
func (z *Zitadel) Exchange(ctx context.Context, code, verifier, nonce string) (Claims, error) {
	tok, err := z.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: code exchange: %w", ErrExchange, err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Claims{}, fmt.Errorf("%w: token response carried no id_token", ErrExchange)
	}
	idt, err := z.verifier.Verify(ctx, rawID)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: verify id_token: %w", ErrExchange, err)
	}
	if idt.Nonce != nonce {
		return Claims{}, fmt.Errorf("%w: nonce mismatch", ErrExchange)
	}
	return claimsFrom(idt)
}

// claimsFrom pulls the profile members off the verified token, tolerating their
// absence (a card field simply stays empty).
func claimsFrom(idt *oidc.IDToken) (Claims, error) {
	var profile struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idt.Claims(&profile); err != nil {
		return Claims{}, fmt.Errorf("%w: decode claims: %w", ErrExchange, err)
	}
	return Claims{
		Issuer:  idt.Issuer,
		Subject: idt.Subject,
		Email:   profile.Email,
		Name:    profile.Name,
	}, nil
}
