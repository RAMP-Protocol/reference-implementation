package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// grant owns the OAuth authorization-code lifecycle — issuing a one-time code
// bound to a downstream client, and redeeming it for an access token. It is the
// service seam the /token and /callback handlers sit on: they parse the request,
// call grant, and write the response, so the protocol rules (single-use, expiry,
// client/redirect binding, PKCE) live in one place instead of inline in transport.
type grant struct {
	clients  oauth.Store
	tokens   *token.Issuer
	clk      clock.Clock
	codeTTL  time.Duration
	tokenTTL time.Duration
}

// codeGrant is the downstream authorization-request context a code is minted for:
// the client and exact redirect it is bound to, the PKCE challenge /token will
// re-verify, the client's own state to echo on the redirect, and the subject
// (minted subdomain) the eventual token authenticates.
type codeGrant struct {
	clientID    string
	redirectURI string
	clientState string
	challenge   string
	subject     string
}

// tokenRequest is the parsed authorization-code-grant request /token redeems.
type tokenRequest struct {
	code        string
	verifier    string
	clientID    string
	redirectURI string
}

// grantError is a caller-facing invalid_grant: a well-formed request the server
// refuses (unknown/used code, expired, binding mismatch, failed PKCE). It carries
// the RFC 6749 error_description; the handler renders it as a 400.
type grantError struct{ desc string }

func (e *grantError) Error() string { return "invalid_grant: " + e.desc }

func invalidGrant(desc string) error { return &grantError{desc: desc} }

// issue mints a fresh one-time authorization code bound to cg, stores its hash, and
// returns the opaque code to hand back to the client.
func (g *grant) issue(ctx context.Context, cg codeGrant) (string, error) {
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	err = g.clients.IssueCode(ctx, hashCode(code), oauth.Code{
		ClientID:      cg.clientID,
		RedirectURI:   cg.redirectURI,
		PKCEChallenge: cg.challenge,
		Subject:       cg.subject,
		ExpiresAt:     g.clk.Now().Add(g.codeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// redeem validates req against the stored code and, on success, consumes the code
// (single-use) and mints the access token, returning it with its lifetime. Expiry,
// client/redirect binding, and PKCE are all checked BEFORE the code is consumed, so
// a stolen code presented with a wrong verifier cannot burn the legitimate client's
// code. It returns a *grantError for a caller-facing invalid_grant and a wrapped
// oauth.ErrUnavailable for a transient store outage; the handler maps each.
func (g *grant) redeem(ctx context.Context, req tokenRequest) (accessToken string, ttl time.Duration, err error) {
	stored, err := g.clients.GetCode(ctx, hashCode(req.code))
	if err != nil {
		if errors.Is(err, oauth.ErrCodeNotFound) {
			return "", 0, invalidGrant("unknown or already-used authorization code")
		}
		return "", 0, err
	}
	if g.clk.Now().After(stored.ExpiresAt) {
		return "", 0, invalidGrant("authorization code expired")
	}
	if stored.ClientID != req.clientID || stored.RedirectURI != req.redirectURI {
		return "", 0, invalidGrant("client_id or redirect_uri mismatch")
	}
	if !verifyPKCE(stored.PKCEChallenge, req.verifier) {
		return "", 0, invalidGrant("PKCE verification failed")
	}
	if _, err := g.clients.ConsumeCode(ctx, hashCode(req.code)); err != nil {
		if errors.Is(err, oauth.ErrCodeNotFound) {
			// Lost the single-use race to a concurrent redemption, or the code was
			// consumed between the peek and the burn.
			return "", 0, invalidGrant("unknown or already-used authorization code")
		}
		return "", 0, err
	}
	access, err := g.tokens.Mint(stored.Subject, g.tokenTTL)
	if err != nil {
		return "", 0, fmt.Errorf("mint access token: %w", err)
	}
	return access, g.tokenTTL, nil
}
