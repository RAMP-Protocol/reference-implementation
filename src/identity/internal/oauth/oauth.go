// Package oauth holds the authorization-server domain types and their store
// contract: the dynamically-registered downstream clients and the one-time
// authorization codes the Identity Service issues when it fronts an MCP client's
// sign-in. It is a thin domain package (types + sentinels, no I/O); the
// Postgres implementation lives in the repo package, and the auth-server handlers
// depend on the Store interface here. Token minting and PKCE verification are the
// handlers' job, not this package's — it owns only the durable state.
package oauth

import (
	"context"
	"errors"
	"time"
)

// Client is a downstream OAuth client registered via RFC 7591 Dynamic Client
// Registration. RedirectURIs is the exact allowlist /authorize checks a requested
// redirect_uri against. These are public clients: PKCE stands in for a secret, so
// none is stored.
type Client struct {
	ID           string
	RedirectURIs []string
	Name         string
}

// Code is a one-time authorization code the server issues at the end of a sign-in
// and redeems at /token. It is bound to the client, the exact redirect_uri, the
// downstream client's PKCE challenge, and the developer subject (the minted
// subdomain) it authenticates — /token re-checks all four. ExpiresAt is carried so
// the caller can reject a stale code against its own clock.
type Code struct {
	ClientID      string
	RedirectURI   string
	PKCEChallenge string
	Subject       string
	ExpiresAt     time.Time
}

// Store is the persistence port the auth-server handlers depend on. *repo.OAuthRepo
// satisfies it.
type Store interface {
	// RegisterClient persists a newly-minted client_id with its redirect-URI
	// allowlist and display name.
	RegisterClient(ctx context.Context, c Client) (Client, error)
	// ClientByID resolves a registered client, or ErrClientNotFound.
	ClientByID(ctx context.Context, clientID string) (Client, error)
	// IssueCode stores a one-time code under the SHA-256 of its opaque value
	// (codeHash), bound to the fields in c.
	IssueCode(ctx context.Context, codeHash string, c Code) error
	// GetCode reads the code's bound fields WITHOUT consuming it, or
	// ErrCodeNotFound when the code is unknown. It returns a row whether or not
	// the code is already consumed, so the caller can validate every binding
	// (expiry, client, redirect, PKCE) before deciding to redeem — the atomic burn
	// is ConsumeCode. Expiry is NOT enforced here.
	GetCode(ctx context.Context, codeHash string) (Code, error)
	// ConsumeCode atomically marks the code redeemed and returns its bound fields,
	// or ErrCodeNotFound when the code is unknown or already consumed. Expiry is
	// NOT enforced here — the caller checks Code.ExpiresAt against its clock.
	ConsumeCode(ctx context.Context, codeHash string) (Code, error)
}

// Domain sentinels the Store maps its persistence errors onto. ErrUnavailable marks
// a transient store outage (retryable), distinct from a definite result.
var (
	ErrClientNotFound = errors.New("oauth: client not found")
	ErrCodeNotFound   = errors.New("oauth: authorization code not found or already used")
	ErrUnavailable    = errors.New("oauth: store unavailable")
)
