// Package agentsign is the seam between key custody and outbound signing: it
// resolves the key an agent should sign with right now and hands it to the
// outbound RFC 9421 transport, so the Identity Service can sign a request on that
// agent's behalf.
//
// # The identity comes from the request, never from the payload
//
// Which agent is being signed for is the whole security question here. The
// subdomain this package resolves MUST come from the AUTHENTICATED identity of the
// inbound request — the bearer token the caller presented — and never from a field
// the caller filled in. Take it off the wire and the service will happily sign as
// whoever was asked for, which is impersonation with the registry's own key
// custody behind it. That is why the subdomain travels on the context, put there
// by the authenticating layer, and why a request that carries no identity is
// refused rather than signed as anyone.
//
// # Why the key is resolved per request, not per client
//
// One transport serves every agent, so the key cannot be bound when the transport
// is built. It is also not cached here: an agent's active key changes under
// rotation and disappears under revocation, and a cached key would keep signing
// with a retired — or revoked — one. Custody already owns "which key signs now"
// (keystore.Active); this package asks it, every time.
//
// # The crypto.Signer narrowing
//
// KeyStore.Signer deliberately returns a crypto.Signer rather than the private
// key, so a Transit/KMS/HSM backend can sign without ever surrendering key bytes.
// The RFC 9421 signing libraries (yaronf/httpsign and the protocol SDK helpers)
// both require raw ed25519 key bytes, so this package has to narrow the signer back
// to an ed25519.PrivateKey and fails with ErrNotSignable when a backend will not
// hand them over. That failure is the honest report of a real gap: moving custody to
// an HSM means teaching the signing path to drive a crypto.Signer, not swapping an
// adapter here.
package agentsign

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// ErrNoIdentity is returned when a signature is requested for a context that
// carries no authenticated agent. It is deliberately fatal to the request:
// forwarding it unsigned would present the caller to the origin as an anonymous
// bot, and signing it as some default agent would be impersonation.
var ErrNoIdentity = errors.New("agentsign: no authenticated agent on the context")

// ErrNotSignable is returned when key custody hands back a signer whose private
// key bytes cannot be read — an HSM or KMS backend. See the package doc: the
// signing libraries require the bytes, so this is a gap to close in the signing
// path, not a condition to work around here.
var ErrNotSignable = errors.New("agentsign: key custody will not surrender private key bytes")

// Custody is the narrow slice of the KeyStore this package needs: which key an
// agent should sign with now, and a signer for it. *keystore.VaultStore satisfies
// it. Interface segregation is not ceremony here — it is what keeps the mint,
// export, and destroy operations out of reach of the request path.
type Custody interface {
	Active(ctx context.Context, subdomain string) (keystore.Key, error)
	Signer(ctx context.Context, ref keystore.Ref) (crypto.Signer, error)
}

type subdomainCtxKey struct{}

// WithSubdomain returns ctx carrying the authenticated agent's subdomain. ONLY the
// layer that authenticated the caller may call this — see the package doc.
func WithSubdomain(ctx context.Context, subdomain string) context.Context {
	return context.WithValue(ctx, subdomainCtxKey{}, subdomain)
}

// SubdomainFromContext returns the authenticated agent's subdomain, or "" when the
// request carries no identity.
func SubdomainFromContext(ctx context.Context) string {
	s, _ := ctx.Value(subdomainCtxKey{}).(string)
	return s
}

// Config wires a Resolver. Keys is required; Scheme defaults to https.
type Config struct {
	// Keys is the custody backend holding the agents' private keys.
	Keys Custody
	// Scheme is the URL scheme of the directory origin published in the covered
	// Signature-Agent header ("https" in production, "http" for a local stack).
	// It must match the scheme the agent's directory is actually served on, or an
	// origin following the pointer will not find it.
	Scheme string
}

// Resolver turns an authenticated agent into the key that signs for it.
type Resolver struct {
	keys   Custody
	scheme string
}

// New builds a Resolver, defaulting the scheme to https. It fails on a missing
// custody backend rather than nil-panicking on the first signed request.
func New(cfg Config) (*Resolver, error) {
	if cfg.Keys == nil {
		return nil, errors.New("agentsign: Config.Keys is required")
	}
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &Resolver{keys: cfg.Keys, scheme: scheme}, nil
}

// DirectoryOrigin is an agent's RAMP identity: the origin its Web Bot Auth
// directory is served on, which is the value that travels in the covered
// Signature-Agent header.
//
// It is exported, and this package owns it, because the same string is needed in
// two places that MUST agree byte-for-byte: the signer puts it in
// Signature-Agent, and the MCP adapter puts it in requester.id. The Broker and
// the Exchange authorize a call by comparing those two, so two spellings of this
// value is two chances for every peer to refuse the call with an error that names
// neither side. One construction, one owner.
//
// A METHOD rather than a package function taking a scheme, deliberately: the
// scheme is the Resolver's, already reconciled with the scheme the agent's
// directory is actually served on. A scheme-taking variant would let a caller
// supply a different one, which is the drift this method exists to remove.
func (r *Resolver) DirectoryOrigin(subdomain string) string {
	return r.scheme + "://" + subdomain
}

// KeyFor returns the key subdomain's agent should sign with right now, addressed
// as the outbound transport wants it. The keyid is the RFC 7638 thumbprint custody
// already stores, and the directory origin is the agent's own subdomain — the two
// values an origin needs to fetch that agent's Web Bot Auth directory and find the
// key there.
//
// Errors wrap the keystore sentinels, so a caller can still tell an agent with no
// active key (keystore.ErrNotFound — expired, revoked, never provisioned) from a
// custody outage (keystore.ErrUnavailable) and answer accordingly.
func (r *Resolver) KeyFor(ctx context.Context, subdomain string) (ramphttpsig.AgentKey, error) {
	key, err := r.keys.Active(ctx, subdomain)
	if err != nil {
		return ramphttpsig.AgentKey{}, fmt.Errorf("agentsign: active key for %q: %w", subdomain, err)
	}
	signer, err := r.keys.Signer(ctx, key.Ref)
	if err != nil {
		return ramphttpsig.AgentKey{}, fmt.Errorf("agentsign: signer for %q: %w", subdomain, err)
	}
	priv, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return ramphttpsig.AgentKey{}, fmt.Errorf("%w: %q holds a %T", ErrNotSignable, subdomain, signer)
	}
	return ramphttpsig.AgentKey{
		Directory: r.DirectoryOrigin(subdomain),
		KeyID:     key.Ref.Thumbprint,
		Private:   priv,
	}, nil
}

// Source adapts the Resolver to the outbound transport's KeySource: it reads the
// authenticated agent off the request context and resolves that agent's key.
// Wire it with ramphttpsig.WithKeySource and one transport signs correctly for
// every agent it carries.
func (r *Resolver) Source() ramphttpsig.KeySource {
	return func(ctx context.Context) (ramphttpsig.AgentKey, error) {
		subdomain := SubdomainFromContext(ctx)
		if subdomain == "" {
			return ramphttpsig.AgentKey{}, ErrNoIdentity
		}
		return r.KeyFor(ctx, subdomain)
	}
}
