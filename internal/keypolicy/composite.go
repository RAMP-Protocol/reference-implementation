// Package keypolicy provides the composite key-resolver policy the RAMP app
// uses for authority ordering: a RevocationAware resolver first, a static
// bootstrap resolver last, an optional per-agent well-known fallback at the
// end. The SDK deliberately does not ship a composite resolver (authority
// ordering is app policy, not protocol mechanics), so this package is the
// app's home for that logic. All types operate over the sdk/go helpers
// KeyResolver interface.
package keypolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// ResolverFunc adapts a plain function to the helpers.KeyResolver interface.
// It lets a caller bind a revocation-aware key source (e.g. the SDK's
// WBAKeyResolver pinned to a fixed directory URL) as a resolver without
// keypolicy owning that binding; the binding + any error translation live in
// the caller (the production root that owns both packages).
type ResolverFunc func(ctx context.Context, keyID string) (ed25519.PublicKey, error)

// Resolve implements helpers.KeyResolver.
func (f ResolverFunc) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	return f(ctx, keyID)
}

// CompositeResolver resolves a keyid by trying each delegate in order. A
// delegate that reports helpers.ErrUnknownKey is treated as "not my key" and
// the next delegate is tried; any OTHER error (e.g. an authoritative
// revocation or expiry verdict) stops the search and is returned, so a
// negative verdict from a revocation-aware source is never masked by a later,
// more permissive delegate. Exhausting every delegate yields helpers.ErrUnknownKey.
//
// Order encodes authority: place the revocation-aware resolver first and the
// static bootstrap resolver last. A caller that wants a transport failure in
// an early delegate to fall through to a later one must translate that failure
// to helpers.ErrUnknownKey before it reaches the composite.
type CompositeResolver struct {
	delegates []helpers.KeyResolver
}

// NewCompositeResolver returns a CompositeResolver over delegates, tried in
// the given order.
func NewCompositeResolver(delegates ...helpers.KeyResolver) *CompositeResolver {
	return &CompositeResolver{delegates: delegates}
}

// Resolve implements helpers.KeyResolver.
func (c *CompositeResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	for _, d := range c.delegates {
		pub, err := d.Resolve(ctx, keyID)
		if err == nil {
			return pub, nil
		}
		if !errors.Is(err, helpers.ErrUnknownKey) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: keyid=%q", helpers.ErrUnknownKey, keyID)
}
