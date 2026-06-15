package httpsig

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ResolverFunc adapts a plain function to the KeyResolver interface. It lets a
// caller bind a revocation-aware key source (e.g. a rampwellknown.Loader keyed
// by a fixed well-known host) as a resolver without httpsig taking a dependency
// on the well-known library; the binding + any error translation live in the
// caller (the production root that owns both packages).
type ResolverFunc func(ctx context.Context, keyID string) (ed25519.PublicKey, error)

// Resolve implements KeyResolver.
func (f ResolverFunc) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	return f(ctx, keyID)
}

// CompositeResolver resolves a keyid by trying each delegate in order. A
// delegate that reports ErrUnknownKey is treated as "not my key" and the next
// delegate is tried; any OTHER error (e.g. an authoritative revocation or
// expiry verdict) stops the search and is returned, so a negative verdict from
// a revocation-aware source is never masked by a later, more permissive
// delegate. Exhausting every delegate yields ErrUnknownKey.
//
// Order therefore encodes authority: place the revocation-aware resolver first
// and the static bootstrap resolver last. A caller that wants a transport
// failure in an early delegate to fall through to a later one must translate
// that failure to ErrUnknownKey before it reaches the composite.
type CompositeResolver struct {
	delegates []KeyResolver
}

// NewCompositeResolver returns a CompositeResolver over delegates, tried in the
// given order.
func NewCompositeResolver(delegates ...KeyResolver) *CompositeResolver {
	return &CompositeResolver{delegates: delegates}
}

// Resolve implements KeyResolver.
func (c *CompositeResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	for _, d := range c.delegates {
		pub, err := d.Resolve(ctx, keyID)
		if err == nil {
			return pub, nil
		}
		if !errors.Is(err, ErrUnknownKey) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
}
