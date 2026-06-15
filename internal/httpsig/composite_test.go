package httpsig_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

func TestCompositeResolver(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	hit := httpsig.ResolverFunc(func(context.Context, string) (ed25519.PublicKey, error) { return pub, nil })
	otherHit := httpsig.ResolverFunc(func(context.Context, string) (ed25519.PublicKey, error) { return other, nil })
	unknown := httpsig.ResolverFunc(func(_ context.Context, kid string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("%w: %s", httpsig.ErrUnknownKey, kid)
	})
	revoked := errors.New("key revoked")
	revokes := httpsig.ResolverFunc(func(context.Context, string) (ed25519.PublicKey, error) { return nil, revoked })

	t.Run("first hit wins", func(t *testing.T) {
		t.Parallel()
		got, err := httpsig.NewCompositeResolver(hit, otherHit).Resolve(context.Background(), "k")
		if err != nil || !got.Equal(pub) {
			t.Fatalf("want first key, got %v err=%v", got, err)
		}
	})
	t.Run("unknown falls through to next", func(t *testing.T) {
		t.Parallel()
		got, err := httpsig.NewCompositeResolver(unknown, otherHit).Resolve(context.Background(), "k")
		if err != nil || !got.Equal(other) {
			t.Fatalf("want fall-through key, got %v err=%v", got, err)
		}
	})
	t.Run("authoritative error stops, not masked by a later hit", func(t *testing.T) {
		t.Parallel()
		_, err := httpsig.NewCompositeResolver(revokes, hit).Resolve(context.Background(), "k")
		if !errors.Is(err, revoked) {
			t.Fatalf("want revoked error surfaced, got %v", err)
		}
	})
	t.Run("all unknown yields ErrUnknownKey", func(t *testing.T) {
		t.Parallel()
		_, err := httpsig.NewCompositeResolver(unknown, unknown).Resolve(context.Background(), "k")
		if !errors.Is(err, httpsig.ErrUnknownKey) {
			t.Fatalf("want ErrUnknownKey, got %v", err)
		}
	})
}
