package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The tests below cover the lazy-provider branch of the RSA lookup. The branch
// exists so a key needed by only SOME tenants does not have to be resolvable at
// boot: an Exchange whose every tenant signs with Ed25519 must start without an
// RSA key, and only a tenant on the AWS_CLOUDFRONT_RSA scheme pays the
// resolution — or hits its failure.

// mustRSAKey mints the key the provider tests hand out.
func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	return priv
}

func TestRSAFuncNotResolvedUntilLookedUp(t *testing.T) {
	t.Parallel()
	priv := mustRSAKey(t)
	store := NewInMemoryKeyStore()
	calls := 0
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		calls++
		return priv, nil
	})
	if calls != 0 {
		t.Fatalf("provider ran at registration time: %d calls", calls)
	}
	got, err := store.RSA("ref")
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("lookup returned a different key than the provider produced")
	}
	if calls != 1 {
		t.Fatalf("want 1 provider call after one lookup, got %d", calls)
	}
}

func TestRSAFuncSuccessIsMemoized(t *testing.T) {
	t.Parallel()
	priv := mustRSAKey(t)
	store := NewInMemoryKeyStore()
	calls := 0
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		calls++
		return priv, nil
	})
	for range 3 {
		if _, err := store.RSA("ref"); err != nil {
			t.Fatalf("RSA: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("want the provider run once and cached, got %d calls", calls)
	}
}

func TestRSAFuncErrorSurfacesVerbatimAndIsRetried(t *testing.T) {
	t.Parallel()
	store := NewInMemoryKeyStore()
	sentinel := errors.New("no RSA signing key: set RAMP_RSA_PRIVATE_PEM")
	calls := 0
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		calls++
		return nil, sentinel
	})
	// Verbatim: the operator-actionable text is the whole point of deferring, so
	// nothing may swallow or rewrite it.
	for range 2 {
		_, err := store.RSA("ref")
		if !errors.Is(err, sentinel) {
			t.Fatalf("want the provider's own error, got %v", err)
		}
	}
	// Not memoized: a provider that failed for a transient reason (an unreadable
	// mount, say) must get another chance rather than poisoning the ref for the
	// process's lifetime.
	if calls != 2 {
		t.Fatalf("want a retry per lookup after an error, got %d calls", calls)
	}
}

func TestRSAFuncNilKeyWithNoErrorIsAnError(t *testing.T) {
	t.Parallel()
	store := NewInMemoryKeyStore()
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) { return nil, nil })
	// Caching a nil key would hand a nil private key to the CloudFront signer,
	// which is a panic at signing time rather than a refusal.
	if _, err := store.RSA("ref"); err == nil {
		t.Fatal("want an error when a provider yields no key and no error")
	}
}

func TestRSAStoredKeyWinsOverProvider(t *testing.T) {
	t.Parallel()
	store := NewInMemoryKeyStore()
	store.PutRSA("ref", mustRSAKey(t))
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		t.Error("provider must not run when a key is already stored")
		return nil, errors.New("unreachable")
	})
	if _, err := store.RSA("ref"); err != nil {
		t.Fatalf("RSA: %v", err)
	}
}

func TestRSAEagerPutDuringProviderRunStillWins(t *testing.T) {
	t.Parallel()
	eager := mustRSAKey(t)
	stale := mustRSAKey(t)
	store := NewInMemoryKeyStore()
	// The provider runs outside the lock, so a PutRSA can land while it is in
	// flight. Calling PutRSA from inside the provider reproduces that window
	// deterministically: the provider's own (now stale) result must NOT clobber
	// the eagerly stored key on the cache-fill.
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		store.PutRSA("ref", eager)
		return stale, nil
	})
	got, err := store.RSA("ref")
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	if !got.Equal(eager) {
		t.Fatal("first lookup returned the provider's stale key over the eagerly stored one")
	}
	got, err = store.RSA("ref")
	if err != nil {
		t.Fatalf("RSA (second lookup): %v", err)
	}
	if !got.Equal(eager) {
		t.Fatal("cache-fill clobbered the eagerly stored key")
	}
}

func TestRSAEagerPutDuringFailingProviderStillWins(t *testing.T) {
	t.Parallel()
	eager := mustRSAKey(t)
	store := NewInMemoryKeyStore()
	// The error-path twin of the test above: "PutRSA always wins" must hold
	// even when the in-flight provider FAILS. Without the re-check on the
	// error path, this lookup would return a stale refusal for a key that is
	// already stored.
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) {
		store.PutRSA("ref", eager)
		return nil, errors.New("boot-time refusal, now stale")
	})
	got, err := store.RSA("ref")
	if err != nil {
		t.Fatalf("want the eagerly stored key over the provider's stale refusal, got error: %v", err)
	}
	if !got.Equal(eager) {
		t.Fatal("lookup returned a different key than the eagerly stored one")
	}
}

func TestRSAUnregisteredRefReportsNotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryKeyStore()
	_, err := store.RSA("absent")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want a not-found error for an unregistered ref, got %v", err)
	}
}

func TestRSAFuncConcurrentLookupsAreSafe(t *testing.T) {
	t.Parallel()
	priv := mustRSAKey(t)
	store := NewInMemoryKeyStore()
	store.PutRSAFunc("ref", func() (*rsa.PrivateKey, error) { return priv, nil })
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.RSA("ref"); err != nil {
				t.Errorf("RSA: %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestURLSignerFor_CFRSASurfacesDeferredKeyError is the reason the lazy provider
// exists, asserted at the layer a caller actually reaches: a tenant on the
// CloudFront scheme served by an Exchange with no RSA key must be refused with
// the operator-actionable reason, not a bare "rsa key not found". The provider
// here mirrors production exactly (installRSAKey wraps ErrRSAKeyUnavailable
// with the env settings), and both properties the service layer relies on are
// pinned: the sentinel survives for errors.Is classification, and the message
// survives for the operator.
func TestURLSignerFor_CFRSASurfacesDeferredKeyError(t *testing.T) {
	t.Parallel()

	store := NewInMemoryKeyStore()
	store.PutRSAFunc("cf-rsa-primary", func() (*rsa.PrivateKey, error) {
		return nil, fmt.Errorf(
			"%w — set RAMP_RSA_PRIVATE_PEM or RAMP_RSA_PRIVATE_PEM_FILE",
			ErrRSAKeyUnavailable)
	})

	_, err := URLSignerFor(TenantKeys{
		Scheme:              SchemeCFRSA,
		RSARef:              "cf-rsa-primary",
		CloudFrontKeyPairID: "K123",
	}, store)
	if err == nil {
		t.Fatal("want a refusal for a CloudFront tenant with no RSA key")
	}
	if !errors.Is(err, ErrRSAKeyUnavailable) {
		t.Fatalf("the sentinel must survive URLSignerFor's wrapping — the service layer classifies on it; got %v", err)
	}
	if !strings.Contains(err.Error(), "RAMP_RSA_PRIVATE_PEM") {
		t.Fatalf("the refusal must name the setting to fix; got %v", err)
	}
}

// TestURLSignerFor_Ed25519NeedsNoRSAKey is the other half of the contract: the
// Ed25519 scheme must be servable with no RSA key present at all, which is what
// lets the Exchange boot without one.
func TestURLSignerFor_Ed25519NeedsNoRSAKey(t *testing.T) {
	t.Parallel()

	store := NewInMemoryKeyStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	store.PutEd25519("ed-ref", pub, priv)

	if _, err := URLSignerFor(TenantKeys{
		Scheme:     SchemeEd25519,
		Ed25519Ref: "ed-ref",
	}, store); err != nil {
		t.Fatalf("an Ed25519 tenant must not need RSA key material: %v", err)
	}
}
