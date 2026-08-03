package signing

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"sync"
)

// InMemoryKeyStore is a trivial KeyStore keyed by opaque ref strings.
// Production deployments swap this for a secret-manager-backed implementation.
type InMemoryKeyStore struct {
	mu     sync.RWMutex
	ed25   map[string]ed25519KeyPair
	rsaKey map[string]*rsa.PrivateKey
	// rsaFunc holds providers registered by PutRSAFunc for refs whose key is
	// resolved on first use rather than up front.
	rsaFunc map[string]func() (*rsa.PrivateKey, error)
}

type ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// NewInMemoryKeyStore constructs an empty store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		ed25:    map[string]ed25519KeyPair{},
		rsaKey:  map[string]*rsa.PrivateKey{},
		rsaFunc: map[string]func() (*rsa.PrivateKey, error){},
	}
}

// PutEd25519 stores an Ed25519 key pair under ref.
func (s *InMemoryKeyStore) PutEd25519(ref string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	s.mu.Lock()
	s.ed25[ref] = ed25519KeyPair{Public: pub, Private: priv}
	s.mu.Unlock()
}

// PutRSA stores an RSA key under ref.
func (s *InMemoryKeyStore) PutRSA(ref string, priv *rsa.PrivateKey) {
	s.mu.Lock()
	s.rsaKey[ref] = priv
	s.mu.Unlock()
}

// Ed25519 implements KeyStore.
func (s *InMemoryKeyStore) Ed25519(ref string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kp, ok := s.ed25[ref]
	if !ok {
		return nil, nil, errors.New("keystore: ed25519 key not found")
	}
	return kp.Public, kp.Private, nil
}

// PutRSAFunc registers a provider that resolves ref's key on the FIRST lookup
// instead of now, for a key only some tenants need: the AWS_CLOUDFRONT_RSA
// scheme uses one and the Ed25519 scheme does not, so an Exchange serving only
// Ed25519 tenants should neither pay the resolution nor inherit its failure.
//
// A successful result is cached and the provider is dropped. An error is NOT
// cached — it is returned verbatim (so an operator-actionable message survives)
// and the provider stays registered, giving a transient failure such as a
// briefly unreadable mount another chance instead of poisoning the ref for the
// life of the process. A key stored eagerly under the same ref by PutRSA always
// wins; the provider is never consulted while one is present.
func (s *InMemoryKeyStore) PutRSAFunc(ref string, resolve func() (*rsa.PrivateKey, error)) {
	s.mu.Lock()
	s.rsaFunc[ref] = resolve
	s.mu.Unlock()
}

// RSA implements KeyStore.
func (s *InMemoryKeyStore) RSA(ref string) (*rsa.PrivateKey, error) {
	s.mu.RLock()
	priv, ok := s.rsaKey[ref]
	resolve := s.rsaFunc[ref]
	s.mu.RUnlock()
	if ok {
		return priv, nil
	}
	if resolve == nil {
		return nil, errors.New("keystore: rsa key not found")
	}
	priv, err := resolve()
	if err != nil {
		return s.storeResolved(ref, nil, err)
	}
	if priv == nil {
		// Caching a nil key would hand the CloudFront signer a nil private key,
		// turning a refusal into a panic at signing time.
		return s.storeResolved(ref, nil, errors.New("keystore: rsa key provider returned no key"))
	}
	return s.storeResolved(ref, priv, nil)
}

// storeResolved finishes an RSA lookup after its provider ran. The provider
// runs outside the lock, so an eager PutRSA (or another lookup's provider) may
// have landed a key meanwhile — the re-check makes the stored key win on EVERY
// outcome, including a provider error: without it, a lookup racing a PutRSA
// would return a stale refusal for a key that is now present, and the
// "PutRSA always wins" guarantee above would hold only on the happy path.
// A cached success also retires the provider, so a later re-registration
// cannot resurrect a stale one.
func (s *InMemoryKeyStore) storeResolved(ref string, priv *rsa.PrivateKey, resolveErr error) (*rsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.rsaKey[ref]; ok {
		delete(s.rsaFunc, ref)
		return existing, nil
	}
	if resolveErr != nil {
		// No key landed and the provider failed: surface its error verbatim and
		// keep the provider registered so a transient failure can retry.
		return nil, resolveErr
	}
	s.rsaKey[ref] = priv
	delete(s.rsaFunc, ref)
	return priv, nil
}
