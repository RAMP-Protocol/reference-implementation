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
}

type ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// NewInMemoryKeyStore constructs an empty store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		ed25:   map[string]ed25519KeyPair{},
		rsaKey: map[string]*rsa.PrivateKey{},
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

// RSA implements KeyStore.
func (s *InMemoryKeyStore) RSA(ref string) (*rsa.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	priv, ok := s.rsaKey[ref]
	if !ok {
		return nil, errors.New("keystore: rsa key not found")
	}
	return priv, nil
}
