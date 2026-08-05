package transport_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// TestNewKeyRegistry_RejectsMalformedKeys pins the construction contract: the
// registry is the source of the served WBA directory, so a malformed entry (a
// wrong-size or nil public key) must fail construction loudly — never be
// skipped silently or published broken.
func TestNewKeyRegistry_RejectsMalformedKeys(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	tests := []struct {
		name    string
		key     ed25519.PublicKey
		wantErr bool
	}{
		{"valid key accepted", pub, false},
		{"truncated public key rejected", pub[:16], true},
		{"nil public key rejected", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := transport.NewKeyRegistry(tc.key)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("NewKeyRegistry error = %v, want error %v", err, tc.wantErr)
			}
		})
	}

	// An empty registry stays valid — the Broker boots without a relay key in
	// local development and still serves its identity key.
	if _, err := transport.NewKeyRegistry(); err != nil {
		t.Errorf("empty registry rejected: %v", err)
	}
}

// TestKeyRegistry_IsImmutableAfterConstruction pins the "fixed at
// construction" promise at the byte level: the published key set must not be
// changeable after boot, neither by a caller that kept the slice it passed in
// nor by a caller mutating what Keys() returned. Without byte copies both
// paths alias the registry's backing arrays, and flipping one byte would
// silently change the key the served WBA directory publishes.
func TestKeyRegistry_IsImmutableAfterConstruction(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	orig := bytes.Clone(pub)

	reg, err := transport.NewKeyRegistry(pub)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	// The caller mutates the slice it handed in, after construction.
	pub[0] ^= 0xFF
	got := reg.Keys()
	if !bytes.Equal(got[0], orig) {
		t.Fatal("mutating the caller's input slice changed the registered key: the constructor must copy the bytes")
	}

	// The caller mutates what Keys() returned; a second read must be pristine.
	got[0][0] ^= 0xFF
	if again := reg.Keys(); !bytes.Equal(again[0], orig) {
		t.Fatal("mutating a returned key changed the registry: Keys() must return byte copies")
	}
}
