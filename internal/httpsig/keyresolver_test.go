package httpsig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestStaticResolver_LookupAndPut(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	r := NewStaticResolver(map[string]ed25519.PublicKey{"k1": pub})
	got, err := r.Resolve(context.Background(), "k1")
	if err != nil {
		t.Fatalf("resolve k1: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("k1 pubkey mismatch")
	}

	_, err = r.Resolve(context.Background(), "missing")
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	r.Put("k2", pub2)
	got2, err := r.Resolve(context.Background(), "k2")
	if err != nil {
		t.Fatalf("resolve k2: %v", err)
	}
	if !got2.Equal(pub2) {
		t.Fatalf("k2 mismatch")
	}
}

// TestStaticResolver_ValidityWindow pins that a statically-loaded key with a
// not_before/not_after window is enforced: outside the window it resolves to
// ErrKeyExpired (an authoritative negative, NOT ErrUnknownKey, so the composite
// rejects rather than falling through), while an unbounded key is always valid.
func TestStaticResolver_ValidityWindow(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	r := NewStaticResolver(nil)
	r.SetClock(func() time.Time { return base })
	r.PutTimed("windowed", pub, base.Add(-time.Hour), base.Add(time.Hour))
	r.Put("unbounded", pub)

	// Within the window and the unbounded key both resolve.
	if _, err := r.Resolve(context.Background(), "windowed"); err != nil {
		t.Fatalf("within window: unexpected err %v", err)
	}
	if _, err := r.Resolve(context.Background(), "unbounded"); err != nil {
		t.Fatalf("unbounded: unexpected err %v", err)
	}

	// Past not_after → ErrKeyExpired, and specifically NOT ErrUnknownKey.
	r.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	_, err = r.Resolve(context.Background(), "windowed")
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("expired key: want ErrKeyExpired, got %v", err)
	}
	if errors.Is(err, ErrUnknownKey) {
		t.Fatal("expired key must NOT be ErrUnknownKey (composite must not fall through)")
	}
	if _, err := r.Resolve(context.Background(), "unbounded"); err != nil {
		t.Fatalf("unbounded after clock advance: unexpected err %v", err)
	}

	// Before not_before → ErrKeyExpired too.
	r.SetClock(func() time.Time { return base.Add(-2 * time.Hour) })
	if _, err := r.Resolve(context.Background(), "windowed"); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("not-yet-valid key: want ErrKeyExpired, got %v", err)
	}
}

// TestLoadKeysFile_EnforcesValidityWindow proves the static bootstrap loader
// carries a key's not_before/not_after through to the resolver: a keys.json
// entry whose window already ended resolves to ErrKeyExpired, not the pubkey.
func TestLoadKeysFile_EnforcesValidityWindow(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	doc := fmt.Sprintf(
		`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,`+
			`"not_before":"2020-01-01T00:00:00Z","not_after":"2020-01-02T00:00:00Z"}]}`, x)
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}

	r := NewStaticResolver(nil)
	if err := loadKeysFile(r, path); err != nil {
		t.Fatalf("loadKeysFile: %v", err)
	}
	// The key loaded, but its window ended in 2020 → expired at time.Now().
	if _, err := r.Resolve(context.Background(), tp); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("expired windowed key from file: want ErrKeyExpired, got %v", err)
	}
}
