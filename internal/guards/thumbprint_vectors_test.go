// Cross-implementation gate: the SDK's thumbprint must reproduce the shared
// vectors byte for byte. The vectors are generated from the Go oracle and are
// also pinned by the TypeScript edge and the Python harness, so this is what
// catches an SDK re-pin that moves the value agent identity is derived from.
//
// This replaced an identical test over an in-repo copy of the same routine. The
// copy pinned only itself: it and the vectors could agree while the function
// every caller actually invokes had moved.
package guards_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// sharedVectors is the repo-root fixture the Go, TS, and Python thumbprint
// implementations are all pinned to (ADR-013 D4). Path is relative to this
// test's package directory.
const sharedVectors = "../../testdata/thumbprint-vectors.json"

type vectorFile struct {
	Vectors []struct {
		PublicKeyB64URL string `json:"public_key_b64url"`
		Thumbprint      string `json:"thumbprint"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(sharedVectors))
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal shared vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("shared vectors file has no vectors")
	}
	return vf
}

func TestThumbprintSharedVectors(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Thumbprint, func(t *testing.T) {
			t.Parallel()
			pub, err := base64.RawURLEncoding.DecodeString(v.PublicKeyB64URL)
			if err != nil {
				t.Fatalf("decode pubkey fixture: %v", err)
			}
			got, err := helpers.Thumbprint(ed25519.PublicKey(pub))
			if err != nil {
				t.Fatalf("Thumbprint: %v", err)
			}
			if got != v.Thumbprint {
				t.Errorf("thumbprint mismatch\n got: %s\nwant: %s", got, v.Thumbprint)
			}
		})
	}
}

func TestThumbprintBytesMatchesString(t *testing.T) {
	t.Parallel()
	vf := loadVectors(t)
	v := vf.Vectors[0]
	pub, err := base64.RawURLEncoding.DecodeString(v.PublicKeyB64URL)
	if err != nil {
		t.Fatalf("decode pubkey fixture: %v", err)
	}
	sum, err := helpers.ThumbprintBytes(ed25519.PublicKey(pub))
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != v.Thumbprint {
		t.Errorf("base64url(ThumbprintBytes) = %s, want %s", got, v.Thumbprint)
	}
}

func TestThumbprintRejectsBadLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := helpers.Thumbprint(make(ed25519.PublicKey, n)); err == nil {
			t.Errorf("len=%d: expected error, got nil", n)
		}
	}
}

func TestThumbprintRealKey(t *testing.T) {
	t.Parallel()
	// A freshly generated key produces a stable, decodable thumbprint of the
	// right length (32-byte digest → 43 base64url chars, no padding).
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(tp)
	if err != nil {
		t.Fatalf("thumbprint not base64url-no-pad: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("digest length = %d, want 32", len(decoded))
	}
}
