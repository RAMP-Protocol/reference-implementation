package signing_test

// Byte-format pin for exchange-minted Ed25519 signed URLs.
//
// History: before the hand-rolled Ed25519URLSigner was deleted, this file was the
// equivalence gate proving local(Ed25519URLSigner.SignURL) == helpers.SignURLEd25519
// byte-for-byte over the SAME fixed seed, expiry, and three inputs below (recorded
// green in the task notes). The golden URLs are that proven output; the test now
// pins the raw SDK helper and the production construction path (URLSignerFor's
// adapter) against those bytes, so any drift in the canonical message format
// ("GET\n<url-minus-sig>", sorted query, base64url-no-pad sig) breaks here before
// it breaks the edge verifier.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// fixedSeed is a deterministic 32-byte seed so the test is stable in CI.
// Never use rand.Reader in a byte pin — the key must be the same across every
// run to prove structural byte-identity, not just sign/verify.
var fixedSeed = [ed25519.SeedSize]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// fixedExpiry is pinned so the exp param is deterministic.
var fixedExpiry = time.Unix(1893456000, 0).UTC() // 2030-01-01T00:00:00Z

func TestEd25519SignedURL_GoldenByteFormat(t *testing.T) {
	t.Parallel()

	priv := ed25519.NewKeyFromSeed(fixedSeed[:])
	pub := priv.Public().(ed25519.PublicKey)

	const keyID = "test-key-id"

	cases := []struct {
		name    string
		rawURL  string
		agentID string
		golden  string
	}{
		{
			// Bearer URL — no agent_id; simplest canonical form.
			name:    "bearer_no_agent_id",
			rawURL:  "https://cdn.example.com/articles/ramp-overview.html",
			agentID: "",
			golden:  "https://cdn.example.com/articles/ramp-overview.html?exp=1893456000&kid=test-key-id&sig=T08X3ZZSfMDqcghcm_7vaMFwra7Ess4eUU7ybOfTLTcQPpBkZ5HMbz29kyGMCP48VJcdcMJ04I1jXabUPCPvBQ",
		},
		{
			// Agent-bound URL — agent_id present and covered by the signature.
			name:    "agent_bound_with_agent_id",
			rawURL:  "https://cdn.example.com/articles/ramp-overview.html",
			agentID: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
			golden:  "https://cdn.example.com/articles/ramp-overview.html?agent_id=kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k&exp=1893456000&kid=test-key-id&sig=Q9JhLyR5P6TfOLgXQIRfmrj0Wl8z6WmlXpAo2yZWQCsyWmM1uNkEeVi_v2J9BmMJZ6l2FHKAkMtnOQjYUdDJDg",
		},
		{
			// Pre-existing query params — exercises canonical query sorting.
			name:    "multi_param_query_sorted",
			rawURL:  "https://cdn.example.com/media/video.mp4?resolution=1080p&format=mp4&token=abc123",
			agentID: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
			golden:  "https://cdn.example.com/media/video.mp4?agent_id=kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k&exp=1893456000&format=mp4&kid=test-key-id&resolution=1080p&sig=aXjTeof4-iDz3EJ1WM6tRhhcJVsuJrgf7YPLzT5sWioe3N8jWwehQzKYZ-kqzLJw0u4ZtznsBxLDCZcPBTs-Ag&token=abc123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The raw SDK helper must reproduce the golden bytes exactly.
			out, err := helpers.SignURLEd25519(priv, keyID, tc.rawURL, tc.agentID, fixedExpiry)
			if err != nil {
				t.Fatalf("SignURLEd25519: %v", err)
			}
			if out.URL != tc.golden {
				t.Fatalf("byte drift:\n got  %s\n want %s", out.URL, tc.golden)
			}
			wantHash := sha256.Sum256([]byte(tc.golden))
			if !bytes.Equal(out.Hash, wantHash[:]) {
				t.Fatalf("hash drift: got %x want %x", out.Hash, wantHash)
			}

			// And the golden URL must verify through the SDK verifier.
			if _, err := helpers.VerifyURLEd25519(tc.golden, pub, fixedExpiry.Add(-time.Hour)); err != nil {
				t.Fatalf("golden url does not verify: %v", err)
			}
		})
	}
}

// TestEd25519SignedURL_DispatcherPathMatchesSDK pins that the PRODUCTION
// construction path (URLSignerFor's adapter) emits exactly what the raw SDK
// helper emits for the same inputs — the adapter adds nothing and loses nothing.
// (kid differs from the golden table above only because URLSignerFor derives it
// as the key's RFC 7638 thumbprint, as production does.)
func TestEd25519SignedURL_DispatcherPathMatchesSDK(t *testing.T) {
	t.Parallel()

	priv := ed25519.NewKeyFromSeed(fixedSeed[:])
	pub := priv.Public().(ed25519.PublicKey)

	sgn, err := signing.URLSignerFor(
		signing.TenantKeys{Scheme: signing.SchemeEd25519, Ed25519Ref: "k"},
		&stubStore{pub: pub, priv: priv},
	)
	if err != nil {
		t.Fatalf("URLSignerFor: %v", err)
	}
	thumb, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	const rawURL = "https://cdn.example.com/media/video.mp4?resolution=1080p&format=mp4"
	const agentID = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	got, err := sgn.SignURL(context.Background(), rawURL, agentID, fixedExpiry)
	if err != nil {
		t.Fatalf("adapter sign: %v", err)
	}
	want, err := helpers.SignURLEd25519(priv, thumb, rawURL, agentID, fixedExpiry)
	if err != nil {
		t.Fatalf("sdk sign: %v", err)
	}
	if got.URL != want.URL {
		t.Fatalf("adapter drift:\n got  %s\n want %s", got.URL, want.URL)
	}
	if !bytes.Equal(got.Hash, want.Hash) {
		t.Fatalf("hash drift: got %x want %x", got.Hash, want.Hash)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Fatalf("expiry drift: got %v want %v", got.Expiry, want.Expiry)
	}
}
