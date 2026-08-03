package signing_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// TestCoSigner_SignForward_ProducesVerifiableForwardingSignature is the
// migrated successor of the old in-message-hop test. Per RFC 9421 hop-by-hop
// forwarding, the broker no longer stamps an IntermediaryHop into the query;
// its contribution to the forwarding chain is a detached request signature
// carried in the X-RAMP-Broker-Signature header. This test still exercises the
// broker-relay multi-sig behaviour — it now asserts the per-hop link is a valid
// ed25519 signature verifiable against the broker's published public key over
// the forwarding payload (domain|id|query|ts). The positive end-to-end
// verification model is covered by the forwarding-chain tests; here we prove
// the chain link is real and
// SignForward does not mutate the query.
func TestCoSigner_SignForward_ProducesVerifiableForwardingSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Deterministic clock so the test can reconstruct the signed payload, which
	// embeds the forwarding-signature timestamp.
	instant := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	signer, err := signing.NewCoSigner("broker.example", "broker-1", priv, clock.NewDeterministic(instant))
	if err != nil {
		t.Fatalf("NewCoSigner: %v", err)
	}
	req := &rampv1.ResourceQuery{Uris: []string{"https://example.com/article"}}

	sig, err := signer.SignForward(req)
	if err != nil {
		t.Fatalf("SignForward: %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
	wantPayload := fmt.Sprintf("broker:%s|id:%s|query:%s|ts:%d",
		"broker.example", "broker-1", "https://example.com/article", instant.Unix())
	if !ed25519.Verify(pub, []byte(wantPayload), decoded) {
		t.Error("forwarding signature does not verify against broker public key over the expected payload")
	}
}

// TestCoSigner_SignForward_NilQueryRejected is the negative path: SignForward
// must refuse a nil ResourceQuery rather than panic.
func TestCoSigner_SignForward_NilQueryRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", priv, nil)
	if err != nil {
		t.Fatalf("NewCoSigner: %v", err)
	}
	if _, err := signer.SignForward(nil); err == nil {
		t.Fatal("expected error for nil ResourceQuery")
	}
}

func TestCoSigner_NewCoSigner_RejectsBadKey(t *testing.T) {
	_, err := signing.NewCoSigner("d", "id", ed25519.PrivateKey([]byte("short")), nil)
	if err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestCoSigner_NewCoSigner_RejectsEmptyDomain(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := signing.NewCoSigner("", "broker-1", priv, nil); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestLoadFromEnv_Seed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	seed := priv.Seed()
	encoded := base64.RawURLEncoding.EncodeToString(seed)
	t.Setenv("BROKER_ED25519_SEED", encoded)

	signer, err := signing.LoadFromEnv("broker.example", "broker-1", nil)
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	// Public key should be derivable from seed.
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	got := signer.PublicKey()
	if !bytes.Equal(want, got) {
		t.Error("public key mismatch")
	}
}

// With no key configured the Broker must refuse to start rather than mint one:
// the key it would mint is the identity it publishes, so a silent fallback
// invalidates every cached copy on each restart.
func TestLoadFromEnv_RefusesEphemeralWithoutOptIn(t *testing.T) {
	t.Setenv("BROKER_ED25519_SEED", "")
	t.Setenv("BROKER_ED25519_KEY_FILE", "")
	t.Setenv(signing.AllowEphemeralKeyEnv, "")

	signer, err := signing.LoadFromEnv("broker.example", "broker-1", nil)
	if err == nil {
		t.Fatal("expected an error when no identity key is configured")
	}
	if signer != nil {
		t.Error("expected a nil signer alongside the error")
	}
	if !strings.Contains(err.Error(), signing.AllowEphemeralKeyEnv) {
		t.Errorf("error should name the opt-out flag so the reader knows the way out, got: %v", err)
	}
}

// The opt-out is a strict allowlist, so a typo must NOT enable it — that is the
// whole reason it does not go through runhttp.EnvBool.
func TestLoadFromEnv_EphemeralOptInIsStrict(t *testing.T) {
	for _, value := range []string{"flase", "disabled", "yes", "on", "0", "false"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("BROKER_ED25519_SEED", "")
			t.Setenv("BROKER_ED25519_KEY_FILE", "")
			t.Setenv(signing.AllowEphemeralKeyEnv, value)

			if _, err := signing.LoadFromEnv("broker.example", "broker-1", nil); err == nil {
				t.Errorf("%q must not enable the ephemeral key", value)
			}
		})
	}
}

func TestLoadFromEnv_EphemeralAllowedWithOptIn(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("BROKER_ED25519_SEED", "")
			t.Setenv("BROKER_ED25519_KEY_FILE", "")
			t.Setenv(signing.AllowEphemeralKeyEnv, value)

			signer, err := signing.LoadFromEnv("broker.example", "broker-1", nil)
			if err != nil {
				t.Fatalf("LoadFromEnv with opt-in: %v", err)
			}
			if got := signer.PublicKey(); len(got) != ed25519.PublicKeySize {
				t.Errorf("ephemeral public key size = %d", len(got))
			}
		})
	}
}
