package httpsig

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Two fixtures, one profile. The paths are relative to this package directory;
// both live at the repo root because the TypeScript edge and the Python e2e
// harness read from there too.
//
// The BASE corpus pins the signature base string every implementation builds.
// The SIGN corpus pins the three header values a signer emits, which is a
// stricter contract: the byte string inside the Signature colons is standard
// base64 while the key beside it is base64url, an asymmetry a hand-written
// signer gets wrong silently and a base-only check cannot see.
//
// The Go signer is the protocol module's now, so the second corpus checks the
// module against the values this repository's edge worker and Python harness are
// built around. Before this it had no reader in any language while its own note
// instructed the next person to refresh it from upstream — a corpus that reads
// as a maintained gate and fails nothing.
const (
	popBaseVectorsPath = "../../testdata/pop-signature-base-vectors.json"
	popSignVectorsPath = "../../testdata/pop-sign-vectors.json"
)

type popBaseVectorFile struct {
	Vectors []struct {
		Method       string `json:"method"`
		URL          string `json:"url"`
		Params       string `json:"params"`
		ExpectedBase string `json:"expected_base"`
	} `json:"vectors"`
}

func loadJSONFixture[T any](t *testing.T, path string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// TestPoPSignatureBaseMatchesSharedVectors pins the signature base against the
// fixture the SDK's TypeScript face and the Python e2e signer are pinned to. A
// divergence here rejects every bound fetch at the edge, and the only symptom
// there is an undifferentiated 403 — so this is the test that names the cause.
func TestPoPSignatureBaseMatchesSharedVectors(t *testing.T) {
	t.Parallel()
	fixture := loadJSONFixture[popBaseVectorFile](t, popBaseVectorsPath)
	if len(fixture.Vectors) == 0 {
		t.Fatal("no vectors in the shared base fixture")
	}
	for i, v := range fixture.Vectors {
		if got := PoPSignatureBase(v.Method, v.URL, v.Params); got != v.ExpectedBase {
			t.Errorf("vector %d base mismatch:\n got %q\nwant %q", i, got, v.ExpectedBase)
		}
	}
}

type popSignVectorFile struct {
	Vectors []popSignVector `json:"vectors"`
}

type popSignVector struct {
	Name           string `json:"name"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	AgentID        string `json:"agent_id"`
	PresentedKey   string `json:"presented_key_b64url"`
	SignerSeedHex  string `json:"signer_seed_hex"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
}

// TestSignAgentBindingMatchesSharedVectors pins the three EMITTED header values
// against the corpus the edge worker and the Python harness are built around.
//
// It signs through the protocol module, which owns the Go signer now. The
// property under test is therefore not "our code is self-consistent" but "the
// module still emits what our verifiers expect" — the check that used to exist
// downstream and went with the signer.
//
// One vector is not a byte pin here. It presents a key the agent_id does not
// name, which a verifier treats as a thumbprint mismatch and a SIGNER refuses
// outright: mispairing a key and a keyid is a custody fault, and the module
// declines rather than minting a proof that names one key while carrying
// another. On this side that vector pins the refusal.
func TestSignAgentBindingMatchesSharedVectors(t *testing.T) {
	t.Parallel()
	fixture := loadJSONFixture[popSignVectorFile](t, popSignVectorsPath)
	if len(fixture.Vectors) == 0 {
		t.Fatal("no vectors in the shared signing fixture")
	}
	// Both KINDS have to be present, not just some vectors. The two branches
	// below assert opposite things — one compares emitted bytes, the other pins a
	// refusal — and which one a vector takes is decided by the vector itself. A
	// corpus that drifted to all-mismatch would run no byte comparison at all and
	// still report green, which is the shape a non-empty check cannot see.
	//
	// Counted out here rather than inside the subtests because the classification
	// is a pure function of the vector, and the subtests run in parallel.
	var bytePins, refusalPins int
	for _, v := range fixture.Vectors {
		if v.pinsBytes(t) {
			bytePins++
			continue
		}
		refusalPins++
	}
	if bytePins == 0 || refusalPins == 0 {
		t.Fatalf("fixture has %d byte-pin and %d refusal vectors; the suite needs at least one of each",
			bytePins, refusalPins)
	}

	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			signer, pub, opts := v.signingInputs(t)
			binding, err := helpers.SignAgentBinding(t.Context(), signer, pub, opts)

			if !v.pinsBytes(t) {
				if !errors.Is(err, helpers.ErrKeyIDMismatch) {
					t.Fatalf("signing a mispaired key returned %v, want ErrKeyIDMismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("sign agent binding: %v", err)
			}
			if binding.AgentKey != v.PresentedKey {
				t.Errorf("agent key header:\n got %q\nwant %q", binding.AgentKey, v.PresentedKey)
			}
			if binding.SignatureInput != v.SignatureInput {
				t.Errorf("signature-input header:\n got %q\nwant %q", binding.SignatureInput, v.SignatureInput)
			}
			if binding.Signature != v.Signature {
				t.Errorf("signature header:\n got %q\nwant %q", binding.Signature, v.Signature)
			}
		})
	}
}

// pinsBytes reports which of the two things a vector is for: the emitted header
// bytes, or the signer's refusal.
//
// A vector whose agent_id is the thumbprint of the key it presents describes a
// proof a correct signer produces, so its three header values are byte pins. One
// that presents a different key describes a proof no signer will mint — the
// module refuses a mispaired key and keyid outright — so on this side it pins
// that refusal instead.
func (v popSignVector) pinsBytes(t *testing.T) bool {
	t.Helper()
	pub, err := base64.RawURLEncoding.DecodeString(v.PresentedKey)
	if err != nil {
		t.Fatalf("decode presented key: %v", err)
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return thumbprint == v.AgentID
}

// signingInputs decodes one vector into what the signer takes. The two instants
// come out of the vector's own parameter list, so the proof is signed over
// exactly the parameters it is then compared against.
func (v popSignVector) signingInputs(t *testing.T) (helpers.Signer, []byte, helpers.PoPOptions) {
	t.Helper()
	pub, err := base64.RawURLEncoding.DecodeString(v.PresentedKey)
	if err != nil {
		t.Fatalf("decode presented key: %v", err)
	}
	seed, err := hex.DecodeString(v.SignerSeedHex)
	if err != nil {
		t.Fatalf("decode signer seed: %v", err)
	}
	signer, err := helpers.NewEd25519SignerFromSeed(v.AgentID, seed)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	created, expires, err := PoPWindowOf(v.SignatureInput)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pub, helpers.PoPOptions{
		URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires, Method: v.Method,
	}
}
