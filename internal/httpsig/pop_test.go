package httpsig

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The two fixtures below are the cross-language contract for the agent-binding
// profile. Paths are relative to this package directory; both live at the repo
// root because the TypeScript edge and the Python e2e harness read them too.
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

type popSignVectorFile struct {
	Vectors []struct {
		Name               string `json:"name"`
		Method             string `json:"method"`
		URL                string `json:"url"`
		AgentID            string `json:"agent_id"`
		PresentedKeyB64URL string `json:"presented_key_b64url"`
		SignerSeedHex      string `json:"signer_seed_hex"`
		SignatureInput     string `json:"signature_input"`
		Signature          string `json:"signature"`
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

// popWindow pulls created/expires back out of a vector's Signature-Input. The
// fixture carries them only inside that string, and reading them from it keeps
// the test driven by the fixture rather than by constants copied beside it.
var popWindow = regexp.MustCompile(`created=(\d+);expires=(\d+)`)

func popWindowOf(t *testing.T, signatureInput string) (created, expires int64) {
	t.Helper()
	m := popWindow.FindStringSubmatch(signatureInput)
	if m == nil {
		t.Fatalf("no created/expires in %q", signatureInput)
	}
	created, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		t.Fatalf("parse created: %v", err)
	}
	if expires, err = strconv.ParseInt(m[2], 10, 64); err != nil {
		t.Fatalf("parse expires: %v", err)
	}
	return created, expires
}

func popKeyOf(t *testing.T, seedHex string) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public half is not an ed25519 key")
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return priv, pub, thumbprint
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

// TestSignAgentBindingMatchesSharedVectors asserts the emitted header values
// byte for byte against the SDK's generated corpus. It covers, in one pass, the
// parameter order, the base bytes, the keyid derivation, and the encoding
// asymmetry between the base64url agent key and the standard-base64 signature.
//
// Vectors whose presented key does not hash to agent_id are the edge's
// thumbprint-mismatch attack, and are handled separately below: this signer
// refuses to mint one at all.
func TestSignAgentBindingMatchesSharedVectors(t *testing.T) {
	t.Parallel()
	fixture := loadJSONFixture[popSignVectorFile](t, popSignVectorsPath)
	if len(fixture.Vectors) == 0 {
		t.Fatal("no vectors in the shared signing fixture")
	}
	honest := 0
	for _, v := range fixture.Vectors {
		priv, pub, thumbprint := popKeyOf(t, v.SignerSeedHex)
		if thumbprint != v.AgentID {
			continue // the mismatch attack; see TestSignAgentBindingRefusesMismatchedKeyID
		}
		honest++
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			created, expires := popWindowOf(t, v.SignatureInput)
			got, err := SignAgentBinding(context.Background(), priv, PoPOptions{
				URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires, Method: v.Method,
			})
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if want := base64.RawURLEncoding.EncodeToString(pub); got.AgentKey != want {
				t.Errorf("agent key:\n got %q\nwant %q", got.AgentKey, want)
			}
			if got.AgentKey != v.PresentedKeyB64URL {
				t.Errorf("agent key vs fixture:\n got %q\nwant %q", got.AgentKey, v.PresentedKeyB64URL)
			}
			if got.SignatureInput != v.SignatureInput {
				t.Errorf("signature-input:\n got %q\nwant %q", got.SignatureInput, v.SignatureInput)
			}
			if got.Signature != v.Signature {
				t.Errorf("signature:\n got %q\nwant %q", got.Signature, v.Signature)
			}
		})
	}
	if honest == 0 {
		t.Fatal("no honest vectors exercised the signer")
	}
}

// TestSignAgentBindingRefusesMismatchedKeyID covers the corpus's wrong-key
// vector from the signing side. The edge answers thumbprint_mismatch for it;
// this signer will not produce it in the first place, because a keyid that is
// not the thumbprint of the key in hand can only come from a custody layer that
// paired the two wrongly.
//
// The base is still pinned against the vector, by signing it directly: getting
// the refusal right is worthless if the bytes we would have signed were wrong.
func TestSignAgentBindingRefusesMismatchedKeyID(t *testing.T) {
	t.Parallel()
	fixture := loadJSONFixture[popSignVectorFile](t, popSignVectorsPath)
	checked := 0
	for _, v := range fixture.Vectors {
		priv, _, thumbprint := popKeyOf(t, v.SignerSeedHex)
		if thumbprint == v.AgentID {
			continue
		}
		checked++
		created, expires := popWindowOf(t, v.SignatureInput)
		_, err := SignAgentBinding(context.Background(), priv, PoPOptions{
			URL: v.URL, KeyID: v.AgentID, Created: created, Expires: expires, Method: v.Method,
		})
		if !errors.Is(err, ErrKeyIDMismatch) {
			t.Fatalf("%s: want ErrKeyIDMismatch, got %v", v.Name, err)
		}
		// The bytes the attacker's signer did produce must still match ours, or a
		// base bug could hide behind the refusal above.
		params := popSignatureParams(v.AgentID, created, expires)
		raw := ed25519.Sign(priv, []byte(PoPSignatureBase(v.Method, v.URL, params)))
		if want := popLabel + "=:" + base64.StdEncoding.EncodeToString(raw) + ":"; want != v.Signature {
			t.Errorf("%s signature over our base:\n got %q\nwant %q", v.Name, want, v.Signature)
		}
	}
	if checked == 0 {
		t.Fatal("the corpus carries no mismatched-keyid vector")
	}
}

// TestSignAgentBindingRefusals covers every precondition. Each one exists
// because emitting the signature anyway would produce a proof that is accepted
// somewhere while meaning nothing — the failure mode this profile cannot afford.
func TestSignAgentBindingRefusals(t *testing.T) {
	t.Parallel()
	const url = "https://cdn.example/doc?agent_id=x"
	priv, _, thumbprint := popKeyOf(t,
		"333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152")
	valid := PoPOptions{URL: url, KeyID: thumbprint, Created: 1700000000, Expires: 1700000600}

	tests := []struct {
		name string
		priv ed25519.PrivateKey
		mut  func(o PoPOptions) PoPOptions
		want error
	}{
		{"short key", ed25519.PrivateKey("too short"), func(o PoPOptions) PoPOptions { return o }, ErrInvalidSigningKey},
		{"no url", priv, func(o PoPOptions) PoPOptions { o.URL = ""; return o }, ErrMissingTargetURI},
		{"no keyid", priv, func(o PoPOptions) PoPOptions { o.KeyID = ""; return o }, ErrMissingKeyID},
		{"no created", priv, func(o PoPOptions) PoPOptions { o.Created = 0; return o }, ErrMissingCreated},
		{"no expires", priv, func(o PoPOptions) PoPOptions { o.Expires = 0; return o }, ErrMissingExpires},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := SignAgentBinding(context.Background(), tc.priv, tc.mut(valid)); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestSignAgentBindingDefaultsToGET pins the Method default. @method is covered,
// so a proof minted for a GET cannot be lifted onto a write — and the default
// is what almost every caller will rely on without stating it.
func TestSignAgentBindingDefaultsToGET(t *testing.T) {
	t.Parallel()
	const url = "https://cdn.example/doc?agent_id=x"
	priv, _, thumbprint := popKeyOf(t,
		"333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152")
	opts := PoPOptions{URL: url, KeyID: thumbprint, Created: 1700000000, Expires: 1700000600}

	implicit, err := SignAgentBinding(context.Background(), priv, opts)
	if err != nil {
		t.Fatalf("sign implicit: %v", err)
	}
	opts.Method = http.MethodGet
	explicit, err := SignAgentBinding(context.Background(), priv, opts)
	if err != nil {
		t.Fatalf("sign explicit: %v", err)
	}
	if implicit.Signature != explicit.Signature {
		t.Errorf("empty Method did not default to GET:\n got %q\nwant %q",
			implicit.Signature, explicit.Signature)
	}
}

// TestAgentBindingApply pins the header names a fetcher ends up sending. The
// edge looks up exactly these three; a rename here is a silent 403.
func TestAgentBindingApply(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	AgentBinding{AgentKey: "key", SignatureInput: "sig1=params", Signature: "sig1=:sig:"}.Apply(h)

	for header, want := range map[string]string{
		AgentKeyHeader:    "key",
		"Signature-Input": "sig1=params",
		"Signature":       "sig1=:sig:",
	} {
		if got := h.Get(header); got != want {
			t.Errorf("%s: got %q, want %q", header, got, want)
		}
	}
}
