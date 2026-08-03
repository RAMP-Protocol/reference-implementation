package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestSignRequest_ArbitraryCoveredSet pins what exporting the general signer
// bought: a caller outside the RAMP profile picks its own covered components and
// the emitted signature verifies over exactly those. Without this the only way to
// sign a non-RAMP covered set would be a second RFC 9421 implementation.
func TestSignRequest_ArbitraryCoveredSet(t *testing.T) {
	t.Parallel()
	priv := fixedKey(0x11)
	req := newWBARequest(t, http.MethodGet, "https://origin.example/thing", nil)
	req.Header.Set("X-Custom", "value")

	params := Params{
		Covered: plainComponents("@method", "@path", "x-custom"),
		KeyID:   "kid-1",
		Alg:     "ed25519",
		Expires: time.Now().Add(time.Minute).Unix(),
	}
	if err := SignRequest(req, nil, priv, params); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !independentVerify(t, req, priv.Public().(ed25519.PublicKey)) {
		t.Fatal("signature over the caller's covered set did not verify")
	}
	got, err := ParseSignatureLabels(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []string{"@method", "@path", "x-custom"}; !equalStrings(coveredNames(got[0].Covered), want) {
		t.Errorf("covered = %v, want %v", coveredNames(got[0].Covered), want)
	}
	// An empty Label defaults to the first-signature label.
	if got[0].Label != "sig1" {
		t.Errorf("label = %q, want sig1", got[0].Label)
	}
}

// TestSignRequest_RejectsMalformedKeyMaterial pins that every exported signer
// refuses a wrong-length key with a sentinel a caller can branch on. The library
// underneath already refuses such a key, but only as free text folded into its
// generic sign failure, so without this the condition is reachable only by
// matching on a message string owned by a dependency. The check lives at the
// shared chokepoint, which is why all four entry points are asserted here.
func TestSignRequest_RejectsMalformedKeyMaterial(t *testing.T) {
	t.Parallel()
	cases := map[string]ed25519.PrivateKey{
		"nil":       nil,
		"too short": []byte("too short"),
		"seed only": ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))[:ed25519.SeedSize],
	}
	for name, priv := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entries := map[string]func(*http.Request) error{
				"SignRequest": func(r *http.Request) error {
					return SignRequest(r, nil, priv, Params{
						Covered: plainComponents("@method"),
						KeyID:   "kid",
						Expires: time.Now().Add(time.Minute).Unix(),
					})
				},
				"SignRequestRAMP": func(r *http.Request) error {
					return SignRequestRAMP(r, nil, "kid", priv, time.Now().Add(time.Minute).Unix())
				},
				"SignRequestWBA": func(r *http.Request) error {
					return SignRequestWBA(r, nil, priv, WBAOptions{
						Directory: "https://alice.example",
						KeyID:     "kid",
						Expires:   time.Now().Add(time.Minute).Unix(),
					})
				},
				"AppendSignatureRAMP": func(r *http.Request) error {
					return AppendSignatureRAMP(r, nil, "kid", priv, time.Now().Add(time.Minute).Unix())
				},
			}
			for entry, sign := range entries {
				t.Run(entry, func(t *testing.T) {
					t.Parallel()
					req := newWBARequest(t, http.MethodGet, "https://origin.example/thing", nil)
					err := sign(req)
					if !errors.Is(err, ErrInvalidSigningKey) {
						t.Fatalf("err = %v, want ErrInvalidSigningKey", err)
					}
					if req.Header.Get("Signature") != "" {
						t.Error("refused signing still wrote a Signature header")
					}
				})
			}
		})
	}
}

// TestSignRequest_ContentDigestFollowsTheCoveredSet pins the one thing the
// general signer does to the request on the caller's behalf: it sets
// Content-Digest when — and only when — the covered set commits to it. Setting it
// unconditionally would put an unsigned digest on a bodyless GET; not setting it
// when covered would sign a digest of whatever the caller happened to leave
// behind.
func TestSignRequest_ContentDigestFollowsTheCoveredSet(t *testing.T) {
	t.Parallel()
	body := []byte(`{"a":1}`)
	sum := sha256.Sum256(body)
	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"

	cases := map[string]struct {
		covered []CoveredComponent
		want    string
	}{
		"covered":     {plainComponents("@method", "content-digest"), wantDigest},
		"not covered": {plainComponents("@method"), ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := newWBARequest(t, http.MethodPost, "https://origin.example/api", body)
			params := Params{
				Covered: tc.covered,
				KeyID:   "kid-1",
				Alg:     "ed25519",
				Expires: time.Now().Add(time.Minute).Unix(),
			}
			if err := SignRequest(req, body, fixedKey(0x12), params); err != nil {
				t.Fatalf("sign: %v", err)
			}
			if got := req.Header.Get("Content-Digest"); got != tc.want {
				t.Errorf("Content-Digest = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSignRequestRAMP_CoveredSetUnchanged guards the refactor that put
// SignRequestRAMP on top of the general signer: the RAMP profile's covered set is
// a wire contract the Exchange verifier mirrors, so it is pinned here rather than
// left to be noticed when an integration suite starts rejecting live traffic.
func TestSignRequestRAMP_CoveredSetUnchanged(t *testing.T) {
	t.Parallel()
	body := []byte(`{"query":"foo"}`)
	req := newWBARequest(t, http.MethodPost, "https://exchange.example/ramp.v1.Service/Method", body)
	if err := SignRequestRAMP(req, body, "kid-1", fixedKey(0x13), time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := ParseSignatureLabels(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"@method", "@target-uri", "content-digest", "authorization", "signature-agent"}
	if !equalStrings(coveredNames(got[0].Covered), want) {
		t.Errorf("covered = %v, want %v", coveredNames(got[0].Covered), want)
	}
	// The RAMP profile carries no WBA parameters; adding them would change the
	// bytes every deployed verifier canonicalizes.
	if got[0].Tag != "" || got[0].Nonce != "" {
		t.Errorf("RAMP signature carries tag=%q nonce=%q, want neither", got[0].Tag, got[0].Nonce)
	}
}
