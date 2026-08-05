// Package httpsig implements the subset of RFC 9421 (HTTP Message Signatures)
// RAMP needs to verify signed RPCs from agents and broker relays.
//
// Implementation choice: the canonicalization, signature-base construction, and
// ed25519 sign/verify are delegated to github.com/yaronf/httpsign; the
// structured-field parsing of the Signature-Input / Signature headers is
// delegated to github.com/dunglas/httpsfv; JWK Set decoding (well-known key
// resolution) is delegated to github.com/go-jose/go-jose/v4. yaronf is the
// canonicalization AUTHORITY for the RAMP and Web Bot Auth profiles — it
// serializes the @signature-params parameters in the order
// created;expires;alg;keyid. This package keeps the RAMP-specific
// policy on top of those libraries: the required covered-component set, the
// ed25519 algorithm allowlist, the created/expires window, content-digest
// verification, the forwarding-chain structure gate, the replay store, the key
// resolvers, and the net/http middleware.
//
// Scope note: production request verification runs through the SDK's
// connectserver middleware in every service; this package's verify side
// (VerifyRequest, VerifyMultisigRequest, Middleware) is kept as the reference
// verifier the signing suites here and in internal/ramphttpsig assert
// against. Resolver composition lives in internal/keypolicy — the composite
// this package once carried was an unused line-for-line copy and was deleted.
//
// The agent-binding profile in pop.go is the ONE exception: it builds its own
// signature base. Two properties of that wire contract lie outside what yaronf
// can express, and neither is negotiable — the parameter order is
// keyid;alg;created;expires, and created is an injected value rather than now(),
// which yaronf stamps itself with no override hook. The contract belongs to the
// delivery edge, whose verifier is the SDK's TypeScript face, so a second base
// builder is the cost of speaking it. The shared vectors
// (testdata/pop-signature-base-vectors.json for the base,
// testdata/pop-sign-vectors.json for the emitted headers) are what keep the two
// builders from drifting apart unnoticed.
package httpsig

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// ErrMissingSignatureInput is returned when Signature-Input is absent.
var ErrMissingSignatureInput = errors.New("httpsig: missing Signature-Input header")

// ErrMissingSignature is returned when Signature is absent.
var ErrMissingSignature = errors.New("httpsig: missing Signature header")

// ErrMissingContentDigest is returned when Content-Digest is absent but
// required by the coverage set.
var ErrMissingContentDigest = errors.New("httpsig: missing Content-Digest header")

// ErrMalformedSignatureInput is returned when the Signature-Input value cannot
// be parsed per the RFC 9421 structured-field grammar (subset we support).
var ErrMalformedSignatureInput = errors.New("httpsig: malformed Signature-Input")

// ErrUnsupportedAlgorithm is returned when the declared alg is not ed25519.
var ErrUnsupportedAlgorithm = errors.New("httpsig: unsupported alg (ed25519 only)")

// ErrDigestMismatch is returned when the body does not match Content-Digest.
var ErrDigestMismatch = errors.New("httpsig: content-digest mismatch")

// ErrSignatureVerify is returned when the ed25519 verify step fails.
var ErrSignatureVerify = errors.New("httpsig: signature verification failed")

// ErrBrokenSignatureChain is returned when a multisig request's signatures do
// not form a valid forwarding chain: labels are non-contiguous, reordered, or a
// sigN (N>1) does not cover exactly its predecessor via "signature";key="sigN-1"
// (forwarding chain, RFC 9421 §2.4).
var ErrBrokenSignatureChain = errors.New("httpsig: signature chain broken (gap/reorder/missing link)")

// ErrTooManyHops is returned when the number of signatures on a request exceeds
// the verifier's configured MaxSignatures budget (Exchange hop bound).
var ErrTooManyHops = errors.New("httpsig: signature count exceeds hop budget")

// ErrInvalidSigningKey is returned by the SIGNING path when the private key is
// not an ed25519 key of the right length. The sentinels above are the verifier's;
// this one is the signer's. The library underneath does catch a bad key, but only
// as free text folded into its generic sign failure — this makes the condition
// matchable without parsing a message.
var ErrInvalidSigningKey = errors.New("httpsig: invalid ed25519 signing key")

// ComponentParam is a single RFC 9421 §2.4 parameter on a covered-component
// identifier — e.g. the key="sig1" on `"signature";key="sig1"`.
type ComponentParam struct {
	Key string
	Val string
}

// CoveredComponent is one entry in a signature's covered-component set: a
// component name plus any RFC 9421 component parameters. Plain components
// (@method, content-digest, ...) carry nil Params; a forwarding-chain link
// carries a single {Key:"key", Val:"sigN-1"} param on Name "signature".
type CoveredComponent struct {
	Name   string
	Params []ComponentParam
}

// coversComponent reports whether covered names component (case-insensitively,
// as RFC 9421 component identifiers are lowercase but callers spell headers
// however they like). Signer and verifier share it so "is the body bound?" is
// decided the same way on both sides.
func coversComponent(covered []CoveredComponent, name string) bool {
	for _, c := range covered {
		if strings.EqualFold(c.Name, name) {
			return true
		}
	}
	return false
}

// plainComponents builds CoveredComponents with no parameters from names.
func plainComponents(names ...string) []CoveredComponent {
	out := make([]CoveredComponent, 0, len(names))
	for _, n := range names {
		out = append(out, CoveredComponent{Name: n})
	}
	return out
}

// Params captures the parameters parsed from a single Signature-Input label.
//
// Tag and Nonce belong to the Web Bot Auth profile: a WBA verifier requires
// tag="web-bot-auth" and reads nonce as the per-request replay guard. They are
// empty on the RAMP profile, which binds freshness through created/expires plus
// the server-side replay store instead.
type Params struct {
	Label   string
	Covered []CoveredComponent
	KeyID   string
	Alg     string
	Created int64
	Expires int64
	Tag     string
	Nonce   string
}

// verifyContentDigest checks the Content-Digest header when the coverage set
// includes it. RFC 9421 + RFC 9530: sha-256=:<base64>:. This is RAMP policy
// (body integrity) and is enforced here rather than delegated, so the digest
// failure surfaces as ErrDigestMismatch independently of the signature check.
func verifyContentDigest(h http.Header, body []byte, covered []CoveredComponent) error {
	if !coversComponent(covered, "content-digest") {
		return nil
	}
	raw := h.Get("Content-Digest")
	if raw == "" {
		return ErrMissingContentDigest
	}
	sum := sha256.Sum256(body)
	expected := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if strings.TrimSpace(raw) != expected {
		return ErrDigestMismatch
	}
	return nil
}
