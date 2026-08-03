package httpsig

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// AgentKeyHeader carries the raw Ed25519 public key the fetcher presents, as
// base64url-no-pad. ADR-013 D1 chose a dedicated header over an inline JWK in
// keyid: the edge hashes this value and requires the digest to equal the URL's
// agent_id, so a fetcher cannot present one key while naming another.
const AgentKeyHeader = "X-RAMP-Agent-Key"

// popLabel is the only signature label this profile emits. Unlike the RAMP
// profile there is no forwarding chain here — a delivery fetch is a single hop
// to the edge — so sigN>1 never arises and the label is fixed rather than
// computed.
const popLabel = "sig1"

// ErrMissingTargetURI is returned when a proof is requested without the URL it
// is meant to bind. @target-uri is half the covered set; signing without it
// would produce a proof valid for any URL the presented key is offered against,
// which is the replay this profile exists to stop.
var ErrMissingTargetURI = errors.New("httpsig: missing target URI (required by the agent-binding profile)")

// A proof requested without a created timestamp reuses the verifier's
// ErrMissingCreated: one condition seen from two ends, the same arrangement
// wba.go makes with ErrMissingExpires. The edge refuses a signature carrying no
// created (pop_missing_created), but the reason to refuse it HERE is subtler:
// the edge does not bound how old created may be, only how far in the future. A
// zero created therefore sails through as a signature claiming 1970 — freshness
// silently absent rather than loudly wrong.

// ErrKeyIDMismatch is returned when the caller-supplied keyid is not the RFC
// 7638 thumbprint of the key doing the signing. The edge checks the same
// equality and answers thumbprint_mismatch, but by then the cause — a custody
// layer that paired a keyid with the wrong private key — is three services away
// from the symptom. Refusing here names it at the source.
var ErrKeyIDMismatch = errors.New("httpsig: keyid is not the thumbprint of the signing key")

// PoPOptions carries what a delivery-URL proof of possession needs beyond the
// key. Every field is required except Method, which defaults to GET.
type PoPOptions struct {
	// URL is the signed delivery URL, used VERBATIM as @target-uri — the exact
	// bytes the Exchange minted, query parameters and all.
	//
	// This is a string and not an *http.Request on purpose. The edge rebuilds the
	// base from the raw request line it received, so any re-serialization on the
	// signing side is a divergence: url.URL.String() re-encodes, and building the
	// component from URL.Path hands over the DECODED path. Either produces a base
	// the edge cannot reconstruct, and the failure is a blanket 403 with no
	// indication that the URL was the problem.
	URL string
	// KeyID is the RFC 9421 keyid: the RFC 7638 thumbprint of the signing key's
	// public half. It is the anchor of the three-way identity the edge enforces —
	// agent_id (in the URL, covered by the Exchange's own signature) == keyid ==
	// thumbprint(presented key). Cross-checked against the key before signing.
	KeyID string
	// Created is the unix-seconds instant the proof was made. The edge rejects a
	// created more than 300s in its own future, so a signer whose clock runs fast
	// fails closed.
	Created int64
	// Expires is the unix-seconds cutoff after which the proof is stale. Keep it
	// short: the covered set is only method and URL, so within this window the
	// proof is replayable by anyone who observes the request.
	Expires int64
	// Method is the HTTP method being signed. Empty means GET. A signed URL is
	// read-only in practice, but @method is covered precisely so a proof made for
	// a GET cannot be lifted onto a write.
	Method string
}

// AgentBinding is the proof a fetcher attaches to a bound delivery request: the
// three header values, ready to apply. It is returned as values rather than
// written straight onto a request so a caller can sign without having built the
// request yet, and so the emitted bytes can be asserted directly against the
// shared cross-language vectors.
type AgentBinding struct {
	// AgentKey is the X-RAMP-Agent-Key value: base64url-no-pad, no padding.
	AgentKey string
	// SignatureInput is the full Signature-Input value, label included.
	SignatureInput string
	// Signature is the full Signature value, label included. The byte string
	// inside the colons is STANDARD base64 while AgentKey above is base64url —
	// an asymmetry that comes from RFC 8941's byte-sequence encoding meeting a
	// header this profile defines itself, and one a verifier will not forgive.
	Signature string
}

// Apply writes the binding's three headers onto h.
func (b AgentBinding) Apply(h http.Header) {
	h.Set(AgentKeyHeader, b.AgentKey)
	h.Set("Signature-Input", b.SignatureInput)
	h.Set("Signature", b.Signature)
}

// PoPSignatureBase builds the RFC 9421 signature base for the agent-binding
// profile: the two covered components followed by the parameters line, joined
// with newlines and with no trailing newline.
//
// It is exported because it is the one string every implementation of this
// profile must agree on byte for byte — the SDK's TypeScript signatureBase, the
// e2e harness's Python signer, and this signer are all pinned to the same
// vectors (testdata/pop-signature-base-vectors.json). A divergence in line
// order, quoting, or spacing rejects every bound fetch, and the symptom is an
// undifferentiated 403.
//
// rawParams is taken as given rather than rebuilt: on the verifying side it
// arrives verbatim in the Signature-Input header, so treating it as an opaque
// string here is what keeps the two faces symmetric.
func PoPSignatureBase(method, rawURL, rawParams string) string {
	return strings.Join([]string{
		`"@method": ` + strings.ToUpper(method),
		`"@target-uri": ` + rawURL,
		`"@signature-params": ` + rawParams,
	}, "\n")
}

// popSignatureParams renders the @signature-params value for this profile.
//
// The parameter ORDER is part of the wire contract, not a formatting choice:
// the base is signed over this exact string and the verifier reconstructs it
// from the header as received. It is deliberately NOT the order the rest of
// this package emits — yaronf serializes created;expires;alg;keyid, whereas
// this profile is keyid;alg;created;expires, matching the SDK's TypeScript and
// Python faces. That mismatch is the whole reason this profile builds its own
// base instead of routing through SignRequest.
func popSignatureParams(keyID string, created, expires int64) string {
	return fmt.Sprintf(
		`("@method" "@target-uri");keyid=%q;alg=%q;created=%d;expires=%d`,
		keyID, helpers.AlgEd25519, created, expires,
	)
}

// SignAgentBinding produces the proof of possession a fetcher presents when it
// retrieves a delivery URL bound to an agent key (ADR-013 D1-D3). The covered
// set is exactly @method and @target-uri: a GET carries no body to digest, and
// the signed URL is itself the credential, so there is no Authorization header
// worth binding.
//
// The signing itself goes through the SDK's Signer rather than a direct
// ed25519.Sign. That keeps the raw crypto behind the interface a remote custody
// backend (Transit, KMS, an HSM) would implement, which is where this repo has
// decided key operations belong — and it is why ctx is a parameter here even
// though the local signer ignores it.
func SignAgentBinding(
	ctx context.Context, priv ed25519.PrivateKey, opts PoPOptions,
) (AgentBinding, error) {
	pub, err := validatePoP(priv, opts)
	if err != nil {
		return AgentBinding{}, err
	}
	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}
	params := popSignatureParams(opts.KeyID, opts.Created, opts.Expires)
	base := PoPSignatureBase(method, opts.URL, params)

	signer, err := helpers.NewEd25519Signer(opts.KeyID, priv)
	if err != nil {
		return AgentBinding{}, fmt.Errorf("httpsig: build agent-binding signer: %w", err)
	}
	raw, err := signer.Sign(ctx, []byte(base))
	if err != nil {
		return AgentBinding{}, fmt.Errorf("httpsig: sign agent binding: %w", err)
	}
	return AgentBinding{
		AgentKey:       base64.RawURLEncoding.EncodeToString(pub),
		SignatureInput: popLabel + "=" + params,
		Signature:      popLabel + "=:" + base64.StdEncoding.EncodeToString(raw) + ":",
	}, nil
}

// validatePoP checks every precondition of a bound fetch and returns the public
// half the proof will present. It runs before any signing so a caller that has
// mispaired a key and a keyid learns it here rather than from a 403.
func validatePoP(priv ed25519.PrivateKey, opts PoPOptions) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key is %d bytes, want %d",
			ErrInvalidSigningKey, len(priv), ed25519.PrivateKeySize)
	}
	if opts.URL == "" {
		return nil, ErrMissingTargetURI
	}
	if opts.KeyID == "" {
		return nil, ErrMissingKeyID
	}
	if opts.Created <= 0 {
		return nil, ErrMissingCreated
	}
	if opts.Expires <= 0 {
		return nil, ErrMissingExpires
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public half is not an ed25519 key", ErrInvalidSigningKey)
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil {
		return nil, fmt.Errorf("httpsig: derive keyid thumbprint: %w", err)
	}
	if thumbprint != opts.KeyID {
		return nil, fmt.Errorf("%w: keyid %q, key thumbprint %q", ErrKeyIDMismatch, opts.KeyID, thumbprint)
	}
	return pub, nil
}
