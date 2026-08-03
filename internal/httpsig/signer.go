package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/yaronf/httpsign"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
)

// SignatureAgentHeader is the RFC 9421 covered header (Web Bot Auth) that
// carries the signer's own directory origin, e.g. "https://agent.example". It
// binds the pointer a verifier follows to fetch the signer's WBA directory and
// resolve the RFC 9421 keyid (an RFC 7638 thumbprint) against it. Because the
// header is covered, an attacker cannot repoint discovery under a valid
// signature. Its lowercase form is the covered-component name.
//
// The name itself lives in internal/agentid, which this package already depends
// on for reading the header: the reader and the constant naming the field it
// reads must not be able to disagree. Re-exported here so callers spelling it
// through httpsig keep working.
const (
	SignatureAgentHeader = agentid.SignatureAgentHeader
	signatureAgentLower  = "signature-agent"
)

// setContentDigest sets Content-Digest to the SHA-256 of body.
func setContentDigest(req *http.Request, body []byte) {
	sum := sha256.Sum256(body)
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
}

// bindAuthorization ensures the Authorization header is present so the signature
// commits to its value (the empty string included) and a later injection cannot
// piggy-back the same signature.
func bindAuthorization(req *http.Request) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "")
	}
}

// bindSignatureAgent ensures the Signature-Agent header is present so the
// signature always commits to the discovery pointer (the empty string
// included). A signer that knows its own directory origin sets the header
// before signing; one that does not (the static bootstrap path, where the keyid
// thumbprint is resolved without discovery) still binds the empty value so the
// covered-component set is uniform and the verifier's requirement is met.
func bindSignatureAgent(req *http.Request) {
	if req.Header.Get(SignatureAgentHeader) == "" {
		req.Header.Set(SignatureAgentHeader, "")
	}
}

// rampCoveredComponents returns the covered-component set the RAMP interceptor
// requires — the same base list the verifier enforces via
// requiredCoveredComponents (which includes signature-agent) — plus
// x-ramp-entitlement-biscuit when that header is present on h. Signer and
// verifier derive from one base so they cannot silently diverge.
func rampCoveredComponents(h http.Header) []CoveredComponent {
	names := append([]string(nil), requiredCoveredComponents...)
	if h.Get("X-RAMP-Entitlement-Biscuit") != "" {
		names = append(names, entitlementHeaderLower)
	}
	return plainComponents(names...)
}

// rampChainCoveredComponents returns the covered set for an appended signature
// (sigN, N>1): the RAMP base set plus a forwarding-chain link
// "signature";key="<prevLabel>" so sigN cryptographically commits to its
// predecessor (RFC 9421 §2.4). When hasPrev is false it degrades to the
// plain base set (identical to a sig1 covered set).
func rampChainCoveredComponents(h http.Header, prevLabel string, hasPrev bool) []CoveredComponent {
	covered := rampCoveredComponents(h)
	if hasPrev {
		covered = append(covered, CoveredComponent{
			Name:   "signature",
			Params: []ComponentParam{{Key: "key", Val: prevLabel}},
		})
	}
	return covered
}

// sigWriteMode selects whether signWithParams replaces or appends the emitted
// Signature-Input / Signature headers.
type sigWriteMode int

const (
	sigWriteSet sigWriteMode = iota
	sigWriteAppend
)

// signWithParams translates params into a yaronf Fields + SignConfig, signs the
// request with priv via httpsign.SignRequest, and writes the returned
// Signature-Input / Signature header strings per mode. Shared by
// SignRequestRAMP and AppendSignatureRAMP so library translation and header
// emission live in one place.
//
// In append mode the predecessor's Signature/Signature-Input headers MUST
// already be present on req before this call: yaronf reads the existing
// Signature header to resolve a "signature";key="sigN-1" chain-link component to
// its predecessor's bytes.
func signWithParams(req *http.Request, params Params, priv ed25519.PrivateKey, mode sigWriteMode) error {
	// Every exported signer funnels through here, so this is the one place the key
	// length has to be checked. The library below does reject a wrong-length key,
	// but only as an opaque string ("key must be 64 bytes long") wrapped into the
	// generic sign-request failure, which leaves a caller no way to tell "this key
	// is unusable" from "signing failed" without matching on message text. Checking
	// here makes it an ErrInvalidSigningKey a caller can branch on, and does it
	// before any request mutation.
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: signing key is %d bytes, want %d",
			ErrInvalidSigningKey, len(priv), ed25519.PrivateKeySize)
	}
	fields, err := coveredToFields(params.Covered)
	if err != nil {
		return err
	}
	cfg := httpsign.NewSignConfig().SetKeyID(params.KeyID).SignCreated(true).SignAlg(true)
	if params.Expires != 0 {
		cfg = cfg.SetExpires(params.Expires)
	}
	// tag and nonce are the Web Bot Auth profile's parameters; the RAMP profile
	// leaves both empty and they stay off the wire.
	if params.Tag != "" {
		cfg = cfg.SetTag(params.Tag)
	}
	if params.Nonce != "" {
		cfg = cfg.SetNonce(params.Nonce)
	}
	signer, err := httpsign.NewEd25519Signer(priv, cfg, fields)
	if err != nil {
		return fmt.Errorf("httpsig: build signer: %w", err)
	}
	sigInput, sigValue, err := httpsign.SignRequest(params.Label, *signer, req)
	if err != nil {
		return fmt.Errorf("httpsig: sign request: %w", err)
	}
	if mode == sigWriteAppend {
		if existing := req.Header.Get("Signature-Input"); existing != "" {
			sigInput = existing + ", " + sigInput
		}
		if existing := req.Header.Get("Signature"); existing != "" {
			sigValue = existing + ", " + sigValue
		}
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sigValue)
	return nil
}

// coveredToFields translates a RAMP covered-component set into a yaronf Fields.
// Plain components map to AddHeader; a "signature" component carrying a key
// param maps to AddDictHeader("signature", key) — the RFC 9421 §2.4
// dictionary-member reference that is the forwarding-chain link.
func coveredToFields(covered []CoveredComponent) (httpsign.Fields, error) {
	f := httpsign.NewFields()
	for _, c := range covered {
		if strings.EqualFold(c.Name, "signature") {
			key := componentParam(c, "key")
			if key == "" {
				return httpsign.Fields{}, fmt.Errorf("%w: signature component missing key param", ErrMalformedSignatureInput)
			}
			f = f.AddDictHeader("signature", key)
			continue
		}
		f = f.AddHeader(c.Name)
	}
	return *f, nil
}

// SignRequest signs req over an ARBITRARY covered-component set — the general
// signer every profile is built from. It is exported so a caller outside the RAMP
// profile (notably the Web Bot Auth profile in wba.go, which covers @authority and
// signature-agent instead) signs through the SAME path rather than growing a
// second RFC 9421 implementation with its own canonicalization bugs.
//
// Content-Digest is computed from body and set on req IFF params.Covered names
// content-digest. That keeps the digest a signature commits to equal to the bytes
// handed here, and leaves a bodyless request (a plain WBA GET) with no digest
// header at all. Every other covered component must already be present on req —
// binding a header the caller has not set yet is profile policy, not the general
// signer's business.
//
// An empty params.Label defaults to "sig1", the first-signature label.
//
// yaronf/httpsign stamps created = now() at signing time; there is no exported
// hook to override it, so this signer takes no created parameter.
func SignRequest(req *http.Request, body []byte, priv ed25519.PrivateKey, params Params) error {
	if params.Label == "" {
		params.Label = "sig1"
	}
	if coversComponent(params.Covered, "content-digest") {
		setContentDigest(req, body)
	}
	return signWithParams(req, params, priv, sigWriteSet)
}

// SignRequestRAMP signs req with the coverage set required by the RAMP
// interceptor: @method, @target-uri, content-digest, authorization, plus
// x-ramp-entitlement-biscuit when that header is populated on req. The
// Authorization header MUST already be set on req (empty string is legal —
// the interceptor binds whatever value is present so a later header swap is
// detected). expires is the unix-seconds cutoff after which the signature
// becomes invalid.
//
// yaronf/httpsign stamps created = now() at signing time; there is no exported
// hook to override it, so this signer takes no created parameter.
func SignRequestRAMP(
	req *http.Request, body []byte, keyID string,
	priv ed25519.PrivateKey, expires int64,
) error {
	bindAuthorization(req)
	bindSignatureAgent(req)
	params := Params{
		Label:   "sig1",
		Covered: rampCoveredComponents(req.Header),
		KeyID:   keyID,
		Alg:     "ed25519",
		Expires: expires,
	}
	return SignRequest(req, body, priv, params)
}

// AppendSignatureRAMP adds a new signature to req WITHOUT replacing existing
// signatures. Parses existing Signature-Input, finds max label number N, signs
// with label sigN+1. The coverage set is the RAMP base (@method, @target-uri,
// content-digest, authorization, plus x-ramp-entitlement-biscuit when present)
// PLUS a forwarding-chain link "signature";key="sigN" committing to the
// immediate predecessor (RFC 9421 §2.4), so the ordered signatures form
// a chain a relay cannot strip or reorder.
//
// When no existing signatures are present, no chain link is added and this
// behaves identically to SignRequestRAMP (a sig1). Content-Digest and
// Authorization headers are preserved (not overwritten) when already set.
//
// yaronf/httpsign stamps created = now() at signing time; there is no exported
// hook to override it, so this signer takes no created parameter.
//
// A Signature-Input header that is present but unparseable is rejected with an
// ErrMalformedSignatureInput-wrapped error rather than treated as "no
// signatures": a relay must fail fast instead of co-signing a fresh sig1 over a
// malformed envelope.
func AppendSignatureRAMP(
	req *http.Request, body []byte, keyID string,
	priv ed25519.PrivateKey, expires int64,
) error {
	// Preserve an existing Content-Digest (set by the first signer); only
	// compute it when missing.
	if req.Header.Get("Content-Digest") == "" {
		setContentDigest(req, body)
	}
	bindAuthorization(req)
	bindSignatureAgent(req)
	maxN, err := maxSignatureLabelN(req.Header)
	if err != nil {
		return err
	}
	prevLabel, hasPrev := "", false
	if maxN > 0 {
		prevLabel, hasPrev = fmt.Sprintf("sig%d", maxN), true
	}
	params := Params{
		Label:   fmt.Sprintf("sig%d", maxN+1),
		Covered: rampChainCoveredComponents(req.Header, prevLabel, hasPrev),
		KeyID:   keyID,
		Alg:     "ed25519",
		Expires: expires,
	}
	return signWithParams(req, params, priv, sigWriteAppend)
}

// maxSignatureLabelN scans Signature-Input for the highest sigN label and
// returns N, deriving the append chain position for AppendSignatureRAMP.
// Parsing goes through httpsfv so the label set matches the verifier's view.
//
// Returns (0, nil) when no Signature-Input header is present — the no-signatures
// case, a valid sig1 append. Returns an ErrMalformedSignatureInput-wrapped error
// when a Signature-Input header IS present but cannot be parsed, so the append
// path fails fast instead of co-signing a fresh sig1 over a malformed envelope.
func maxSignatureLabelN(h http.Header) (int, error) {
	values := h.Values("Signature-Input")
	if len(values) == 0 {
		return 0, nil
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrMalformedSignatureInput, err)
	}
	maxN := 0
	for _, label := range dict.Names() {
		if !strings.HasPrefix(label, "sig") {
			continue
		}
		// Atoi rejects trailing junk (e.g. "sig1x"), unlike Sscanf which would
		// stop at the first non-digit and accept it as sig1.
		if num, err := strconv.Atoi(strings.TrimPrefix(label, "sig")); err == nil && num > maxN {
			maxN = num
		}
	}
	return maxN, nil
}
