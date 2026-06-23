package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// BrokerKeyIDPrefix is the keyID prefix that marks a broker relay key on the
// wire (shape "broker.<instance>.<rotation>"). Relay-key loaders stamp it, and
// the multisig classifier uses it to route a signature into the relay slot
// before the authoritative agents.requester_type check. Shared so the
// producing and consuming sides cannot drift.
const BrokerKeyIDPrefix = "broker."

// SignRequest signs req's body with priv using the fixed coverage set used
// by the demo (@method, @path, @authority, content-digest). It mutates req
// to add the Content-Digest, Signature-Input, and Signature headers. body
// must be the exact bytes that will be transmitted on the wire.
//
// Exposed for tests; production callers sign from their own transports.
func SignRequest(req *http.Request, body []byte, keyID string, priv ed25519.PrivateKey, created int64) error {
	setContentDigest(req, body)
	params := Params{
		Label:   "sig1",
		Covered: plainComponents("@method", "@path", "@authority", "content-digest"),
		KeyID:   keyID,
		Alg:     "ed25519",
		Created: created,
	}
	return signWithParams(req, params, priv, sigWriteSet)
}

// signatureInputInner renders the inner list + parameter tail for a label's
// Signature-Input value. It delegates the inner list to quotedList so the header
// and the @signature-params line in the signature base are byte-identical.
func signatureInputInner(p Params) string {
	return "(" + quotedList(p.Covered) + ")" + renderParamsTail(p)
}

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

// rampCoveredComponents returns the covered-component set the RAMP interceptor
// requires — the same base list the verifier enforces via
// requiredCoveredComponents — plus x-ramp-entitlement-biscuit when that header
// is present on h. Signer and verifier derive from one base so they cannot
// silently diverge.
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
// predecessor (RAMP-56, RFC 9421 §2.4). When hasPrev is false it degrades to the
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

// signWithParams builds the signature base for params, signs it with priv, and
// writes the Signature-Input / Signature headers per mode. Shared by
// SignRequest, SignRequestRAMP, and AppendSignatureRAMP so base construction and
// header emission live in one place.
func signWithParams(req *http.Request, params Params, priv ed25519.PrivateKey, mode sigWriteMode) error {
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, []byte(base))
	input := params.Label + "=" + signatureInputInner(params)
	value := fmt.Sprintf("%s=:%s:", params.Label, base64.StdEncoding.EncodeToString(sig))
	if mode == sigWriteAppend {
		if existing := req.Header.Get("Signature-Input"); existing != "" {
			input = existing + ", " + input
		}
		if existing := req.Header.Get("Signature"); existing != "" {
			value = existing + ", " + value
		}
	}
	req.Header.Set("Signature-Input", input)
	req.Header.Set("Signature", value)
	return nil
}

// SignRequestRAMP signs req with the coverage set required by the RAMP
// interceptor: @method, @target-uri, content-digest, authorization, plus
// x-ramp-entitlement-biscuit when that header is populated on req. The
// Authorization header MUST already be set on req (empty string is legal —
// the interceptor binds whatever value is present so a later header swap is
// detected). expires is the unix-seconds cutoff after which the signature
// becomes invalid; created is the unix-seconds issuance time.
func SignRequestRAMP(
	req *http.Request, body []byte, keyID string,
	priv ed25519.PrivateKey, created, expires int64,
) error {
	setContentDigest(req, body)
	bindAuthorization(req)
	params := Params{
		Label:   "sig1",
		Covered: rampCoveredComponents(req.Header),
		KeyID:   keyID,
		Alg:     "ed25519",
		Created: created,
		Expires: expires,
	}
	return signWithParams(req, params, priv, sigWriteSet)
}

// AppendSignatureRAMP adds a new signature to req WITHOUT replacing existing
// signatures. Parses existing Signature-Input, finds max label number N, signs
// with label sigN+1. The coverage set is the RAMP base (@method, @target-uri,
// content-digest, authorization, plus x-ramp-entitlement-biscuit when present)
// PLUS a forwarding-chain link "signature";key="sigN" committing to the
// immediate predecessor (RAMP-56, RFC 9421 §2.4), so the ordered signatures form
// a chain a relay cannot strip or reorder.
//
// When no existing signatures are present, no chain link is added and this
// behaves identically to SignRequestRAMP (a sig1). Content-Digest and
// Authorization headers are preserved (not overwritten) when already set.
func AppendSignatureRAMP(
	req *http.Request, body []byte, keyID string,
	priv ed25519.PrivateKey, created, expires int64,
) error {
	// Preserve an existing Content-Digest (set by the first signer); only
	// compute it when missing.
	if req.Header.Get("Content-Digest") == "" {
		setContentDigest(req, body)
	}
	bindAuthorization(req)
	prevLabel, hasPrev := findPrevLabel(req.Header)
	params := Params{
		Label:   findNextLabel(req.Header),
		Covered: rampChainCoveredComponents(req.Header, prevLabel, hasPrev),
		KeyID:   keyID,
		Alg:     "ed25519",
		Created: created,
		Expires: expires,
	}
	return signWithParams(req, params, priv, sigWriteAppend)
}

// maxSignatureLabelN scans Signature-Input for the highest sigN label and
// returns N (0 when no valid sigN label exists). Shared by findNextLabel and
// findPrevLabel so both derive the chain position from one parse.
func maxSignatureLabelN(h http.Header) int {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return 0
	}
	maxN := 0
	for _, labelInput := range parseMultiLabelInput(rawInput) {
		eq := strings.Index(labelInput, "=")
		if eq <= 0 {
			continue
		}
		label := strings.TrimSpace(labelInput[:eq])
		if !strings.HasPrefix(label, "sig") {
			continue
		}
		// Atoi rejects trailing junk (e.g. "sig1x"), unlike Sscanf which would
		// stop at the first non-digit and accept it as sig1.
		if num, err := strconv.Atoi(strings.TrimPrefix(label, "sig")); err == nil && num > maxN {
			maxN = num
		}
	}
	return maxN
}

// findNextLabel returns the label for the next appended signature: sig(maxN+1),
// or "sig1" when no signatures exist.
func findNextLabel(h http.Header) string {
	return fmt.Sprintf("sig%d", maxSignatureLabelN(h)+1)
}

// findPrevLabel returns the highest existing sigN label — the predecessor an
// appended signature must chain to — and whether one exists. Returns ("", false)
// when the request carries no signature yet (the appender becomes sig1).
func findPrevLabel(h http.Header) (string, bool) {
	maxN := maxSignatureLabelN(h)
	if maxN == 0 {
		return "", false
	}
	return fmt.Sprintf("sig%d", maxN), true
}
