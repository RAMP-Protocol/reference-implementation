// Package httpsig implements a narrow subset of RFC 9421 (HTTP Message
// Signatures) sufficient for verifying PushResources calls from catalog
// contributors.
//
// Implementation choice: minimal inline ed25519-only verifier rather than
// pulling in a third-party library (fewer transitive deps, easier to audit
// for the demo bootstrap). Supports a fixed signature base construction
// covering @method, @path, @authority, content-digest (SHA-256) and the
// caller-supplied keyid/created/alg parameters. Extend only when a
// downstream caller requires additional covered components.
package httpsig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

// ErrUnknownKey is returned when the KeyResolver cannot find the keyid. Return
// it (wrapped or direct) to signal a miss that should trigger lazy self-signup
// at the caller site.
var ErrUnknownKey = errors.New("httpsig: unknown keyid")

// ErrBrokenSignatureChain is returned when a multisig request's signatures do
// not form a valid forwarding chain: labels are non-contiguous, reordered, or a
// sigN (N>1) does not cover exactly its predecessor via "signature";key="sigN-1"
// (RAMP-56 forwarding chain, RFC 9421 §2.4).
var ErrBrokenSignatureChain = errors.New("httpsig: signature chain broken (gap/reorder/missing link)")

// ErrTooManyHops is returned when the number of signatures on a request exceeds
// the verifier's configured MaxSignatures budget (Exchange hop bound).
var ErrTooManyHops = errors.New("httpsig: signature count exceeds hop budget")

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

// plainComponents builds CoveredComponents with no parameters from names.
func plainComponents(names ...string) []CoveredComponent {
	out := make([]CoveredComponent, 0, len(names))
	for _, n := range names {
		out = append(out, CoveredComponent{Name: n})
	}
	return out
}

// componentParam returns the value of the named parameter on c, or "" if absent.
func componentParam(c CoveredComponent, key string) string {
	for _, p := range c.Params {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}

// renderComponent serializes a covered-component identifier as it appears in the
// Signature-Input header and the @signature-params line: `"name";k="v";...`.
// The name is rendered verbatim (callers supply already-lowercased names) so the
// header inner list and the signature base inner list are byte-identical.
func renderComponent(c CoveredComponent) string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(c.Name)
	b.WriteByte('"')
	for _, p := range c.Params {
		fmt.Fprintf(&b, ";%s=%q", p.Key, p.Val)
	}
	return b.String()
}

// Params captures the parameters parsed from a single Signature-Input label.
type Params struct {
	Label    string
	Covered  []CoveredComponent
	KeyID    string
	Alg      string
	Created  int64
	Expires  int64
	rawInput string // verbatim value inside the inner list, used for signature base
}

// parseAllSignatures extracts ALL signature labels from Signature-Input and
// Signature headers. Returns a list of Params (one per label) and a map of
// label→signature bytes. Handles 0, 1, or N signatures gracefully.
func parseAllSignatures(h http.Header) ([]Params, map[string][]byte, error) {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return nil, nil, ErrMissingSignatureInput
	}
	rawSig := h.Get("Signature")
	if rawSig == "" {
		return nil, nil, ErrMissingSignature
	}

	// Parse all labels from Signature-Input (comma-separated list).
	inputLabels := parseMultiLabelInput(rawInput)
	if len(inputLabels) == 0 {
		return nil, nil, fmt.Errorf("%w: no labels found", ErrMalformedSignatureInput)
	}

	allParams := make([]Params, 0, len(inputLabels))
	for _, labelInput := range inputLabels {
		params, err := parseSignatureInput(labelInput)
		if err != nil {
			return nil, nil, err
		}
		allParams = append(allParams, params)
	}

	// Parse all signatures from Signature header (comma-separated list).
	sigMap := make(map[string][]byte, len(allParams))
	for _, params := range allParams {
		sigBytes, err := parseSignatureField(rawSig, params.Label)
		if err != nil {
			return nil, nil, err
		}
		sigMap[params.Label] = sigBytes
	}

	return allParams, sigMap, nil
}

// ParseSignatureLabels parses the Signature-Input + Signature headers off h and
// returns one Params per label, in header order. It is the exported entry point
// for callers outside this package (e.g. the relay integration test) that need
// to inspect the labels/keyids of a multi-signature request without
// re-implementing the structured-field parser. Returns an error when either
// header is absent or any label is malformed.
func ParseSignatureLabels(h http.Header) ([]Params, error) {
	params, _, err := parseAllSignatures(h)
	return params, err
}

// parseSignatureInput parses a single-label Signature-Input structured field:
//
//	sig1=("@method" "@path" "@authority" "content-digest");\
//	keyid="caller.example";alg="ed25519";created=1700000000
func parseSignatureInput(raw string) (Params, error) {
	eq := strings.Index(raw, "=")
	if eq <= 0 {
		return Params{}, fmt.Errorf("%w: missing label", ErrMalformedSignatureInput)
	}
	label := strings.TrimSpace(raw[:eq])
	rest := strings.TrimSpace(raw[eq+1:])
	lparen := strings.Index(rest, "(")
	rparen := strings.Index(rest, ")")
	if lparen != 0 || rparen < 0 {
		return Params{}, fmt.Errorf("%w: expected ( ... )", ErrMalformedSignatureInput)
	}
	inner := rest[1:rparen]
	params := Params{Label: label, rawInput: rest[:rparen+1] + rest[rparen+1:]}
	fields, err := parseComponentList(inner)
	if err != nil {
		return Params{}, err
	}
	params.Covered = fields
	tail := strings.TrimSpace(rest[rparen+1:])
	for _, kv := range splitParams(tail) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return Params{}, fmt.Errorf("%w: bad param %q", ErrMalformedSignatureInput, kv)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "keyid":
			params.KeyID = strings.Trim(v, `"`)
		case "alg":
			params.Alg = strings.Trim(v, `"`)
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return Params{}, fmt.Errorf("%w: created=%q", ErrMalformedSignatureInput, v)
			}
			params.Created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return Params{}, fmt.Errorf("%w: expires=%q", ErrMalformedSignatureInput, v)
			}
			params.Expires = n
		}
	}
	if params.KeyID == "" {
		return Params{}, fmt.Errorf("%w: keyid required", ErrMalformedSignatureInput)
	}
	return params, nil
}

// parseSignatureField pulls the binary sig bytes for label out of the
// Signature header, which can be formatted as:
//   - Single: `sig1=:base64data:`
//   - Multi:  `sig1=:base64data:, sig2=:moredata:`
func parseSignatureField(raw, label string) ([]byte, error) {
	raw = strings.TrimSpace(raw)

	// Split on commas to handle multi-label format.
	parts := parseMultiLabelSignature(raw)

	// Find the matching label.
	for _, part := range parts {
		part = strings.TrimSpace(part)
		prefix := label + "="
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		body := strings.TrimPrefix(part, prefix)
		if !strings.HasPrefix(body, ":") || !strings.HasSuffix(body, ":") {
			return nil, fmt.Errorf("%w: Signature value not byte-sequence", ErrMalformedSignatureInput)
		}
		b64 := body[1 : len(body)-1]
		out, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("%w: Signature base64: %w", ErrMalformedSignatureInput, err)
		}
		return out, nil
	}

	return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
}

// verifyContentDigest checks the Content-Digest header when the coverage set
// includes it. RFC 9421 + RFC 9530: sha-256=:<base64>:.
func verifyContentDigest(h http.Header, body []byte, covered []CoveredComponent) error {
	needDigest := false
	for _, c := range covered {
		if strings.EqualFold(c.Name, "content-digest") {
			needDigest = true
			break
		}
	}
	if !needDigest {
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

// buildSignatureBase assembles the RFC 9421 §2.5 signature base covering the
// derived components (@method, @path, @authority) and literal headers listed
// in params.Covered. Canonical value rules per §2.4.
func buildSignatureBase(req *http.Request, params Params) (string, error) {
	var b bytes.Buffer
	for _, c := range params.Covered {
		v, err := componentValue(req, c)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s: %s\n", renderComponent(c), v)
	}
	// The @signature-params pseudo-component is always last and contains the
	// exact structured-field inner list + parameters, verbatim.
	sigParams := "(" + quotedList(params.Covered) + ")" + renderParamsTail(params)
	fmt.Fprintf(&b, "\"@signature-params\": %s", sigParams)
	return b.String(), nil
}

func quotedList(items []CoveredComponent) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, renderComponent(it))
	}
	return strings.Join(parts, " ")
}

func renderParamsTail(p Params) string {
	var b strings.Builder
	if p.KeyID != "" {
		fmt.Fprintf(&b, ";keyid=%q", p.KeyID)
	}
	if p.Alg != "" {
		fmt.Fprintf(&b, ";alg=%q", p.Alg)
	}
	if p.Created != 0 {
		fmt.Fprintf(&b, ";created=%d", p.Created)
	}
	if p.Expires != 0 {
		fmt.Fprintf(&b, ";expires=%d", p.Expires)
	}
	return b.String()
}

// reconstructTargetURI produces an absolute-form target URI from the pieces
// a server sees on an incoming HTTP/1.1 request (req.URL.Path + req.Host +
// TLS indicator). Outbound signers may supply req.URL.Scheme/Host directly;
// when those are present we prefer them so the same helper works client and
// server side.
func reconstructTargetURI(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	raw := req.URL.RawQuery
	if raw != "" {
		return scheme + "://" + host + path + "?" + raw
	}
	return scheme + "://" + host + path
}

// componentValue yields the canonicalized value for a covered component. The
// verifier supports @method, @path, @authority, @target-uri, the RFC 9421 §2.4
// "signature";key="sigN" dictionary-member reference (the forwarding-chain
// link), and any literal request header name.
func componentValue(req *http.Request, c CoveredComponent) (string, error) {
	switch strings.ToLower(c.Name) {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@path":
		if req.URL == nil {
			return "", fmt.Errorf("httpsig: request URL unset for @path")
		}
		p := req.URL.Path
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@authority":
		auth := req.Host
		if auth == "" && req.URL != nil {
			auth = req.URL.Host
		}
		return strings.ToLower(auth), nil
	case "@target-uri":
		if req.URL == nil {
			return "", fmt.Errorf("httpsig: request URL unset for @target-uri")
		}
		return reconstructTargetURI(req), nil
	case "signature":
		return chainLinkValue(req, c)
	default:
		// Values (not Get) so we can distinguish an explicitly-set empty
		// header (bound intentionally) from an absent one.
		values := req.Header.Values(http.CanonicalHeaderKey(c.Name))
		if len(values) == 0 {
			return "", fmt.Errorf("httpsig: header %q missing from request", c.Name)
		}
		return strings.TrimSpace(strings.Join(values, ", ")), nil
	}
}

// chainLinkValue resolves a "signature";key="sigN" component to the canonical
// RFC 8941 byte-sequence serialization of the referenced Signature dictionary
// member: :base64(bytes):. It decodes the referenced member to raw bytes and
// re-encodes canonically (base64.StdEncoding) rather than splicing the raw wire
// substring, so signer and verifier agree byte-for-byte regardless of incidental
// whitespace around the member on the wire (RAMP-56, Risk R1).
func chainLinkValue(req *http.Request, c CoveredComponent) (string, error) {
	key := componentParam(c, "key")
	if key == "" {
		return "", fmt.Errorf("%w: signature component missing key param", ErrMalformedSignatureInput)
	}
	rawSig := req.Header.Get("Signature")
	if rawSig == "" {
		return "", fmt.Errorf("resolve chain link %q: %w", key, ErrMissingSignature)
	}
	prevBytes, err := parseSignatureField(rawSig, key)
	if err != nil {
		return "", fmt.Errorf("resolve chain link %q: %w", key, err)
	}
	return ":" + base64.StdEncoding.EncodeToString(prevBytes) + ":", nil
}
