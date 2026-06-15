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
	"context"
	"crypto/ed25519"
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

// ErrUnknownKey is returned when the LookupKey callback cannot find the keyid.
var ErrUnknownKey = errors.New("httpsig: unknown keyid")

// LookupKey returns the Ed25519 public key registered for keyid. Return
// ErrUnknownKey (wrapped or direct) to signal a miss that should trigger
// lazy self-signup at the caller site.
type LookupKey func(ctx context.Context, keyid string) (ed25519.PublicKey, error)

// Verified carries the parsed signature metadata on success.
type Verified struct {
	KeyID     string
	Algorithm string
	Label     string
}

// Params captures the parameters parsed from a single Signature-Input label.
type Params struct {
	Label    string
	Covered  []string
	KeyID    string
	Alg      string
	Created  int64
	Expires  int64
	rawInput string // verbatim value inside the inner list, used for signature base
}

// Verify parses Signature-Input + Signature + Content-Digest off req, rebuilds
// the signature base per RFC 9421 §2.3, and verifies the ed25519 signature
// against the public key returned by lookup.
//
// body must be the exact bytes that produced the request payload; caller is
// responsible for tee-reading the HTTP body before it is consumed downstream.
func Verify(ctx context.Context, req *http.Request, body []byte, lookup LookupKey) (*Verified, error) {
	params, rawSig, err := parseSignatureHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(params.Alg, "ed25519") {
		return nil, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlgorithm, params.Alg)
	}
	if err := verifyContentDigest(req.Header, body, params.Covered); err != nil {
		return nil, err
	}
	pub, err := lookup(ctx, params.KeyID)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("httpsig: stored key length %d != %d", len(pub), ed25519.PublicKeySize)
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, []byte(base), rawSig) {
		return nil, ErrSignatureVerify
	}
	return &Verified{KeyID: params.KeyID, Algorithm: params.Alg, Label: params.Label}, nil
}

// parseSignatureHeaders extracts a single Signature-Input / Signature pair,
// rejecting multi-label requests (the demo supports one signer per request).
func parseSignatureHeaders(h http.Header) (Params, []byte, error) {
	rawInput := h.Get("Signature-Input")
	if rawInput == "" {
		return Params{}, nil, ErrMissingSignatureInput
	}
	rawSig := h.Get("Signature")
	if rawSig == "" {
		return Params{}, nil, ErrMissingSignature
	}
	params, err := parseSignatureInput(rawInput)
	if err != nil {
		return Params{}, nil, err
	}
	sigBytes, err := parseSignatureField(rawSig, params.Label)
	if err != nil {
		return Params{}, nil, err
	}
	return params, sigBytes, nil
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
	fields, err := parseQuotedList(inner)
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

func parseQuotedList(inner string) ([]string, error) {
	var out []string
	i := 0
	for i < len(inner) {
		for i < len(inner) && (inner[i] == ' ' || inner[i] == '\t') {
			i++
		}
		if i >= len(inner) {
			break
		}
		if inner[i] != '"' {
			return nil, fmt.Errorf("%w: expected quoted identifier at %q", ErrMalformedSignatureInput, inner[i:])
		}
		j := i + 1
		for j < len(inner) && inner[j] != '"' {
			j++
		}
		if j >= len(inner) {
			return nil, fmt.Errorf("%w: unterminated quoted string", ErrMalformedSignatureInput)
		}
		out = append(out, inner[i+1:j])
		i = j + 1
	}
	return out, nil
}

// splitParams splits "keyid=\"x\";alg=\"ed25519\";created=1" on top-level
// semicolons while preserving quoted values.
func splitParams(s string) []string {
	s = strings.TrimPrefix(s, ";")
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ';' && !inQuote {
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// parseSignatureField pulls the binary sig bytes for label out of the
// Signature header, which is formatted as `sig1=:base64data:`.
func parseSignatureField(raw, label string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	prefix := label + "="
	if !strings.HasPrefix(raw, prefix) {
		return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
	}
	body := strings.TrimPrefix(raw, prefix)
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

// verifyContentDigest checks the Content-Digest header when the coverage set
// includes it. RFC 9421 + RFC 9530: sha-256=:<base64>:.
func verifyContentDigest(h http.Header, body []byte, covered []string) error {
	needDigest := false
	for _, c := range covered {
		if strings.EqualFold(c, "content-digest") {
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
		fmt.Fprintf(&b, "\"%s\": %s\n", strings.ToLower(c), v)
	}
	// The @signature-params pseudo-component is always last and contains the
	// exact structured-field inner list + parameters, verbatim.
	sigParams := "(" + quotedList(params.Covered) + ")" + renderParamsTail(params)
	fmt.Fprintf(&b, "\"@signature-params\": %s", sigParams)
	return b.String(), nil
}

func quotedList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, `"`+it+`"`)
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
// demo verifier supports @method, @path, @authority, @target-uri, and any
// literal request header name.
func componentValue(req *http.Request, name string) (string, error) {
	switch strings.ToLower(name) {
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
	default:
		// Values (not Get) so we can distinguish an explicitly-set empty
		// header (bound intentionally) from an absent one.
		values := req.Header.Values(http.CanonicalHeaderKey(name))
		if len(values) == 0 {
			return "", fmt.Errorf("httpsig: header %q missing from request", name)
		}
		return strings.TrimSpace(strings.Join(values, ", ")), nil
	}
}
