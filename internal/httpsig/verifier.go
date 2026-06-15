package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Minimum RFC 9421 covered-component set enforced by VerifyRequest. The set is
// chosen to bind the Authorization header (so a JWT cannot be swapped under a
// signed envelope), the Content-Digest (so the body is intact), and the method
// + target URI (so the request cannot be replayed against a different path).
// @signature-params, created, and expires are carried inside the Signature
// header itself; they are bound by the canonical base and do not appear in
// Covered.
var requiredCoveredComponents = []string{
	"@method",
	"@target-uri",
	"content-digest",
	"authorization",
}

// entitlementHeaderLower is the lowercase header name that, when present on
// a signed request, MUST be part of the covered-component set (ADR-002,
// ye6f-12). The header is optional at the protocol level — not every RPC
// carries a biscuit — so enforcement is conditional on presence. When the
// header is present the signature MUST commit to it, otherwise a biscuit
// could be injected or swapped under an existing RFC 9421 signature.
const entitlementHeaderLower = "x-ramp-entitlement-biscuit"

// ErrMissingRequiredComponent is returned when Signature-Input's covered set
// omits one of the RFC 9421 components RAMP policy requires.
var ErrMissingRequiredComponent = errors.New("httpsig: required covered component missing")

// ErrExpired is returned when the signature's expires param is in the past.
var ErrExpired = errors.New("httpsig: signature expired")

// ErrFutureCreated is returned when the signature's created param is more than
// the allowed skew window in the future. Defence against replays crafted with
// distant-future created values.
var ErrFutureCreated = errors.New("httpsig: signature created in the future")

// ErrMissingCreated is returned when created= is absent from Signature-Input.
var ErrMissingCreated = errors.New("httpsig: missing created param")

// ErrMissingExpires is returned when expires= is absent from Signature-Input.
var ErrMissingExpires = errors.New("httpsig: missing expires param")

// maxFutureSkew is the maximum number of seconds a created timestamp may be
// ahead of the verifier's clock. 300s matches the OAuth 2.0 reauth skew
// convention and is small enough to stop replay games via clock drift.
const maxFutureSkew = 300 * time.Second

// VerifyRequestOptions tunes the verifier for tests. Production callers should
// pass the zero value.
type VerifyRequestOptions struct {
	// Clk is the time source consulted for the created/expires window. When
	// nil, clock.System{} is used (the canonical wall-clock leaf, ADR-008 D1).
	Clk clock.Clock
	// MaxFutureSkew overrides the created-in-the-future tolerance.
	MaxFutureSkew time.Duration
}

// VerifiedRequest carries the signature metadata on successful verification.
// Signature is the base64 Signature header value for the sig1 label — callers
// feed this to a ReplayStore to enforce the (keyid, signature) uniqueness
// invariant.
type VerifiedRequest struct {
	KeyID     string
	Algorithm string
	Label     string
	Signature string
	Created   int64
	Expires   int64
	// PublicKey is the Ed25519 key the signature was cryptographically
	// verified against (resolved from KeyID). It is carried here so downstream
	// consumers can bind to the *proven* key rather than re-resolving from the
	// claimed KeyID — notably the delivery-URL identity binding, which embeds
	// the key's RFC 7638 thumbprint as agent_id (ADR-013 D5).
	PublicKey ed25519.PublicKey
}

// VerifyRequest parses the Signature + Signature-Input headers off req,
// enforces the RAMP-required covered-component set, verifies the Ed25519
// signature via resolver, and enforces the created/expires window.
//
// The request body is read and restored — callers may continue to read
// req.Body after a successful call without re-buffering.
func VerifyRequest(req *http.Request, resolver KeyResolver, opts ...VerifyRequestOptions) (*VerifiedRequest, error) {
	options := VerifyRequestOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	clk := options.Clk
	if clk == nil {
		clk = clock.System{}
	}
	maxSkew := options.MaxFutureSkew
	if maxSkew == 0 {
		maxSkew = maxFutureSkew
	}

	params, sigBytes, err := parseSignatureHeaders(req.Header)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(params.Alg, "ed25519") {
		return nil, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlgorithm, params.Alg)
	}
	if err := enforceRequiredComponents(params.Covered); err != nil {
		return nil, err
	}
	if err := enforceEntitlementCoverage(req.Header, params.Covered); err != nil {
		return nil, err
	}
	if err := enforceCreatedExpires(params, clk.Now(), maxSkew); err != nil {
		return nil, err
	}

	body, err := readAndRestoreBody(req)
	if err != nil {
		return nil, err
	}
	if err := verifyContentDigest(req.Header, body, params.Covered); err != nil {
		return nil, err
	}

	pub, err := resolver.Resolve(req.Context(), params.KeyID)
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
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		return nil, ErrSignatureVerify
	}

	rawSig := req.Header.Get("Signature")
	return &VerifiedRequest{
		KeyID:     params.KeyID,
		Algorithm: params.Alg,
		Label:     params.Label,
		Signature: rawSig,
		Created:   params.Created,
		Expires:   params.Expires,
		PublicKey: pub,
	}, nil
}

func enforceRequiredComponents(covered []string) error {
	seen := make(map[string]bool, len(covered))
	for _, c := range covered {
		seen[strings.ToLower(c)] = true
	}
	for _, need := range requiredCoveredComponents {
		if !seen[need] {
			return fmt.Errorf("%w: %s", ErrMissingRequiredComponent, need)
		}
	}
	return nil
}

// enforceEntitlementCoverage requires the signature to commit to
// X-RAMP-Entitlement-Biscuit iff the header is present on the request.
// Absent header → no constraint (RPCs without a biscuit remain legal).
// Present header without coverage → ErrMissingRequiredComponent so an
// attacker cannot slip a biscuit through an otherwise valid signature.
func enforceEntitlementCoverage(h http.Header, covered []string) error {
	if h.Get("X-RAMP-Entitlement-Biscuit") == "" {
		return nil
	}
	for _, c := range covered {
		if strings.ToLower(c) == entitlementHeaderLower {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrMissingRequiredComponent, entitlementHeaderLower)
}

func enforceCreatedExpires(p Params, now time.Time, maxSkew time.Duration) error {
	if p.Created == 0 {
		return ErrMissingCreated
	}
	if p.Expires == 0 {
		return ErrMissingExpires
	}
	nowUnix := now.Unix()
	if p.Expires < nowUnix {
		return fmt.Errorf("%w: expires=%d now=%d", ErrExpired, p.Expires, nowUnix)
	}
	if p.Created > nowUnix+int64(maxSkew.Seconds()) {
		return fmt.Errorf("%w: created=%d now=%d", ErrFutureCreated, p.Created, nowUnix)
	}
	return nil
}

// readAndRestoreBody drains req.Body (if any) and puts the bytes back so
// downstream handlers see an unconsumed request.
func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("httpsig: read body: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return body, nil
}
