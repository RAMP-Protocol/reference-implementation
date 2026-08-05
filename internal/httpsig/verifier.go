package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yaronf/httpsign"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
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
	signatureAgentLower,
}

// entitlementHeaderLower is the lowercase header name that, when present on
// a signed request, MUST be part of the covered-component set (ADR-002).
// The header is optional at the protocol level — not every RPC
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
	// MaxSignatures bounds the number of signatures accepted on a multisig
	// request — the Exchange hop bound. 0 means unbounded; only the
	// Exchange-terminal middleware sets it (= max_intermediary_hops + 1). A
	// request carrying more signatures is rejected with ErrTooManyHops before
	// any signature is cryptographically verified.
	MaxSignatures int
}

// VerifiedRequest carries the signature metadata on successful verification.
// Signature is the base64 value of THIS label's own signature bytes (not the
// full multi-label Signature header) — callers feed this to a ReplayStore to
// enforce the (keyid, signature) uniqueness invariant. Keying on the per-label
// value keeps the replay key stable when a relay re-wraps the same signature
// under a fresh co-signature.
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
	// SignatureAgent is the (covered, therefore signed) Signature-Agent header
	// value: the signer's own directory origin. After the WBA split the KeyID is
	// an RFC 7638 thumbprint (a proof of key possession) while the agent identity
	// is the directory domain named here; authorization keys on this value and
	// the thumbprint proves the named directory published the key. Empty when the
	// signer set no Signature-Agent.
	SignatureAgent string
}

// VerifyRequest parses the Signature + Signature-Input headers off req,
// enforces the RAMP-required covered-component set, verifies the Ed25519
// signature via resolver, and enforces the created/expires window.
//
// The request body is read and restored — callers may continue to read
// req.Body after a successful call without re-buffering.
func VerifyRequest(req *http.Request, resolver KeyResolver, opts ...VerifyRequestOptions) (*VerifiedRequest, error) {
	options := buildVerifyOptions(opts)

	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		return nil, err
	}
	if len(allParams) == 0 {
		return nil, ErrMissingSignatureInput
	}

	body, err := readAndRestoreBody(req)
	if err != nil {
		return nil, err
	}

	// Verify the first (and, for single-signer requests, only) signature. The
	// full validation chain lives in verifySingleSignature, shared with the
	// multisig path so both judge a signature by identical rules.
	return verifySingleSignature(req, allParams[0], sigMap, body, resolver, options)
}

func enforceRequiredComponents(covered []CoveredComponent) error {
	seen := make(map[string]bool, len(covered))
	for _, c := range covered {
		seen[strings.ToLower(c.Name)] = true
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
func enforceEntitlementCoverage(h http.Header, covered []CoveredComponent) error {
	if h.Get("X-RAMP-Entitlement-Biscuit") == "" {
		return nil
	}
	for _, c := range covered {
		if strings.ToLower(c.Name) == entitlementHeaderLower {
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

// VerifyMultisigRequest verifies ALL signatures on req. Returns list of
// VerifiedRequest structs in label order (sig1, sig2, ...). Each signature
// must pass verification.
func VerifyMultisigRequest(
	req *http.Request, resolver KeyResolver, opts ...VerifyRequestOptions,
) ([]VerifiedRequest, error) {
	options := buildVerifyOptions(opts)

	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		return nil, err
	}

	if options.MaxSignatures > 0 && len(allParams) > options.MaxSignatures {
		return nil, fmt.Errorf("%w: got %d max %d", ErrTooManyHops, len(allParams), options.MaxSignatures)
	}

	if err := enforceSignatureChain(allParams); err != nil {
		return nil, err
	}

	body, err := readAndRestoreBody(req)
	if err != nil {
		return nil, err
	}

	verified := make([]VerifiedRequest, 0, len(allParams))
	for _, params := range allParams {
		v, err := verifySingleSignature(req, params, sigMap, body, resolver, options)
		if err != nil {
			return nil, err
		}
		verified = append(verified, *v)
	}

	return verified, nil
}

// enforceSignatureChain checks that allParams form a valid forwarding chain
// labels are exactly sig1..sigN contiguous in Signature-Input order,
// sig1 carries no "signature" component, and every sigK (K>1) covers exactly one
// "signature";key="sig(K-1)" link to its immediate predecessor.
//
// This is the STRUCTURAL gate only — it inspects the parsed covered sets, not the
// signature bytes. The cryptographic binding is enforced separately by the
// per-signature verify in the caller: each sigK's base resolves its chain link to
// the live bytes of sig(K-1) (componentValue → chainLinkValue), so substituting
// or tampering with a predecessor fails sigK's Ed25519 check. Signature-header
// member order is immaterial because bytes are matched to labels by name; only
// the Signature-Input order is constrained here.
//
// A single signature (the agent-direct case) trivially satisfies the chain.
func enforceSignatureChain(allParams []Params) error {
	for i, p := range allParams {
		wantLabel := fmt.Sprintf("sig%d", i+1)
		if p.Label != wantLabel {
			return fmt.Errorf("%w: label %q at position %d, want %q", ErrBrokenSignatureChain, p.Label, i+1, wantLabel)
		}
		link, count := chainLink(p.Covered)
		if i == 0 {
			if count != 0 {
				return fmt.Errorf("%w: sig1 must not carry a signature component", ErrBrokenSignatureChain)
			}
			continue
		}
		wantPrev := fmt.Sprintf("sig%d", i)
		if count != 1 || link != wantPrev {
			return fmt.Errorf("%w: %s must cover exactly \"signature\";key=%q (got %d links, key=%q)",
				ErrBrokenSignatureChain, wantLabel, wantPrev, count, link)
		}
	}
	return nil
}

// chainLink returns the key parameter of the single "signature" covered
// component and the number of "signature" components present. A well-formed
// chain link has count == 1; count == 0 means no link, count > 1 is malformed.
func chainLink(covered []CoveredComponent) (key string, count int) {
	for _, c := range covered {
		if strings.EqualFold(c.Name, "signature") {
			count++
			key = componentParam(c, "key")
		}
	}
	return key, count
}

func buildVerifyOptions(opts []VerifyRequestOptions) VerifyRequestOptions {
	options := VerifyRequestOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	if options.Clk == nil {
		options.Clk = clock.System{}
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = maxFutureSkew
	}
	return options
}

func verifySingleSignature(
	req *http.Request,
	params Params,
	sigMap map[string][]byte,
	body []byte,
	resolver KeyResolver,
	opts VerifyRequestOptions,
) (*VerifiedRequest, error) {
	if !strings.EqualFold(params.Alg, "ed25519") {
		return nil, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlgorithm, params.Alg)
	}

	if err := enforceRequiredComponents(params.Covered); err != nil {
		return nil, err
	}
	if err := enforceEntitlementCoverage(req.Header, params.Covered); err != nil {
		return nil, err
	}
	if err := enforceCreatedExpires(params, opts.Clk.Now(), opts.MaxFutureSkew); err != nil {
		return nil, err
	}
	if err := verifyContentDigest(req.Header, body, params.Covered); err != nil {
		return nil, err
	}

	// Signature-Agent is a required covered component (enforced above), so its
	// value is bound by this signature. Thread it to the resolver so a discovery
	// resolver can fetch the named directory and match the keyid thumbprint
	// against it; carry it on the result so authorization keys on the directory
	// domain rather than the raw thumbprint.
	//
	// Read through agentid so this stack and the SDK's read the header identically.
	// Web Bot Auth defines the value as a quoted structured-field String, and the
	// bytes on the wire are left untouched — only the extracted value is unquoted,
	// so the signature base above still covers what the signer signed. Reading the
	// REQUEST rather than one header line is what makes that parity hold for a
	// repeated Signature-Agent too; see agentid.DirectoryFromRequest.
	sigAgent := agentid.DirectoryFromRequest(req.Header)
	pub, err := resolver.Resolve(WithSignatureAgent(req.Context(), sigAgent), params.KeyID)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("httpsig: stored key length %d != %d", len(pub), ed25519.PublicKeySize)
	}

	sigBytes, ok := sigMap[params.Label]
	if !ok {
		return nil, fmt.Errorf("%w: label %q not in Signature", ErrMalformedSignatureInput, params.Label)
	}

	if err := verifyEd25519(req, params.Label, pub, body); err != nil {
		return nil, err
	}

	return &VerifiedRequest{
		KeyID:          params.KeyID,
		Algorithm:      params.Alg,
		Label:          params.Label,
		Signature:      base64.StdEncoding.EncodeToString(sigBytes),
		Created:        params.Created,
		Expires:        params.Expires,
		PublicKey:      pub,
		SignatureAgent: sigAgent,
	}, nil
}

// verifyEd25519 reconstructs the RFC 9421 signature base from the request's
// received Signature-Input bytes (order-agnostic) and checks the ed25519
// signature for label via yaronf/httpsign. The verifier is built with an EMPTY
// Headers() set so yaronf imposes no coverage policy of its own — RAMP's
// enforceRequiredComponents owns coverage — and with SetRejectExpired(false) so
// RAMP's enforceCreatedExpires owns the time window and its specific errors.
// Any verify failure (bad signature, malformed structured field, missing label)
// is WRAPPED as ErrSignatureVerify: the sentinel is preserved for callers that
// branch with errors.Is, while yaronf's underlying cause stays on the error
// chain so operators can distinguish a malformed Signature-Input from a bad key
// or a tampered body (Rule 9). yaronf may read req.Body to canonicalize body-
// derived components, so body is re-restored afterwards for the next label and
// downstream handlers.
func verifyEd25519(req *http.Request, label string, pub ed25519.PublicKey, body []byte) error {
	// Disable BOTH of yaronf's built-in time policies so RAMP's
	// enforceCreatedExpires (expires + maxFutureSkew) is the SOLE freshness
	// authority. NewVerifyConfig defaults to verifyCreated=true with a 10s
	// notOlderThan / 2s notNewerThan window — far tighter than RAMP's, and it
	// would reject any signature more than 10s old: legitimate delays, retries,
	// clock skew, and pre-existing signatures during the verifiers-first
	// rollout. SetRejectExpired(false) alone leaves that created-window active.
	vcfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetRejectExpired(false)
	verifier, err := httpsign.NewEd25519Verifier(pub, vcfg, httpsign.Headers())
	if err != nil {
		return fmt.Errorf("httpsig: build verifier: %w", err)
	}
	verr := httpsign.VerifyRequest(label, *verifier, req)
	restoreBody(req, body)
	if verr != nil {
		return fmt.Errorf("%w: %w", ErrSignatureVerify, verr)
	}
	return nil
}

// restoreBody resets req.Body (and GetBody) to a fresh reader over body so a
// reader consumed by a verify pass is replenished for the next signature and
// for downstream handlers. A nil body leaves the request untouched.
func restoreBody(req *http.Request, body []byte) {
	if body == nil {
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
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
	restoreBody(req, body)
	return body, nil
}
