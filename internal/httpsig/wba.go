package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// WBATag is the RFC 9421 tag parameter every Web Bot Auth signature carries. The
// WBA architecture draft makes it mandatory and lets an origin discard any
// signature whose tag differs, so it is what marks a signature as "an automated
// agent identifying itself" rather than some other application's use of RFC 9421.
const WBATag = "web-bot-auth"

// wbaNonceBytes is the entropy behind the per-request nonce. The WBA draft leaves
// the length open; 32 bytes matches the draft's own examples and is far past any
// birthday-collision concern for a value an origin only has to remember for the
// signature's lifetime.
const wbaNonceBytes = 32

// The three refusals below share one rationale: each of Directory, KeyID, and
// Expires is required by the Web Bot Auth draft, and a signature missing any of
// them is one no conformant origin can act on. Emitting it would present the
// agent as authenticated while leaving it unverifiable, so each is refused at the
// boundary rather than sent.

// ErrMissingDirectory is returned when a Web Bot Auth signature is requested
// without the signer's own directory origin. WBA resolves a keyid thumbprint by
// fetching the directory named in Signature-Agent, so a signature with no
// directory is one no origin can verify — better refused here than sent.
var ErrMissingDirectory = errors.New("httpsig: missing directory origin (required by Web Bot Auth)")

// ErrMissingKeyID is returned when a Web Bot Auth signature is requested without
// a keyid. An empty keyid goes on the wire as keyid="", which matches no JWK in
// the fetched directory — the same unverifiable signature ErrMissingDirectory
// refuses, arrived at from the other side.
var ErrMissingKeyID = errors.New("httpsig: missing keyid (required by Web Bot Auth)")

// The third refusal, a missing expiry, reuses the verifier's ErrMissingExpires:
// it is one condition seen from two ends. signWithParams omits a zero expires
// from the wire entirely, so signing with one produces exactly the signature that
// sentinel describes — and such a signature is replayable for as long as its
// covered components hold, which for this profile is any path and any method on
// the same authority.

// WBAOptions carries what a Web Bot Auth signature needs beyond the request and
// the key. Directory, KeyID, and Expires are required and each is enforced; Nonce
// is generated when empty.
type WBAOptions struct {
	// Directory is the signer's own directory origin — the URL prefix serving
	// /.well-known/http-message-signatures-directory, e.g.
	// "https://alice.rampmcp.org". It goes on the wire in the covered
	// Signature-Agent header, so an origin cannot be repointed under a valid
	// signature.
	Directory string
	// KeyID is the RFC 9421 keyid: the RFC 7638 JWK thumbprint of the signing
	// key's public half (internal/rampthumbprint). The WBA draft requires exactly
	// that form, so the verifier can match the keyid against the directory's JWKs
	// without trusting a self-chosen label.
	KeyID string
	// Expires is the unix-seconds cutoff after which the signature is stale. The
	// draft RECOMMENDS no more than 24h; a caller signing per request should use
	// far less.
	Expires int64
	// Nonce is the per-request replay guard. Left empty, a fresh 32-byte random
	// value is generated — the normal case; a caller supplies one only to pin it
	// in a test.
	Nonce string
}

// WBACoveredComponents returns the Web Bot Auth covered-component set:
// @authority and signature-agent, the two the draft's example signs, plus
// content-digest when the request carries a body.
//
// @authority (not @target-uri) is what the draft covers, so the signature binds
// the origin the request was aimed at while staying valid across a path the
// origin itself rewrites. content-digest is RAMP's addition on bodied requests:
// extra covered components are always legal — a verifier checks what the
// signature says it covers — and leaving a request body unbound would let it be
// swapped under a valid signature.
func WBACoveredComponents(hasBody bool) []CoveredComponent {
	names := []string{"@authority", signatureAgentLower}
	if hasBody {
		names = append(names, "content-digest")
	}
	return plainComponents(names...)
}

// SignRequestWBA signs req as a Web Bot Auth request: covered components
// @authority + signature-agent (+ content-digest when body is non-empty), and the
// signature parameters created, expires, alg, keyid, nonce, and tag="web-bot-auth"
// the WBA architecture draft requires. The receiver is an arbitrary WBA-aware
// origin, not a RAMP peer, so the RAMP covered set does not apply.
//
// It sets the Signature-Agent header itself, as a structured-field String — the
// quoted form the draft specifies (Signature-Agent: "https://agent.example").
// This is DELIBERATELY not the form the RAMP profile emits: bindSignatureAgent
// writes the origin bare, and RAMP's own verifier and the agentkeys resolver read
// it bare. An external WBA verifier canonicalizes the header value exactly as
// sent, so the quoted form is required for the signature to verify off-network;
// changing RAMP's form to match is a wire break across signer, verifier, and
// resolver, and is not part of this profile.
//
// yaronf/httpsign stamps created = now() at signing time; there is no exported
// hook to override it, so this signer takes no created parameter.
func SignRequestWBA(req *http.Request, body []byte, priv ed25519.PrivateKey, opts WBAOptions) error {
	if opts.Directory == "" {
		return ErrMissingDirectory
	}
	if opts.KeyID == "" {
		return ErrMissingKeyID
	}
	if opts.Expires <= 0 {
		return ErrMissingExpires
	}
	agent, err := httpsfv.Marshal(httpsfv.NewItem(opts.Directory))
	if err != nil {
		return fmt.Errorf("httpsig: encode Signature-Agent %q: %w", opts.Directory, err)
	}
	req.Header.Set(SignatureAgentHeader, agent)

	nonce := opts.Nonce
	if nonce == "" {
		if nonce, err = randomNonce(); err != nil {
			return err
		}
	}
	params := Params{
		Label:   "sig1",
		Covered: WBACoveredComponents(len(body) > 0),
		KeyID:   opts.KeyID,
		Alg:     "ed25519",
		Expires: opts.Expires,
		Tag:     WBATag,
		Nonce:   nonce,
	}
	return SignRequest(req, body, priv, params)
}

// randomNonce returns a fresh base64url-no-pad nonce from crypto/rand.
func randomNonce() (string, error) {
	b := make([]byte, wbaNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("httpsig: generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
