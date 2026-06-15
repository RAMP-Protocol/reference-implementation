package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// SignRequest signs req's body with priv using the fixed coverage set used
// by the demo (@method, @path, @authority, content-digest). It mutates req
// to add the Content-Digest, Signature-Input, and Signature headers. body
// must be the exact bytes that will be transmitted on the wire.
//
// Exposed for tests; production callers sign from their own transports.
func SignRequest(req *http.Request, body []byte, keyID string, priv ed25519.PrivateKey, created int64) error {
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	req.Header.Set("Content-Digest", digest)

	covered := []string{"@method", "@path", "@authority", "content-digest"}
	params := Params{
		Label:   "sig1",
		Covered: covered,
		KeyID:   keyID,
		Alg:     "ed25519",
		Created: created,
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature-Input", "sig1="+signatureInputInner(params))
	req.Header.Set("Signature", fmt.Sprintf("sig1=:%s:", base64.StdEncoding.EncodeToString(sig)))
	return nil
}

func signatureInputInner(p Params) string {
	parts := make([]string, 0, len(p.Covered))
	for _, c := range p.Covered {
		parts = append(parts, `"`+c+`"`)
	}
	return "(" + strings.Join(parts, " ") + ")" + renderParamsTail(p)
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
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	req.Header.Set("Content-Digest", digest)
	if req.Header.Get("Authorization") == "" {
		// Bind the absence of authn so a later injection cannot piggy-back
		// the same signature.
		req.Header.Set("Authorization", "")
	}

	covered := []string{"@method", "@target-uri", "content-digest", "authorization"}
	if req.Header.Get("X-RAMP-Entitlement-Biscuit") != "" {
		covered = append(covered, "x-ramp-entitlement-biscuit")
	}
	params := Params{
		Label:   "sig1",
		Covered: covered,
		KeyID:   keyID,
		Alg:     "ed25519",
		Created: created,
		Expires: expires,
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature-Input", "sig1="+signatureInputInner(params))
	req.Header.Set("Signature", fmt.Sprintf("sig1=:%s:", base64.StdEncoding.EncodeToString(sig)))
	return nil
}
