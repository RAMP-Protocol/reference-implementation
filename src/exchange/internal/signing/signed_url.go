package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	cfsign "github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign"
)

// SignedURL carries the issued URL along with metadata needed for audit logging.
// The Hash field is a 32-byte SHA-256 digest of the full URL, suitable for the
// transaction_log.signed_url_hash column.
type SignedURL struct {
	URL    string
	Expiry time.Time
	Hash   []byte
}

// URLSigner is the abstract contract for producing signed URLs. Implementations
// are per-scheme: Ed25519 for Cloudflare/Fastly publishers, RSA for AWS CloudFront.
type URLSigner interface {
	SignURL(ctx context.Context, rawURL string, expiry time.Time) (SignedURL, error)
}

// Ed25519URLSigner signs `GET\n<canonical-url-without-sig>` with Ed25519 and
// embeds the signature as query parameters (`exp`, `sig`, optional `kid`).
// The canonical format and base64url signature encoding MUST match the edge
// worker's verifier (`src/edge/src/verify.ts#canonicalMessage`).
type Ed25519URLSigner struct {
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
	KeyID    string
	SigParam string // defaults to "sig"
	ExpParam string // defaults to "exp"
	KIDParam string // defaults to "kid"
}

// SignURL implements URLSigner.
func (s *Ed25519URLSigner) SignURL(_ context.Context, rawURL string, expiry time.Time) (SignedURL, error) {
	if len(s.Private) != ed25519.PrivateKeySize {
		return SignedURL{}, errors.New("ed25519 url signer: private key not configured")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return SignedURL{}, fmt.Errorf("parse url: %w", err)
	}
	expParam := coalesce(s.ExpParam, "exp")
	sigParam := coalesce(s.SigParam, "sig")
	kidParam := coalesce(s.KIDParam, "kid")

	q := parsed.Query()
	q.Set(expParam, strconv.FormatInt(expiry.Unix(), 10))
	if s.KeyID != "" {
		q.Set(kidParam, s.KeyID)
	}
	q.Del(sigParam)
	parsed.RawQuery = q.Encode()

	canonical := "GET\n" + parsed.String()
	sig := ed25519.Sign(s.Private, []byte(canonical))
	q.Set(sigParam, base64.RawURLEncoding.EncodeToString(sig))
	parsed.RawQuery = q.Encode()

	signedURL := parsed.String()
	return SignedURL{
		URL:    signedURL,
		Expiry: expiry,
		Hash:   hashURL(signedURL),
	}, nil
}

// CloudFrontURLSigner adapts the AWS SDK canned-policy CloudFront URL signer.
// It is selected for tenants whose origin is fronted by CloudFront.
type CloudFrontURLSigner struct {
	KeyPairID  string
	PrivateKey *rsa.PrivateKey
}

// SignURL implements URLSigner.
func (s *CloudFrontURLSigner) SignURL(_ context.Context, rawURL string, expiry time.Time) (SignedURL, error) {
	if s.PrivateKey == nil {
		return SignedURL{}, errors.New("cloudfront url signer: private key not configured")
	}
	if s.KeyPairID == "" {
		return SignedURL{}, errors.New("cloudfront url signer: key pair id not configured")
	}
	signer := cfsign.NewURLSigner(s.KeyPairID, s.PrivateKey)
	signed, err := signer.Sign(rawURL, expiry)
	if err != nil {
		return SignedURL{}, fmt.Errorf("cloudfront sign: %w", err)
	}
	return SignedURL{URL: signed, Expiry: expiry, Hash: hashURL(signed)}, nil
}

func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// ExtractSignatureFromURL returns the verbatim signature substring carried in
// a signed URL's query string. CloudFront RSA URLs use `Signature=`; Ed25519
// URLs use `sig=`. Returned string is what `make ledger` shows side-by-side
// with the Lambda@Edge access log entry — matching bytes prove "the URL the
// agent fetched is the URL the Exchange minted." Empty if no recognised
// signature param is present.
func ExtractSignatureFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	if v := q.Get("Signature"); v != "" {
		return v
	}
	return q.Get("sig")
}

// AppendAuditQueryParams adds opaque audit query parameters to a URL before
// signing. Both URL signers (Ed25519 canonical-message, CloudFront RSA canned
// policy) cover all query params present at signing time, so audit params
// added here become part of the signature: they cannot be changed downstream
// without invalidating verification.
//
// Used to embed tx_id and req_id correlators into signed URLs so a Lambda@Edge
// or CloudFront access-log entry can be tied back to a transaction_log row
// without re-hashing the URL. Non-empty values only — empty strings are
// dropped to avoid littering the URL with placeholders.
func AppendAuditQueryParams(rawURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return rawURL, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse url for audit params: %w", err)
	}
	q := parsed.Query()
	for k, v := range params {
		if k == "" || v == "" {
			continue
		}
		q.Set(k, v)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}
