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
//
// agentID, when non-empty, is the requesting agent's RFC 7638 JWK Thumbprint
// (base64url-no-pad). It is embedded as the `agent_id` query parameter and
// covered by the signature, binding the URL to the agent's key (ADR-013). An
// empty agentID produces an unbound (bearer) URL.
type URLSigner interface {
	SignURL(ctx context.Context, rawURL, agentID string, expiry time.Time) (SignedURL, error)
}

// AgentIDParam is the query-parameter name carrying the agent's RFC 7638
// thumbprint on signed delivery URLs (ADR-009 D5 / ADR-013 17.5). The edge
// verifier reads the same name (src/edge/src/verify.ts).
const AgentIDParam = "agent_id"

// Ed25519URLSigner signs `GET\n<canonical-url-without-sig>` with Ed25519 and
// embeds the signature as query parameters (`exp`, `sig`, optional `kid`).
// The canonical format and base64url signature encoding MUST match the edge
// worker's verifier (`src/edge/src/verify.ts#canonicalMessage`).
//
// The canonical payload covers the FULL URL (scheme + host + path + query
// minus the `sig` param), not just path+query. Host-side e2e tests that
// rewrite the URL's netloc for compose-port routing MUST also stamp a Host
// header matching the original signed authority, otherwise Workerd
// reconstructs c.req.url with the rewritten authority and signature
// verification fails. See tests/e2e/harness/test_full_stack.py and
// tests/e2e/harness/obligations/test_00_happy_03_usage_record_paid_access.py
// for the host-rewrite+Host-stamp pattern.
type Ed25519URLSigner struct {
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
	KeyID    string
	SigParam string // defaults to "sig"
	ExpParam string // defaults to "exp"
	KIDParam string // defaults to "kid"
}

// SignURL implements URLSigner.
func (s *Ed25519URLSigner) SignURL(_ context.Context, rawURL, agentID string, expiry time.Time) (SignedURL, error) {
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
	if agentID != "" {
		q.Set(AgentIDParam, agentID)
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
//
// agentID, when present, rides in the resource URL's query before the canned
// CloudFront policy is computed, so it is committed by the signature (the canned
// policy signs the full resource URL). CloudFront verifies the URL signature
// natively but cannot run the proof-of-possession check; binding enforcement on
// the CloudFront-native path therefore falls back to bearer security (ADR-013
// D6). A code-capable edge (Lambda@Edge) would be required to enforce the bind.
func (s *CloudFrontURLSigner) SignURL(_ context.Context, rawURL, agentID string, expiry time.Time) (SignedURL, error) {
	if s.PrivateKey == nil {
		return SignedURL{}, errors.New("cloudfront url signer: private key not configured")
	}
	if s.KeyPairID == "" {
		return SignedURL{}, errors.New("cloudfront url signer: key pair id not configured")
	}
	resourceURL, err := withAgentID(rawURL, agentID)
	if err != nil {
		return SignedURL{}, err
	}
	signer := cfsign.NewURLSigner(s.KeyPairID, s.PrivateKey)
	signed, err := signer.Sign(resourceURL, expiry)
	if err != nil {
		return SignedURL{}, fmt.Errorf("cloudfront sign: %w", err)
	}
	return SignedURL{URL: signed, Expiry: expiry, Hash: hashURL(signed)}, nil
}

// withAgentID returns rawURL with the agent_id query parameter set, or rawURL
// unchanged when agentID is empty.
func withAgentID(rawURL, agentID string) (string, error) {
	if agentID == "" {
		return rawURL, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	q := parsed.Query()
	q.Set(AgentIDParam, agentID)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func coalesce(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
