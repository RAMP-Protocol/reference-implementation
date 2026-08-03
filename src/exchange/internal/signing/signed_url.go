package signing

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"time"

	cfsign "github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// URLSigner is the abstract contract for producing signed URLs. Implementations
// are per-scheme: Ed25519 for Cloudflare/Fastly publishers, RSA for AWS CloudFront.
//
// The result is the SDK's helpers.SignedURL (URL + expiry + the SHA-256 Hash the
// transaction_log.signed_url_hash column stores). Ed25519 production lives in the
// SDK (helpers.SignURLEd25519, wired via the dispatcher); the canonical message
// format ("GET\n<full-url-minus-sig>", sorted query, base64url-no-pad sig) is the
// contract the edge worker's verifier (src/edge/src/verify.ts#canonicalMessage)
// and the SDK verify helpers share. The canonical payload covers the FULL URL
// (scheme + host + path + query minus the `sig` param), so host-side e2e tests
// that rewrite the URL's netloc for compose-port routing MUST also stamp a Host
// header matching the original signed authority (see tests/e2e/harness).
//
// agentID, when non-empty, is the requesting agent's RFC 7638 JWK Thumbprint
// (base64url-no-pad). It is embedded as the `agent_id` query parameter and
// covered by the signature, binding the URL to the agent's key (ADR-013). An
// empty agentID produces an unbound (bearer) URL.
type URLSigner interface {
	SignURL(ctx context.Context, rawURL, agentID string, expiry time.Time) (helpers.SignedURL, error)
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
func (s *CloudFrontURLSigner) SignURL(
	_ context.Context, rawURL, agentID string, expiry time.Time,
) (helpers.SignedURL, error) {
	if s.PrivateKey == nil {
		return helpers.SignedURL{}, errors.New("cloudfront url signer: private key not configured")
	}
	if s.KeyPairID == "" {
		return helpers.SignedURL{}, errors.New("cloudfront url signer: key pair id not configured")
	}
	resourceURL, err := withAgentID(rawURL, agentID)
	if err != nil {
		return helpers.SignedURL{}, err
	}
	signer := cfsign.NewURLSigner(s.KeyPairID, s.PrivateKey)
	signed, err := signer.Sign(resourceURL, expiry)
	if err != nil {
		return helpers.SignedURL{}, fmt.Errorf("cloudfront sign: %w", err)
	}
	return helpers.SignedURL{URL: signed, Expiry: expiry, Hash: helpers.HashURL(signed)}, nil
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
	q.Set(helpers.AgentIDParam, agentID)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}
