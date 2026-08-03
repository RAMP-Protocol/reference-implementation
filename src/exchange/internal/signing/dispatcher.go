package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Scheme mirrors ramp.signing_scheme in the database.
type Scheme string

// Scheme values mirror the ramp.signing_scheme enum.
const (
	SchemeEd25519 Scheme = "ED25519"
	SchemeCFRSA   Scheme = "AWS_CLOUDFRONT_RSA"
)

// KeyStore abstracts lookup of per-tenant private key material. Production
// implementations hit a secret manager; tests provide an in-memory map.
type KeyStore interface {
	Ed25519(ref string) (ed25519.PublicKey, ed25519.PrivateKey, error)
	RSA(ref string) (*rsa.PrivateKey, error)
}

// ErrRSAKeyUnavailable marks a deployment that deliberately runs without an RSA
// key: the composition root registers a provider returning this (wrapped with
// the settings that would supply one) instead of failing the boot, because only
// AWS_CLOUDFRONT_RSA tenants need the key. Exported so the service layer can
// classify the refusal as a configuration precondition rather than an internal
// fault — the distinction between "the operator has not provisioned this yet"
// and "something broke".
var ErrRSAKeyUnavailable = errors.New(
	"no RSA signing key: this tenant signs delivery URLs with the " +
		"AWS_CLOUDFRONT_RSA scheme, which needs one")

// TenantKeys is the minimal set of signing-related tenant fields the
// dispatcher needs. It decouples the signing package from sqlc-generated
// types so the signing layer can be unit-tested in isolation.
type TenantKeys struct {
	Scheme              Scheme
	Ed25519Ref          string
	RSARef              string
	CloudFrontKeyPairID string
}

// URLSignerFor returns the URL signer appropriate for the tenant's scheme.
func URLSignerFor(keys TenantKeys, store KeyStore) (URLSigner, error) {
	switch keys.Scheme {
	case SchemeEd25519:
		pub, priv, err := store.Ed25519(keys.Ed25519Ref)
		if err != nil {
			return nil, fmt.Errorf("ed25519 keys: %w", err)
		}
		// The delivery-URL keyid is the key's RFC 7638 thumbprint after the WBA
		// split: the edge verifier resolves it against the exchange's WBA
		// directory by locally-computed thumbprint, never by the DB key ref.
		keyID, err := helpers.Thumbprint(pub)
		if err != nil {
			return nil, fmt.Errorf("ed25519 keyid thumbprint: %w", err)
		}
		return &ed25519URLSigner{private: priv, keyID: keyID}, nil
	case SchemeCFRSA:
		if keys.CloudFrontKeyPairID == "" {
			return nil, errors.New("cloudfront: key pair id missing on tenant")
		}
		priv, err := store.RSA(keys.RSARef)
		if err != nil {
			return nil, fmt.Errorf("rsa key: %w", err)
		}
		return &CloudFrontURLSigner{KeyPairID: keys.CloudFrontKeyPairID, PrivateKey: priv}, nil
	default:
		return nil, fmt.Errorf("unsupported signing scheme %q", keys.Scheme)
	}
}

// ed25519URLSigner adapts the SDK's helpers.SignURLEd25519 to the URLSigner
// interface. The Ed25519 signed-URL production (canonical "GET\n" message,
// sorted query, base64url-no-pad sig, sha256 hash) lives entirely in the SDK;
// this adapter only carries the tenant's key material.
type ed25519URLSigner struct {
	private ed25519.PrivateKey
	keyID   string
}

// SignURL implements URLSigner via the SDK helper.
func (s *ed25519URLSigner) SignURL(
	_ context.Context, rawURL, agentID string, expiry time.Time,
) (helpers.SignedURL, error) {
	return helpers.SignURLEd25519(s.private, s.keyID, rawURL, agentID, expiry)
}
