package signing

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
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
		return &Ed25519URLSigner{Private: priv, Public: pub, KeyID: keys.Ed25519Ref}, nil
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
