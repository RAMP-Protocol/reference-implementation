// Helpers that resolve the Exchange's demo signing keys. Order of preference:
//
//  1. Env var holds a PEM — parse + use. This is the AWS deployment path; the
//     ECS task definition wires the env vars from Secrets Manager.
//  2. Env var is empty — generate a fresh keypair at startup. This is the
//     local-docker-e2e path; keys rotate each container restart but every
//     piece of the chain (JWKS, signing, verification) agrees because they
//     share the same in-process value.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// resolveEd25519Key returns the keypair to use for offer signing and demo URL
// signing. When RAMP_ED25519_PRIVATE_PEM is set, the PEM is parsed; otherwise
// a fresh keypair is generated.
func resolveEd25519Key(logger *slog.Logger) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw := runhttp.EnvOr("RAMP_ED25519_PRIVATE_PEM", "")
	if raw == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
		}
		logger.Info("ed25519 key generated (no RAMP_ED25519_PRIVATE_PEM set)")
		return pub, priv, nil
	}
	priv, err := parseEd25519PrivatePEM(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ed25519 pem: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("ed25519 private key has non-ed25519 public")
	}
	logger.Info("ed25519 key loaded from env")
	return pub, priv, nil
}

// resolveRSAKey returns the RSA private key for the AWS_CLOUDFRONT_RSA tenant
// scheme. When RAMP_RSA_PRIVATE_PEM is set the PEM is parsed; otherwise a
// fresh 2048-bit key is generated.
func resolveRSAKey(logger *slog.Logger) (*rsa.PrivateKey, error) {
	raw := runhttp.EnvOr("RAMP_RSA_PRIVATE_PEM", "")
	if raw == "" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("rsa keygen: %w", err)
		}
		logger.Info("rsa key generated (no RAMP_RSA_PRIVATE_PEM set)")
		return priv, nil
	}
	priv, err := parseRSAPrivatePEM(raw)
	if err != nil {
		return nil, fmt.Errorf("parse rsa pem: %w", err)
	}
	logger.Info("rsa key loaded from env")
	return priv, nil
}

func parseEd25519PrivatePEM(raw string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// OpenSSL writes Ed25519 private keys as PKCS#8.
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private, got %T", parsed)
	}
	return priv, nil
}

func parseRSAPrivatePEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pkcs8: %w", err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected rsa private, got %T", parsed)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
}
