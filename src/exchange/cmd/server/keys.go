// Helpers that resolve the Exchange's signing keys. Both schemes (Ed25519 for
// offer + demo URL signing, RSA for the AWS_CLOUDFRONT_RSA tenant scheme) resolve
// from an inline PEM env var or, when that is empty, a matching *_PEM_FILE path:
//
//   - Production wires the env var from Secrets Manager (the AWS ECS task).
//   - e2e injects a file the keygen one-shot writes at stack-up (compose).
//   - Local `go run` uses `make dev-keys` to write the same files.
//
// There is NO in-process key generation: an unset key is a hard error. Minting a
// fresh key on each restart would silently invalidate every previously-signed URL
// and offer attestation, so the binary fails closed rather than booting on a key
// no consumer can verify against.
package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// resolveEd25519Key loads the keypair used for offer signing and demo URL signing
// from RAMP_ED25519_PRIVATE_PEM, or — when that is empty — the file at
// RAMP_ED25519_PRIVATE_PEM_FILE. There is no in-process generation: an unset key
// is a hard error so the binary fails closed instead of minting a key that
// invalidates every previously-signed artifact on the next restart.
func resolveEd25519Key(logger *slog.Logger) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := pemFromEnvOrFile("RAMP_ED25519_PRIVATE_PEM", "RAMP_ED25519_PRIVATE_PEM_FILE")
	if err != nil {
		return nil, nil, err
	}
	if raw == "" {
		return nil, nil, errors.New(
			"no Ed25519 signing key: set RAMP_ED25519_PRIVATE_PEM or RAMP_ED25519_PRIVATE_PEM_FILE",
		)
	}
	priv, err := parseEd25519PrivatePEM(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ed25519 pem: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("ed25519 private key has non-ed25519 public")
	}
	logger.Info("ed25519 signing key loaded")
	return pub, priv, nil
}

// resolveRSAKey loads the RSA private key for the AWS_CLOUDFRONT_RSA tenant scheme
// from RAMP_RSA_PRIVATE_PEM, or — when that is empty — the file at
// RAMP_RSA_PRIVATE_PEM_FILE. Like the Ed25519 path it never generates: an unset
// key is a hard error so a mis-provisioned stack fails fast rather than minting a
// key the CloudFront shim cannot verify against.
func resolveRSAKey(logger *slog.Logger) (*rsa.PrivateKey, error) {
	raw, err := pemFromEnvOrFile("RAMP_RSA_PRIVATE_PEM", "RAMP_RSA_PRIVATE_PEM_FILE")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New(
			"no RSA signing key: set RAMP_RSA_PRIVATE_PEM or RAMP_RSA_PRIVATE_PEM_FILE",
		)
	}
	priv, err := parseRSAPrivatePEM(raw)
	if err != nil {
		return nil, fmt.Errorf("parse rsa pem: %w", err)
	}
	logger.Info("rsa signing key loaded")
	return priv, nil
}

// pemFromEnvOrFile resolves a PEM from the inline env var, then the *_FILE path.
// Returns "" only when neither is set (the caller treats "" as a hard error). An
// explicitly-configured-but-unreadable file is an error so a mis-provisioned
// deployment fails fast rather than silently degrading. File injection is the
// production-legitimate path the e2e keygen one-shot and `make dev-keys` reuse —
// ECS/k8s mount secrets as files exactly this way.
func pemFromEnvOrFile(inlineVar, fileVar string) (string, error) {
	if raw := runhttp.EnvOr(inlineVar, ""); raw != "" {
		return raw, nil
	}
	path := runhttp.EnvOr(fileVar, "")
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled deployment path
	if err != nil {
		return "", fmt.Errorf("read %s %s: %w", fileVar, path, err)
	}
	return string(data), nil
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
