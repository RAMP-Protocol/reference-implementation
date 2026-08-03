// Helpers that resolve the Exchange's signing keys. Both schemes (Ed25519 for
// offer + demo URL signing, RSA for the AWS_CLOUDFRONT_RSA tenant scheme) resolve
// from an inline PEM env var or, when that is empty, a matching *_PEM_FILE path:
//
//   - Production wires the env var from Secrets Manager (the AWS ECS task).
//   - e2e injects a file the keygen one-shot writes at stack-up (compose).
//   - Local `go run` uses `make dev-keys` to write the same files.
//
// There is NO in-process key generation. Minting a fresh key on each restart
// would silently invalidate every previously-signed URL and offer attestation,
// so the binary fails closed rather than booting on a key no consumer can verify
// against.
//
// The two keys differ in WHEN a missing one is fatal. Every tenant signs offers
// with the Ed25519 key, so its absence stops the boot. The RSA key is needed only
// by tenants on the AWS_CLOUDFRONT_RSA scheme, so its absence is deferred: the
// Exchange starts, and only a request that would mint a CloudFront URL is
// refused, with the settings to fix named in the refusal.
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

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/pemkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
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

// errNoRSAKey is the refusal a tenant on the AWS_CLOUDFRONT_RSA scheme gets when
// the Exchange was started without an RSA key. It wraps the signing package's
// sentinel — which the service layer matches to classify the refusal as
// FailedPrecondition rather than Internal — and appends the env settings here,
// because which variables supply the key is composition-root knowledge the
// signing package does not have. The full message must survive unchanged up to
// the service layer, which logs it for the operator: a bare "rsa key not found"
// tells an operator nothing about the fix. Remote callers get a sanitized
// message instead — env-var names are operator knowledge, not caller knowledge
// (see mintSignedURL).
var errNoRSAKey = fmt.Errorf(
	"%w — set RAMP_RSA_PRIVATE_PEM or RAMP_RSA_PRIVATE_PEM_FILE",
	signing.ErrRSAKeyUnavailable,
)

// resolveRSAKeyIfConfigured loads the RSA private key for the
// AWS_CLOUDFRONT_RSA tenant scheme from RAMP_RSA_PRIVATE_PEM, or — when that is
// empty — the file at RAMP_RSA_PRIVATE_PEM_FILE. It returns (nil, nil) when
// NEITHER is set.
//
// That is the one place this differs from the Ed25519 path, and deliberately:
// every tenant needs the Ed25519 key, so its absence is a boot error, while the
// RSA key is needed only by CloudFront-scheme tenants. Forcing every deployment
// to supply one made a Cloudflare-only stack generate and mount a key nothing
// reads. An absent key is therefore deferred to the first tenant that needs it
// (see installRSAKey); a key that IS configured but unparseable still fails
// here, because an operator who configured one plainly means to use it and a
// mis-provisioned stack should fail fast rather than at first CloudFront mint.
func resolveRSAKeyIfConfigured(logger *slog.Logger) (*rsa.PrivateKey, error) {
	raw, err := pemFromEnvOrFile("RAMP_RSA_PRIVATE_PEM", "RAMP_RSA_PRIVATE_PEM_FILE")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
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

// parseEd25519PrivatePEM decodes the PKCS#8 PEM openssl writes for an Ed25519
// key. The format is shared with the Identity Service, which emits it when a
// developer exports the key it custodies, so encode and decode live together in
// internal/pemkeys with a round-trip test rather than once per tree.
func parseEd25519PrivatePEM(raw string) (ed25519.PrivateKey, error) {
	return pemkeys.ParseEd25519Private([]byte(raw))
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

// demoKeys bundles the Ed25519 + RSA key material setupDemoKeys returns; a
// struct keeps the run() call site readable and within line-length limits.
type demoKeys struct {
	offerSigner *signing.Ed25519Signer
	keystore    *signing.InMemoryKeyStore
}

// setupDemoKeys resolves the Ed25519 key every tenant signs offers with, and
// installs the RSA key material the AWS_CLOUDFRONT_RSA scheme needs. Extracted
// from run() to keep run() under the funlen cap.
func setupDemoKeys(logger *slog.Logger) (*demoKeys, error) {
	demoPub, demoPriv, err := resolveEd25519Key(logger)
	if err != nil {
		return nil, err
	}
	offerSigner, err := signing.NewEd25519Signer(demoPub, demoPriv)
	if err != nil {
		return nil, err
	}
	keystore := signing.NewInMemoryKeyStore()
	demoKeyRef := runhttp.EnvOr("RAMP_DEMO_ED25519_KEY_REF", "exchange-primary")
	keystore.PutEd25519(demoKeyRef, demoPub, demoPriv)
	if err := installRSAKey(logger, keystore); err != nil {
		return nil, err
	}
	return &demoKeys{offerSigner: offerSigner, keystore: keystore}, nil
}

// installRSAKey puts the AWS_CLOUDFRONT_RSA scheme's key material in the
// keystore under the ref a CloudFront-scheme tenant's rsa_key_ref points at.
//
// A configured key is stored now, so a broken one stops the boot. An ABSENT key
// registers a provider that refuses on first lookup instead: the Exchange then
// starts and serves every Ed25519 tenant, and only a CloudFront-scheme tenant
// ever meets the refusal — carrying the settings to fix, since URLSignerFor
// reaches the keystore only in its CloudFront branch.
func installRSAKey(logger *slog.Logger, keystore *signing.InMemoryKeyStore) error {
	ref := runhttp.EnvOr("RAMP_DEMO_RSA_KEY_REF", "cf-rsa-primary")
	priv, err := resolveRSAKeyIfConfigured(logger)
	if err != nil {
		return err
	}
	if priv != nil {
		keystore.PutRSA(ref, priv)
		return nil
	}
	logger.Info("no RSA signing key configured; AWS_CLOUDFRONT_RSA tenants will be refused",
		"rsa_key_ref", ref)
	keystore.PutRSAFunc(ref, func() (*rsa.PrivateKey, error) { return nil, errNoRSAKey })
	return nil
}
