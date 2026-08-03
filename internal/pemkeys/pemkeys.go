// Package pemkeys is the single home for the PKCS#8 PEM encoding of Ed25519
// private keys.
//
// Two callers need the same format from opposite directions: the Exchange
// *parses* an operator-provisioned signing key at boot (openssl writes Ed25519
// as PKCS#8, so that is the shape on disk), and the Identity Service *emits*
// one when a developer exports the key the registry custodies for their agent.
// An exported key that the importing side cannot parse is a silent breach of
// the "the developer owns their identity" promise, so encode and decode live in
// one package with a round-trip test rather than in two trees that drift.
package pemkeys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// blockType is the PEM block header PKCS#8 keys carry. It is deliberately not
// "ED25519 PRIVATE KEY": x509.MarshalPKCS8PrivateKey emits PKCS#8 DER, and
// openssl labels that block "PRIVATE KEY" regardless of the algorithm inside.
const blockType = "PRIVATE KEY"

// ErrNotPEM is returned when the input contains no PEM block at all.
var ErrNotPEM = errors.New("pemkeys: no PEM block found")

// MarshalEd25519Private encodes priv as a PKCS#8 PEM document. The output is
// byte-identical to `openssl genpkey -algorithm ED25519`, so an exported key
// drops straight into any tool that speaks PEM.
func MarshalEd25519Private(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("pemkeys: marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), nil
}

// ParseEd25519Private decodes a PKCS#8 PEM document into an Ed25519 private key.
// A PEM holding a different algorithm (an RSA key, say) is an error rather than
// a silent nil: the caller asked for an Ed25519 key and must not proceed with
// something else.
func ParseEd25519Private(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, ErrNotPEM
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pemkeys: parse pkcs8: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pemkeys: expected ed25519 private key, got %T", parsed)
	}
	return priv, nil
}
