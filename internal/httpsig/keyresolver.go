package httpsig

import (
	"context"
	"crypto/ed25519"
)

// KeyResolver looks up the Ed25519 public key registered for keyid (after the
// WBA split, an RFC 7638 thumbprint). The adapter is the boundary between the
// RFC 9421 verifier and whatever key directory the caller wires. The SDK's
// helpers.StaticKeyResolver satisfies it structurally, and its
// helpers.ErrUnknownKey miss is the conventional unknown-keyid sentinel —
// this package no longer defines one of its own. A discovery resolver reads
// the signed directory origin via SignatureAgentFromContext to know which WBA
// directory to fetch.
type KeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

type signatureAgentCtxKey struct{}

// WithSignatureAgent returns ctx carrying the (signed) Signature-Agent directory
// origin. The verifier sets it before invoking a KeyResolver so a discovery
// resolver knows which WBA directory to fetch and match the keyid against.
func WithSignatureAgent(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, signatureAgentCtxKey{}, dir)
}

// SignatureAgentFromContext returns the Signature-Agent directory origin set by
// the verifier, or "" when absent.
func SignatureAgentFromContext(ctx context.Context) string {
	v, _ := ctx.Value(signatureAgentCtxKey{}).(string)
	return v
}
