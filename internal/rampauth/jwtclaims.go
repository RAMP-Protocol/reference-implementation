package rampauth

import "context"

// JWTClaims captures the subset of JWT-derived principal facts the
// Exchange service layer consumes for authz and audit:
//
//   - Sub — the JWT subject (principal identifier), carried into audit
//     records. It is NOT the agent-identity hash: that value is the
//     accepting agent's RFC 7638 JWK thumbprint — itself a SHA-256 over
//     the canonical JWK — taken from the presented key rather than from
//     any JWT claim, and used verbatim without a further hash.
//   - Org — the JWT org/tenant claim, cross-checked against the tenant
//     the request is being executed for.
//
// JWT validation lives in a future interceptor (deferred); the
// claims ride in ctx so the service layer stays transport-agnostic and
// tests can populate the struct directly without signing a real JWT.
type JWTClaims struct {
	Sub string
	Org string
}

// jwtCtxKey isolates the stashed JWTClaims from other ctx values.
type jwtCtxKey struct{}

// WithJWTClaims returns ctx annotated with the principal's claims.
func WithJWTClaims(ctx context.Context, c JWTClaims) context.Context {
	return context.WithValue(ctx, jwtCtxKey{}, c)
}

// JWTClaimsFromContext returns the claims stashed by the JWT interceptor
// (or by WithJWTClaims in tests). The zero value is returned when no
// claims are present — callers can disambiguate by inspecting Sub.
func JWTClaimsFromContext(ctx context.Context) JWTClaims {
	v, _ := ctx.Value(jwtCtxKey{}).(JWTClaims)
	return v
}
