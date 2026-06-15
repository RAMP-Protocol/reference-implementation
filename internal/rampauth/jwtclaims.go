package rampauth

import "context"

// JWTClaims captures the subset of JWT-derived principal facts the
// Exchange service layer consumes for authz and audit:
//
//   - Sub — the JWT subject (principal identifier). Used as one input
//     to the agent-identity hash (see docs/design/request-lifecycle.md
//     §2a and sha256(sub||tenant_id) in src/exchange/internal/service).
//   - Org — the JWT org/tenant claim. Gate D cross-checks this against
//     the authority-block subscriber_org fact.
//
// JWT validation lives in a future interceptor (tracked as ye6f-5); the
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
