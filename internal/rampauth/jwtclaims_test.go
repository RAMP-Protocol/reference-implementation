package rampauth_test

import (
	"context"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
)

func TestJWTClaimsRoundTrip(t *testing.T) {
	ctx := rampauth.WithJWTClaims(context.Background(), rampauth.JWTClaims{
		Sub: "user_bob_123",
		Org: "acme",
	})
	got := rampauth.JWTClaimsFromContext(ctx)
	if got.Sub != "user_bob_123" || got.Org != "acme" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestJWTClaimsZeroValueFromEmptyCtx(t *testing.T) {
	got := rampauth.JWTClaimsFromContext(context.Background())
	if got.Sub != "" || got.Org != "" {
		t.Fatalf("want zero, got %+v", got)
	}
}
