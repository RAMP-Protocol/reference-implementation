package token_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestIssuer_MintVerifyRoundTrip(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	iss, err := token.NewIssuer(mustKey(t), "https://auth.rampmcp.org", "https://mcp.rampmcp.org", clk)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	raw, err := iss.Mint("agent-xyz.rampmcp.org", time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := iss.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "agent-xyz.rampmcp.org" {
		t.Errorf("subject = %q, want the minted subdomain", claims.Subject)
	}
	if claims.Issuer != "https://auth.rampmcp.org" {
		t.Errorf("issuer = %q, want the configured issuer", claims.Issuer)
	}
}

func TestIssuer_VerifyRejectsExpired(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	iss, _ := token.NewIssuer(mustKey(t), "iss", "aud", clk)
	raw, _ := iss.Mint("sub", 30*time.Minute)

	// Advance well past expiry plus go-jose's default 1-minute skew leeway.
	clk.Advance(40 * time.Minute)
	if _, err := iss.Verify(raw); !errors.Is(err, token.ErrInvalid) {
		t.Fatalf("Verify expired = %v, want ErrInvalid", err)
	}
}

func TestIssuer_VerifyRejectsWrongAudience(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	priv := mustKey(t)
	minter, _ := token.NewIssuer(priv, "iss", "aud-a", clk)
	raw, _ := minter.Mint("sub", time.Hour)

	// Same key, different audience: a resource server for aud-b must reject a token
	// minted for aud-a.
	verifier, _ := token.NewIssuer(priv, "iss", "aud-b", clk)
	if _, err := verifier.Verify(raw); !errors.Is(err, token.ErrInvalid) {
		t.Fatalf("Verify wrong-aud = %v, want ErrInvalid", err)
	}
}

func TestIssuer_VerifyRejectsWrongKey(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	minter, _ := token.NewIssuer(mustKey(t), "iss", "aud", clk)
	raw, _ := minter.Mint("sub", time.Hour)

	other, _ := token.NewIssuer(mustKey(t), "iss", "aud", clk)
	if _, err := other.Verify(raw); !errors.Is(err, token.ErrInvalid) {
		t.Fatalf("Verify wrong-key = %v, want ErrInvalid", err)
	}
}

func TestNewIssuer_RejectsBadKey(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if _, err := token.NewIssuer(ed25519.PrivateKey("too-short"), "iss", "aud", clk); err == nil {
		t.Fatal("NewIssuer with short key = nil error, want failure")
	}
	if _, err := token.NewIssuer(mustKey(t), "iss", "aud", nil); err == nil {
		t.Fatal("NewIssuer with nil clock = nil error, want failure")
	}
}
