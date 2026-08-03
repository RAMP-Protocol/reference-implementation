package oidcup_test

import (
	"context"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
)

// New's discovery leg needs a live issuer, so it is exercised by the Tier-B E2E
// against a real Zitadel. What is unit-testable without a network is that New
// rejects an incomplete config before attempting discovery.
func TestNew_RejectsIncompleteConfig(t *testing.T) {
	cases := map[string]oidcup.Config{
		"no issuer":       {ClientID: "c", RedirectURL: "https://auth.example/callback"},
		"no client id":    {Issuer: "https://idp.example", RedirectURL: "https://auth.example/callback"},
		"no redirect":     {Issuer: "https://idp.example", ClientID: "c"},
		"all three unset": {},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := oidcup.New(context.Background(), cfg); err == nil {
				t.Fatalf("New(%+v) = nil error, want a validation failure", cfg)
			}
		})
	}
}
