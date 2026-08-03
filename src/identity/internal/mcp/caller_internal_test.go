package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
)

// callerFrom decides whose custodied key signs a tool call, so its branches are
// the anti-impersonation guard. The fail-closed mismatch branch cannot be staged
// over the wire — the SDK pins a session to one TokenInfo.UserID and refuses a
// second — so it is unreachable from the integration suite and would survive its
// own deletion there. callerFrom is pure logic with four branches, which testing
// doctrine point 2 admits for a unit test; this table drives each directly.
func TestCallerFrom(t *testing.T) {
	t.Parallel()

	ctxWith := func(subdomain string) context.Context {
		if subdomain == "" {
			return context.Background()
		}
		return agentsign.WithSubdomain(context.Background(), subdomain)
	}
	// reqWith builds a CallToolRequest whose Extra carries the given bearer UserID;
	// hasExtra=false models the SDK supplying no Extra at all (nil request extras).
	reqWith := func(hasExtra bool, userID string) *mcpsdk.CallToolRequest {
		if !hasExtra {
			return &mcpsdk.CallToolRequest{}
		}
		extra := &mcpsdk.RequestExtra{}
		if userID != "" {
			extra.TokenInfo = &auth.TokenInfo{UserID: userID}
		}
		return &mcpsdk.CallToolRequest{Extra: extra}
	}

	cases := []struct {
		name         string
		ctxSubdomain string
		hasExtra     bool
		bearerUserID string
		wantSub      string
		wantErr      error
	}{
		{
			name:         "context and bearer agree",
			ctxSubdomain: "agent-a", hasExtra: true, bearerUserID: "agent-a",
			wantSub: "agent-a",
		},
		{
			name:         "context and bearer disagree fails closed",
			ctxSubdomain: "agent-a", hasExtra: true, bearerUserID: "agent-b",
			wantErr: errIdentityMismatch,
		},
		{
			name:         "context only, no extra supplied",
			ctxSubdomain: "agent-a", hasExtra: false,
			wantSub: "agent-a",
		},
		{
			name:         "bearer only, empty context",
			ctxSubdomain: "", hasExtra: true, bearerUserID: "agent-b",
			wantSub: "agent-b",
		},
		{
			name:         "extra present but no bearer, context carries identity",
			ctxSubdomain: "agent-a", hasExtra: true, bearerUserID: "",
			wantSub: "agent-a",
		},
		{
			name:         "no extra and empty context",
			ctxSubdomain: "", hasExtra: false,
			wantErr: errNoIdentity,
		},
		{
			name:         "extra without bearer and empty context",
			ctxSubdomain: "", hasExtra: true, bearerUserID: "",
			wantErr: errNoIdentity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := callerFrom(ctxWith(tc.ctxSubdomain), reqWith(tc.hasExtra, tc.bearerUserID))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got.subdomain != "" {
					t.Errorf("a rejected call returned a subdomain %q; it must be empty", got.subdomain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.subdomain != tc.wantSub {
				t.Errorf("subdomain = %q, want %q", got.subdomain, tc.wantSub)
			}
		})
	}
}
