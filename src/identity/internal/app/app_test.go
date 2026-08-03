package app_test

import (
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
)

// Build validates its mandatory sub-configs up front, before any DB or keystore
// work, so these guards are reached with a zero-value Config and need no fixture.
// They are the fail-closed contract: a deployment missing either mandatory surface
// must not come up, rather than serve a half-built identity service.

func TestBuild_RejectsMissingAuth(t *testing.T) {
	t.Parallel()
	handler, _, err := app.Build(app.Config{Auth: nil})
	if err == nil {
		t.Fatal("Build with nil Auth returned no error; sign-up is mandatory")
	}
	if handler != nil {
		t.Errorf("Build returned a non-nil handler alongside its error: %v", handler)
	}
	if !strings.Contains(err.Error(), "Auth is required") {
		t.Errorf("error = %q, want it to name the missing Auth config", err)
	}
}

func TestBuild_RejectsMissingMCP(t *testing.T) {
	t.Parallel()
	// Auth is present so the first guard passes and Build reaches the MCP check;
	// MCP is nil, which must fail closed — the RAMP adapter is the agent-facing
	// surface, and a server without it can be reached by no agent.
	handler, _, err := app.Build(app.Config{Auth: &app.AuthConfig{}})
	if err == nil {
		t.Fatal("Build with nil MCP returned no error; the RAMP adapter is mandatory")
	}
	if handler != nil {
		t.Errorf("Build returned a non-nil handler alongside its error: %v", handler)
	}
	if !strings.Contains(err.Error(), "MCP is required") {
		t.Errorf("error = %q, want it to name the missing MCP config", err)
	}
}
