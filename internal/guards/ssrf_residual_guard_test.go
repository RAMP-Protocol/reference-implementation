// This file pins the "hand-rolled SSRF guard" disease closed on the Go side.
// The SSRF-guarded HTTP client lives in the RAMP SDK
// (sdk/go/resolvers.NewGuardedClientFromEnv) — app code must not re-implement
// the classification, the scheme guard, the redirect anchoring, the env-gate
// option builder, or a package-level guarded default. Every outbound caller
// constructs its client from the SDK factory; nothing in the app re-wraps it.
package guards

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// residualSSRFGuard matches every hand-rolled SSRF-guard identifier that must
// NOT survive in app source. The two package-qualified forms
// (rampwellknown.NewGuardedClient, rampwellknown.GuardOptions) are anchored to
// the rampwellknown package on purpose: the bare token "NewGuardedClient" is a
// SUBSTRING of the RETAINED SDK call resolvers.NewGuardedClientFromEnv (used by
// internal/agentkeys after the rewire), so an unqualified ban would false-fail.
// rampwellknown.NewGuardedClient still catches rampwellknown.NewGuardedClientFromEnv
// (it is a prefix), and rampwellknown.GuardOptions catches ...GuardOptionsFromEnv.
// The remaining names are guard.go-local and unambiguous.
var residualSSRFGuard = regexp.MustCompile(
	`rampwellknown\.NewGuardedClient|` +
		`rampwellknown\.GuardOptions|` +
		`\bguardControl\b|` +
		`\bschemeGuard\b|` +
		`\bguardRedirect\b|` +
		`\bGuardOptionsFromEnv\b|` +
		`\bdefaultGuardedClient\b`,
)

// TestNoResidualHandRolledSSRFGuard fails when any app source file still carries
// hand-rolled SSRF-guard code — the guard belongs to sdk/go/resolvers, never to
// the app (internal/rampwellknown/guard.go and its callers must be gone).
func TestNoResidualHandRolledSSRFGuard(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range appSourceFiles(t, root) {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if residualSSRFGuard.Match(src) {
			t.Errorf("%s still carries hand-rolled SSRF-guard code — construct the client "+
				"from the SDK factory resolvers.NewGuardedClientFromEnv() and delete "+
				"internal/rampwellknown/guard.go", rel)
		}
	}
}

// TestSSRFGuardFileStaysDeleted fails while the deleted disease home reappears.
func TestSSRFGuardFileStaysDeleted(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range []string{
		"internal/rampwellknown/guard.go",
		"internal/rampwellknown/guard_test.go",
		"internal/rampwellknown/guard_internal_test.go",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Errorf("%s exists — the SSRF guard is SDK-owned (sdk/go/resolvers); "+
				"do not keep the app copy", rel)
		}
	}
}

// --- meta-tests: prove the detector itself works ---------------------------

// TestMeta_ResidualSSRFDetectorFlagsHandRolledCode is the positive meta-test:
// package-qualified guard construction and a guard.go-local name must both match.
func TestMeta_ResidualSSRFDetectorFlagsHandRolledCode(t *testing.T) {
	t.Parallel()
	for _, dirty := range []string{
		`client = rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{Insecure: true})`,
		`fetchClient := rampwellknown.NewGuardedClientFromEnv()`,
		`Control: guardControl(opts.Insecure),`,
		`Transport: schemeGuard{base: base}`,
		`CheckRedirect: guardRedirect(opts.Insecure),`,
		`return NewGuardedClient(GuardOptionsFromEnv())`,
		`var defaultGuardedClient = sync.OnceValue(...)`,
	} {
		if !residualSSRFGuard.MatchString(dirty) {
			t.Fatalf("residual-SSRF detector missed hand-rolled code: %q", dirty)
		}
	}
}

// TestMeta_ResidualSSRFDetectorPassesSDKCall is the negative meta-test: the
// RETAINED SDK factory call must NOT match, even though it contains the
// substring "NewGuardedClient" and "GuardedClientFromEnv".
func TestMeta_ResidualSSRFDetectorPassesSDKCall(t *testing.T) {
	t.Parallel()
	for _, clean := range []string{
		`client, err := resolvers.NewGuardedClientFromEnv()`,
		`cfg.HTTP, err = resolvers.NewGuardedClientFromEnv()`,
	} {
		if residualSSRFGuard.MatchString(clean) {
			t.Fatalf("residual-SSRF detector wrongly flagged the retained SDK call: %q", clean)
		}
	}
}
