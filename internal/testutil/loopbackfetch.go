package testutil

import "testing"

// AllowLoopbackFetch opens the SDK's two deployment opt-outs so an httptest peer
// on loopback is reachable: SKIP_SSRF drops the dial-time address check, and
// ALLOW_INSECURE permits the plaintext http scheme such a peer speaks.
//
// These are PRODUCTION switches a local stack sets, not a test-only bypass, and
// the guards they open are real — they refuse these peers by default, which is
// what TestRegister_DialsUnderTheSSRFGuard in the identity service's outbound
// client asserts by clearing both and watching the dial be refused.
//
// The SDK reads both variables when a transport is CONSTRUCTED, so this must run
// before the code under test builds one. t.Setenv is also why a test that dials
// this way cannot be parallel.
//
// Shared because four call sites across all three services set the same pair,
// each with the reasoning written out again in different words — one upstream
// rename away from four edits and four independently drifting explanations. They
// had already drifted on the value: two wrote "1" and two wrote "true". The SDK
// accepts either, so nothing was broken, which is exactly why nobody noticed.
//
// The sites that CLEAR both variables are a different rule and stay as they are.
// They arm the guards to watch a dial be refused, which is the assertion this
// helper's opt-out exists to be measured against.
func AllowLoopbackFetch(t *testing.T) {
	t.Helper()
	t.Setenv("SKIP_SSRF", "1")
	t.Setenv("ALLOW_INSECURE", "1")
}
