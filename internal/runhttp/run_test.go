package runhttp

import "testing"

func TestEnvOr(t *testing.T) {
	if got := EnvOr("RAMP_TEST_UNSET_XYZ", "fallback"); got != "fallback" {
		t.Errorf("EnvOr fallback: got %q, want fallback", got)
	}
	t.Setenv("RAMP_TEST_SET", "value")
	if got := EnvOr("RAMP_TEST_SET", "fallback"); got != "value" {
		t.Errorf("EnvOr set: got %q, want value", got)
	}
}
