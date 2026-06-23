package runhttp

import (
	"testing"
	"time"
)

func TestEnvOr(t *testing.T) {
	if got := EnvOr("RAMP_TEST_UNSET_XYZ", "fallback"); got != "fallback" {
		t.Errorf("EnvOr fallback: got %q, want fallback", got)
	}
	t.Setenv("RAMP_TEST_SET", "value")
	if got := EnvOr("RAMP_TEST_SET", "fallback"); got != "value" {
		t.Errorf("EnvOr set: got %q, want value", got)
	}
}

func TestEnvBool(t *testing.T) {
	const key = "RAMP_TEST_BOOL"
	if got := EnvBool(key, true); !got {
		t.Errorf("unset should return default true, got %v", got)
	}
	if got := EnvBool(key, false); got {
		t.Errorf("unset should return default false, got %v", got)
	}
	for _, v := range []string{"0", "false", "FALSE", "no", "Off"} {
		t.Setenv(key, v)
		if EnvBool(key, true) {
			t.Errorf("%q should parse false", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", "on", "anything"} {
		t.Setenv(key, v)
		if !EnvBool(key, false) {
			t.Errorf("%q should parse true", v)
		}
	}
}

func TestEnvDuration(t *testing.T) {
	const key = "RAMP_TEST_DUR"
	if got := EnvDuration(key, 5*time.Second); got != 5*time.Second {
		t.Errorf("unset should return default, got %v", got)
	}
	t.Setenv(key, "250ms")
	if got := EnvDuration(key, time.Second); got != 250*time.Millisecond {
		t.Errorf("parse 250ms: got %v", got)
	}
	for _, bad := range []string{"nonsense", "-1s"} {
		t.Setenv(key, bad)
		if got := EnvDuration(key, time.Second); got != time.Second {
			t.Errorf("%q should fall back to default, got %v", bad, got)
		}
	}
}
