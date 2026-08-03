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

// EnvOptIn guards deliberately-unsafe behaviour, so it is a strict allowlist:
// only "true" and "1" enable it. The cases that matter are the ones EnvBool
// would wrongly treat as true — a typo must leave the guard in place.
func TestEnvOptIn(t *testing.T) {
	const key = "RAMP_TEST_OPTIN"

	if EnvOptIn(key) {
		t.Error("unset must be false")
	}
	for _, v := range []string{"true", "TRUE", "True", "1"} {
		t.Setenv(key, v)
		if !EnvOptIn(key) {
			t.Errorf("%q should opt in", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "yes", "on", "flase", "disabled", "true "} {
		t.Setenv(key, v)
		if EnvOptIn(key) {
			t.Errorf("%q must NOT opt in", v)
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
