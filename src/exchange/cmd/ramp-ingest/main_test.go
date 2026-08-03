package main

import (
	"strings"
	"testing"
)

// TestRun_MissingKeyFlagErrors asserts the ingester refuses to run when --key is
// absent: there is no committed default key any more, so the only safe behavior
// is a clear non-nil error naming the missing flag. This is the no-private-key-in-git invariant
// — the ingester cannot fall back to a tracked private key.
func TestRun_MissingKeyFlagErrors(t *testing.T) {
	// All other required flags are supplied so the only failure cause is --key.
	err := run([]string{
		"-exchange-url", "http://exchange:8081",
		"-tenant", "publisher.example",
	})
	if err == nil {
		t.Fatal("run with no --key returned nil error; want a missing-key error")
	}
	// The error must be the explicit required-flag rejection, NOT a downstream
	// read error from a fallback default path — there is no committed default
	// key any more. The sentinel phrase proves validation fired before
	// any file access.
	if !strings.Contains(err.Error(), "--key is required") {
		t.Fatalf("error %q is not the explicit required-flag rejection for --key", err)
	}
}

// TestRun_MissingKeyFileErrors asserts that supplying --key pointing at a
// nonexistent file fails clearly rather than silently degrading.
func TestRun_MissingKeyFileErrors(t *testing.T) {
	err := run([]string{
		"-exchange-url", "http://exchange:8081",
		"-tenant", "publisher.example",
		"-key", "/nonexistent/path/to/key.json",
	})
	if err == nil {
		t.Fatal("run with missing key file returned nil error; want a read error")
	}
}

// TestRun_MissingExchangeURLErrors and TestRun_MissingTenantErrors pin the other
// two required flags so the "required" doc comment is enforced, not aspirational.
func TestRun_MissingExchangeURLErrors(t *testing.T) {
	err := run([]string{
		"-tenant", "publisher.example",
		"-key", "/some/key.json",
	})
	if err == nil {
		t.Fatal("run with no --exchange-url returned nil error; want a missing-flag error")
	}
	if !strings.Contains(err.Error(), "--exchange-url is required") {
		t.Fatalf("error %q is not the explicit required-flag rejection for --exchange-url", err)
	}
}

func TestRun_MissingTenantErrors(t *testing.T) {
	err := run([]string{
		"-exchange-url", "http://exchange:8081",
		"-key", "/some/key.json",
	})
	if err == nil {
		t.Fatal("run with no --tenant returned nil error; want a missing-flag error")
	}
	if !strings.Contains(err.Error(), "--tenant is required") {
		t.Fatalf("error %q is not the explicit required-flag rejection for --tenant", err)
	}
}
