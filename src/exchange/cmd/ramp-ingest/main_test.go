package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// sampleFeedPath resolves the committed reference sample JSON-L fixture
// relative to this test file (deploy/fixtures/publisher/sample.jsonl at the
// repo root).
func sampleFeedPath() string {
	return filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "publisher", "sample.jsonl")
}

// TestRun_MissingKeyFlagErrors asserts the ingester refuses to run when --key is
// absent: there is no committed default key any more, so the only safe behavior
// is a clear non-nil error naming the missing flag. This is the no-private-key-in-git invariant
// — the ingester cannot fall back to a tracked private key.
func TestRun_MissingKeyFlagErrors(t *testing.T) {
	// All other required flags are supplied so the only failure cause is --key.
	err := run([]string{
		"-exchange-url", "http://exchange:8081",
		"-tenant", "publisher.example",
	}, io.Discard)
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
		sampleFeedPath(),
	}, io.Discard)
	if err == nil {
		t.Fatal("run with missing key file returned nil error; want a read error")
	}
}

// TestRun_MissingExchangeURLErrors and TestRun_MissingTenantErrors pin the other
// two required flags so the "required" doc comment is enforced, not aspirational.
// --exchange is deliberately absent from that list: it defaults to the host of
// --exchange-url, and ingest.Run's own tests pin the derivation.
func TestRun_MissingExchangeURLErrors(t *testing.T) {
	err := run([]string{
		"-tenant", "publisher.example",
		"-key", "/some/key.json",
	}, io.Discard)
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
	}, io.Discard)
	if err == nil {
		t.Fatal("run with no --tenant returned nil error; want a missing-flag error")
	}
	if !strings.Contains(err.Error(), "--tenant is required") {
		t.Fatalf("error %q is not the explicit required-flag rejection for --tenant", err)
	}
}

// TestRun_CheckNeedsNoConnectionFlags proves --check is a local verdict. With
// none of --key, --exchange-url or --tenant it still runs; on a feed carrying
// an entry the Exchange's ingest tier would refuse (a bare pricing unit that
// is not a registered metering token) it returns an error and the report
// names the SDK rule, the field path and the token; on the committed sample
// feed it returns nil. Nothing is dialled and no key is read — there is no
// URL to dial and no key path to read.
func TestRun_CheckNeedsNoConnectionFlags(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	line := `{"domain":"publisher.example","path":"/article/bogus-unit","terms":[{"semantics":"enumerated",` +
		`"pricing":{"model":"per_unit","unit":"bogus-unit","rate":"0.01","currency":"EUR"}}]}` + "\n"
	if err := os.WriteFile(bad, []byte(line), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	var report bytes.Buffer
	err := run([]string{"-check", bad}, &report)
	if err == nil {
		t.Fatal("--check over a feed with a violation returned nil; want an error so the process exits non-zero")
	}
	if !strings.Contains(err.Error(), "1 violation(s)") {
		t.Fatalf("error %q does not count the violation", err)
	}
	for _, want := range []string{
		"record 0 (publisher.example/article/bogus-unit): violation",
		"rule=pricing.unit.registered",
		"path=terms[0].pricing.unit",
		`token="bogus-unit"`,
		"check: records=1 violations=1 warnings=0",
	} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("check report lacks %q:\n%s", want, report.String())
		}
	}

	report.Reset()
	if err := run([]string{"-check", sampleFeedPath()}, &report); err != nil {
		t.Fatalf("--check over the sample feed: %v\n%s", err, report.String())
	}
	if !strings.Contains(report.String(), "check: records=") || !strings.Contains(report.String(), "violations=0") {
		t.Fatalf("check report over the sample feed lacks a clean summary:\n%s", report.String())
	}
}

// TestRun_CheckAcceptsAWarningOnlyFeed pins the contract --check exists to
// allow: a feed the Exchange stores and merely warns about must exit 0. The
// warning is an unregistered bare restriction token, which is accepted and
// reported in the push response. Without this case the CLI suite covers only
// clean feeds and feeds with violations, and a verdict tightened to "no
// findings at all" would block a publisher from pushing a feed that pushes.
func TestRun_CheckAcceptsAWarningOnlyFeed(t *testing.T) {
	warn := filepath.Join(t.TempDir(), "warn.jsonl")
	line := `{"domain":"publisher.example","path":"/article/odd-function","terms":[{"semantics":"enumerated",` +
		`"functions":["ai-input","totally-made-up-function"],"pricing":{"model":"free","rate":"0","currency":"EUR"}}]}` + "\n"
	if err := os.WriteFile(warn, []byte(line), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	var report bytes.Buffer
	if err := run([]string{"-check", warn}, &report); err != nil {
		t.Fatalf("--check over a warning-only feed returned %v; a warning does not fail the check\n%s", err, report.String())
	}
	for _, want := range []string{
		"record 0 (publisher.example/article/odd-function): warning",
		"check: records=1 violations=0 warnings=1",
	} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("check report lacks %q:\n%s", want, report.String())
		}
	}
}

// TestRun_CheckRefusesAnEmptyFeed pins that --check gives an empty feed the
// same refusal the push gives it. Nothing earlier catches one — it parses and
// it maps — so a check that reported zero findings over zero records would
// hand a CI preflight a green light for a feed the run rejects every time.
func TestRun_CheckRefusesAnEmptyFeed(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	// The sentinel, not its sentence. The package exports ErrEmptyFeed and the
	// other two call sites match on it; matching the message here would fail on
	// a reword that changed no behaviour, and would pass for any other error
	// whose text happened to contain the phrase.
	if err := run([]string{"-check", empty}, io.Discard); !errors.Is(err, ingest.ErrEmptyFeed) {
		t.Fatalf("--check over an empty feed returned %v; want ErrEmptyFeed", err)
	}
}

// TestRun_CheckRefusesAFeedThatDoesNotParse pins that --check is as strict as
// a push about the feed's shape: a line that is not a record is an error
// naming the line, exactly as Run would refuse it, not a clean report.
func TestRun_CheckRefusesAFeedThatDoesNotParse(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken.jsonl")
	if err := os.WriteFile(broken, []byte(`{"domain":"publisher.example","unknown":1}`+"\n"), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	err := run([]string{"-check", broken}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("--check over an unparseable feed returned %v; want a parse error naming line 1", err)
	}
}
