package runhttp

import (
	"os"
	"path/filepath"
	"testing"
)

// EnvOrFile is the seam that lets the OIDC client credentials arrive as mounted
// secret files instead of inline env (the e2e stack, and Docker/Kubernetes
// secrets in production). These pin the four behaviors the wiring depends on:
// inline value, file fallback, inline precedence, and a set-but-unreadable file
// failing loudly rather than resolving to empty.

func TestEnvOrFile_InlineValueUsedDirectly(t *testing.T) {
	t.Setenv("RAMP_TEST_CRED", "inline-secret")

	got, err := EnvOrFile("RAMP_TEST_CRED")
	if err != nil {
		t.Fatalf("envOrFile: %v", err)
	}
	if got != "inline-secret" {
		t.Fatalf("got %q, want the inline value", got)
	}
}

func TestEnvOrFile_ReadsFromFileWhenInlineEmpty(t *testing.T) {
	// A file with a trailing newline, as a shell redirect or a secret mount
	// commonly writes — the newline must be trimmed, or the credential carries a
	// stray byte and the OIDC handshake fails.
	path := writeTemp(t, "file-secret\n")
	t.Setenv("RAMP_TEST_CRED", "")
	t.Setenv("RAMP_TEST_CRED_FILE", path)

	got, err := EnvOrFile("RAMP_TEST_CRED")
	if err != nil {
		t.Fatalf("envOrFile: %v", err)
	}
	if got != "file-secret" {
		t.Fatalf("got %q, want the trimmed file contents", got)
	}
}

func TestEnvOrFile_InlineWinsOverFile(t *testing.T) {
	path := writeTemp(t, "file-secret")
	t.Setenv("RAMP_TEST_CRED", "inline-secret")
	t.Setenv("RAMP_TEST_CRED_FILE", path)

	got, err := EnvOrFile("RAMP_TEST_CRED")
	if err != nil {
		t.Fatalf("envOrFile: %v", err)
	}
	if got != "inline-secret" {
		t.Fatalf("got %q, want the inline value to win over the file", got)
	}
}

func TestEnvOrFile_EmptyWhenNeitherSet(t *testing.T) {
	t.Setenv("RAMP_TEST_CRED", "")
	t.Setenv("RAMP_TEST_CRED_FILE", "")

	got, err := EnvOrFile("RAMP_TEST_CRED")
	if err != nil {
		t.Fatalf("envOrFile: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty when neither the var nor its _FILE is set", got)
	}
}

func TestEnvOrFile_UnreadableFileIsAnError(t *testing.T) {
	// A configured-but-missing secret file must fail startup, not degrade to an
	// empty credential that then surfaces as a confusing OIDC error later.
	t.Setenv("RAMP_TEST_CRED", "")
	t.Setenv("RAMP_TEST_CRED_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	if _, err := EnvOrFile("RAMP_TEST_CRED"); err == nil {
		t.Fatal("envOrFile returned no error for an unreadable _FILE")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp secret: %v", err)
	}
	return path
}
