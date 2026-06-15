package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// TestPEMFromEnvOrFile covers the four branches of pemFromEnvOrFile, including the
// fail-closed error path for an explicitly-configured-but-unreadable key file (a
// minted-but-unverifiable key would break verification at the edge, so a
// mis-provisioned stack must fail fast rather than silently degrade).
func TestPEMFromEnvOrFile(t *testing.T) {
	const inlineVar, fileVar = "RAMP_RSA_PRIVATE_PEM", "RAMP_RSA_PRIVATE_PEM_FILE"

	// Subtests use t.Setenv and therefore cannot run with t.Parallel.
	t.Run("env set wins over file", func(t *testing.T) {
		t.Setenv(inlineVar, "PEM-FROM-ENV")
		t.Setenv(fileVar, "/ignored")
		got, err := pemFromEnvOrFile(inlineVar, fileVar)
		if err != nil || got != "PEM-FROM-ENV" {
			t.Fatalf("got %q, err %v; want %q, nil", got, err, "PEM-FROM-ENV")
		}
	})

	t.Run("neither set returns empty", func(t *testing.T) {
		t.Setenv(inlineVar, "")
		t.Setenv(fileVar, "")
		got, err := pemFromEnvOrFile(inlineVar, fileVar)
		if err != nil || got != "" {
			t.Fatalf("got %q, err %v; want empty, nil", got, err)
		}
	})

	t.Run("readable file returns contents", func(t *testing.T) {
		t.Setenv(inlineVar, "")
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, []byte("PEM-FROM-FILE"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Setenv(fileVar, path)
		got, err := pemFromEnvOrFile(inlineVar, fileVar)
		if err != nil || got != "PEM-FROM-FILE" {
			t.Fatalf("got %q, err %v; want %q, nil", got, err, "PEM-FROM-FILE")
		}
	})

	t.Run("unreadable file is hard error", func(t *testing.T) {
		t.Setenv(inlineVar, "")
		t.Setenv(fileVar, filepath.Join(t.TempDir(), "missing.pem"))
		if _, err := pemFromEnvOrFile(inlineVar, fileVar); err == nil {
			t.Fatal("want error for unreadable file, got nil")
		}
	})
}

// TestResolveEd25519Key_FailsClosedWhenUnset pins that an unset Ed25519 key is a
// hard error: no ephemeral keypair is minted (which would invalidate every
// previously-signed URL on the next restart).
func TestResolveEd25519Key_FailsClosedWhenUnset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("RAMP_ED25519_PRIVATE_PEM", "")
	t.Setenv("RAMP_ED25519_PRIVATE_PEM_FILE", "")
	if _, _, err := resolveEd25519Key(logger); err == nil {
		t.Fatal("want error when no Ed25519 key configured, got nil")
	}
}

// TestResolveRSAKey_FailsClosedWhenUnset is the RSA counterpart.
func TestResolveRSAKey_FailsClosedWhenUnset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("RAMP_RSA_PRIVATE_PEM", "")
	t.Setenv("RAMP_RSA_PRIVATE_PEM_FILE", "")
	if _, err := resolveRSAKey(logger); err == nil {
		t.Fatal("want error when no RSA key configured, got nil")
	}
}

// TestResolveEd25519Key_LoadsFromFile exercises the file-injection path end to
// end: a PKCS#8 PEM (the shape `openssl genpkey -algorithm ED25519` and the e2e
// keygen one-shot write) is read from RAMP_ED25519_PRIVATE_PEM_FILE and parsed
// back to the same keypair.
func TestResolveEd25519Key_LoadsFromFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "ed25519.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("RAMP_ED25519_PRIVATE_PEM", "")
	t.Setenv("RAMP_ED25519_PRIVATE_PEM_FILE", path)

	gotPub, gotPriv, err := resolveEd25519Key(logger)
	if err != nil {
		t.Fatalf("resolveEd25519Key: %v", err)
	}
	if !gotPriv.Equal(priv) {
		t.Fatal("resolved private key does not match the file's key")
	}
	if !gotPub.Equal(priv.Public()) {
		t.Fatal("resolved public key does not match the file's key")
	}
}
