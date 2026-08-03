package keystore

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// The subdomain and thumbprint a caller supplies become part of a storage path.
// Validating them up front is what makes an escape from one agent's namespace
// impossible by construction rather than by careful string handling downstream.
func TestValidateSubdomainRejectsAnythingThatIsNotADNSName(t *testing.T) {
	t.Parallel()

	valid := []string{
		"agent-123.rampmcp.org",
		"a.b.c.example.com",
		"agent1",
	}
	for _, subdomain := range valid {
		t.Run("accepts "+subdomain, func(t *testing.T) {
			t.Parallel()
			if err := validateSubdomain(subdomain); err != nil {
				t.Errorf("validateSubdomain(%q) = %v, want nil", subdomain, err)
			}
		})
	}

	invalid := map[string]string{
		"path traversal":     "../../etc/passwd",
		"absolute path":      "/secret/agents",
		"embedded separator": "agent/../other-agent",
		"empty":              "",
		"trailing hyphen":    "agent-.rampmcp.org",
		"leading hyphen":     "-agent.rampmcp.org",
		"uppercase":          "Agent.RampMCP.org",
		"space":              "agent 123",
		"null byte":          "agent\x00.rampmcp.org",
		"over 253 chars":     string(make([]byte, 254)),
	}
	for name, subdomain := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Parallel()
			if err := validateSubdomain(subdomain); !errors.Is(err, ErrInvalidSubdomain) {
				t.Errorf("validateSubdomain(%q) = %v, want ErrInvalidSubdomain", subdomain, err)
			}
		})
	}
}

func TestValidateRefRejectsAThumbprintThatIsNotADigest(t *testing.T) {
	t.Parallel()

	// 43 base64url characters — the length of a base64url-no-pad SHA-256 digest.
	good := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	if err := validateRef(Ref{Subdomain: "agent.rampmcp.org", Thumbprint: good}); err != nil {
		t.Errorf("validateRef with a well-formed thumbprint = %v, want nil", err)
	}

	invalid := map[string]string{
		"traversal":     "../../../root",
		"empty":         "",
		"too short":     "abc",
		"has a slash":   "0123456789abcdefghijklmnopqrstuvwxyzABCDE/G",
		"has a padding": "0123456789abcdefghijklmnopqrstuvwxyzABCDEF=",
	}
	for name, tp := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Parallel()
			err := validateRef(Ref{Subdomain: "agent.rampmcp.org", Thumbprint: tp})
			if !errors.Is(err, ErrInvalidThumbprint) {
				t.Errorf("validateRef(%q) = %v, want ErrInvalidThumbprint", tp, err)
			}
		})
	}
}

// List's order is load-bearing: a WBA consumer that does not know which key it
// wants takes the first one in document order. Newest-first is what puts a freshly
// rotated key in front of the one it replaces.
func TestSortNewestFirstLeadsWithTheNewestKey(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	keys := []Key{
		{Ref: Ref{Thumbprint: "older"}, CreatedAt: base},
		{Ref: Ref{Thumbprint: "newest"}, CreatedAt: base.Add(2 * time.Hour)},
		{Ref: Ref{Thumbprint: "middle"}, CreatedAt: base.Add(time.Hour)},
	}

	sortNewestFirst(keys)

	want := []string{"newest", "middle", "older"}
	for i, tp := range want {
		if keys[i].Ref.Thumbprint != tp {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, keys[i].Ref.Thumbprint, tp, thumbprintsOf(keys))
		}
	}
}

// Two keys minted in the same instant must still come back in one fixed order —
// otherwise the "current key" a consumer picks could change between two reads of
// the same directory.
func TestSortNewestFirstIsTotalWhenTimestampsTie(t *testing.T) {
	t.Parallel()

	same := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	keys := []Key{
		{Ref: Ref{Thumbprint: "bbb"}, CreatedAt: same},
		{Ref: Ref{Thumbprint: "aaa"}, CreatedAt: same},
	}

	sortNewestFirst(keys)

	if keys[0].Ref.Thumbprint != "aaa" || keys[1].Ref.Thumbprint != "bbb" {
		t.Errorf("tie broken as %v, want thumbprint order [aaa bbb]", thumbprintsOf(keys))
	}
}

func TestConfigRequiresAnAuthenticatedClientAndAClock(t *testing.T) {
	t.Parallel()

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}

	// The store never builds its own Vault client: how the service proves its
	// identity to Vault is the composition root's decision, and hardening it later
	// must not mean editing custody. And it never falls back to the wall clock: a
	// store that silently supplied its own would stamp CreatedAt from real time in a
	// suite that thinks it froze it, and the key-ordering tests would go quietly
	// non-deterministic.
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no client", Config{Clk: clock.System{}}},
		{"no clock", Config{Client: client}},
		{"neither", Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			if err := cfg.validate(); err == nil {
				t.Errorf("validate accepted a Config with %s", tc.name)
			}
			if _, err := NewVaultStore(tc.cfg); err == nil {
				t.Errorf("NewVaultStore accepted a Config with %s", tc.name)
			}
		})
	}
}

// Mount and prefix default; the client and the clock do not. The store takes no
// logger at all — it reads the request-scoped one off the context, which is what
// carries the request_id.
func TestConfigDefaultsTheMountAndPrefix(t *testing.T) {
	t.Parallel()

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	cfg := Config{Client: client, Clk: clock.System{}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a Config with only a client and a clock was rejected: %v", err)
	}
	if cfg.Mount != DefaultMount || cfg.Prefix != DefaultPrefix {
		t.Errorf("validate left mount/prefix as %q/%q, want the defaults %q/%q",
			cfg.Mount, cfg.Prefix, DefaultMount, DefaultPrefix)
	}
}

func thumbprintsOf(keys []Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Ref.Thumbprint)
	}
	return out
}
