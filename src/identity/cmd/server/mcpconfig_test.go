package main

import (
	"strings"
	"testing"
)

// The MCP adapter's start-up rules are documented with their exact error text,
// and a quoted message is a claim like any other. These pin the two halves of it
// so the documentation cannot drift from what the binary emits.

// TestBuildMCPConfig_RequiresTheBroker pins the one required RAMP peer and the
// sentence an operator will find in the logs. The Broker has no default because
// a default would point an agent's signed discovery somewhere nobody chose.
func TestBuildMCPConfig_RequiresTheBroker(t *testing.T) {
	t.Setenv("IDENTITY_MCP_BROKER_URL", "")

	_, err := buildMCPConfig()
	if err == nil {
		t.Fatal("the adapter was configured with no Broker")
	}
	// The exact sentence src/identity/CONFIGURATION.md quotes, under "The MCP
	// endpoint has no off switch".
	if got := err.Error(); got != "IDENTITY_MCP_BROKER_URL is required" {
		t.Errorf("error = %q, want the sentence the documentation quotes", got)
	}
}

// TestBuildMCPConfig_ReadsAWhitespaceBrokerAsUnset is the "one answer per
// deployment" rule, applied to the required variable.
//
// The allowlist eighteen lines below is read through EnvTrimmed, so a value of
// spaces reads as unset there. The Broker URL was read through EnvOr, so the same
// operator mistake passed the required check and the service came up with a
// whitespace Broker URL — one error, two behaviours, and nothing in the
// configuration file to show the difference.
func TestBuildMCPConfig_ReadsAWhitespaceBrokerAsUnset(t *testing.T) {
	t.Setenv("IDENTITY_MCP_BROKER_URL", "   ")

	_, err := buildMCPConfig()
	if err == nil {
		t.Fatal("the adapter came up with a whitespace Broker URL")
	}
	if got := err.Error(); got != "IDENTITY_MCP_BROKER_URL is required" {
		t.Errorf("error = %q, want the same sentence an empty value produces", got)
	}
}

// TestBuildMCPConfig_NeedsNoExchange is the change this ticket makes visible at
// the composition root: a deployment is no longer told where agents' accounts
// live, because an agent names that per call.
//
// Asserted rather than assumed, because the failure it guards against is quiet:
// a re-added required Exchange variable would break every deployment that
// upgraded, and nothing else in the suite would notice.
func TestBuildMCPConfig_NeedsNoExchange(t *testing.T) {
	t.Setenv("IDENTITY_MCP_BROKER_URL", "https://broker.example")

	cfg, err := buildMCPConfig()
	if err != nil {
		t.Fatalf("the adapter refused to configure with no Exchange named: %v", err)
	}
	if cfg.BrokerURL != "https://broker.example" {
		t.Errorf("broker = %q, want the configured origin", cfg.BrokerURL)
	}
	if cfg.ExchangeAllowlist != "" {
		t.Errorf("an unset allowlist read as %q, want the permit-everything policy",
			cfg.ExchangeAllowlist)
	}
}

// TestBuildMCPConfig_ReadsTheExchangePolicy pins that the optional lever is read
// at all. It is parsed later, at Build, so what this covers is the plumbing
// between the environment and that parse.
func TestBuildMCPConfig_ReadsTheExchangePolicy(t *testing.T) {
	t.Setenv("IDENTITY_MCP_BROKER_URL", "https://broker.example")
	t.Setenv("IDENTITY_MCP_EXCHANGE_ALLOWLIST", "  exchange.example,exchange-b.example:8081  ")

	cfg, err := buildMCPConfig()
	if err != nil {
		t.Fatalf("buildMCPConfig: %v", err)
	}
	if !strings.Contains(cfg.ExchangeAllowlist, "exchange-b.example:8081") {
		t.Errorf("allowlist = %q, want the configured list", cfg.ExchangeAllowlist)
	}
	// Trimmed, so a variable holding only whitespace reads as unset rather than
	// being parsed as a policy with one blank entry.
	if strings.HasPrefix(cfg.ExchangeAllowlist, " ") || strings.HasSuffix(cfg.ExchangeAllowlist, " ") {
		t.Errorf("allowlist = %q, want the surrounding whitespace trimmed", cfg.ExchangeAllowlist)
	}
}
