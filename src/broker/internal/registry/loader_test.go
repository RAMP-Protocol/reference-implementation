package registry_test

import (
	"bytes"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
)

func TestLoadFromReader_ParsesEntries(t *testing.T) {
	data := []byte(`
exchanges:
  - id: mp-a
    domain: a.example
    endpoint: https://a.example
    trust_level: VERIFIED
    priority: 10
    supported_profiles: [p1, p2]
`)
	got, err := registry.LoadFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].ID != "mp-a" || got[0].TrustLevel != "VERIFIED" {
		t.Errorf("got %+v", got[0])
	}
	if len(got[0].SupportedProfiles) != 2 {
		t.Errorf("profiles = %v", got[0].SupportedProfiles)
	}
}

func TestLoadFromReader_DefaultsTrust(t *testing.T) {
	data := []byte(`
exchanges:
  - id: mp-a
    domain: a.example
    endpoint: https://a.example
`)
	got, err := registry.LoadFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("LoadFromReader: %v", err)
	}
	if got[0].TrustLevel != "DISCOVERED" {
		t.Errorf("trust = %q", got[0].TrustLevel)
	}
}

func TestLoadFromReader_RejectsMissingFields(t *testing.T) {
	data := []byte(`
exchanges:
  - id: ""
    domain: a.example
    endpoint: https://a.example
`)
	if _, err := registry.LoadFromReader(bytes.NewReader(data)); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestDefaultBootstrap_Parses(t *testing.T) {
	got, err := registry.LoadFromReader(bytes.NewReader(registry.DefaultBootstrap))
	if err != nil {
		t.Fatalf("parse default bootstrap: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one bootstrap entry")
	}
}
