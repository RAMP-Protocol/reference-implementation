package directory_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// wbaDoc is the parsed shape of a built directory, enough to assert the RAMP
// extension members and key order the JWK Set carries.
type wbaDoc struct {
	Keys          []map[string]any `json:"keys"`
	RevocationURL string           `json:"revocation_url"`
}

func mustKey(t *testing.T, nb, na time.Time) keystore.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return keystore.Key{Public: pub, Window: keystore.Window{NotBefore: nb, NotAfter: na}}
}

func TestBuildWBA_SchemaValid(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, err := directory.BuildWBA([]keystore.Key{mustKey(t, nb, nb.AddDate(1, 0, 0))}, "")
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	// BuildWBA validates internally; re-run the shared guard to prove the bytes
	// satisfy the published ramp-wba-directory.json schema.
	if err := rampwellknown.ValidateWBA(raw); err != nil {
		t.Fatalf("ValidateWBA: %v", err)
	}
}

func TestBuildWBA_GoJoseInterop(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := mustKey(t, nb, nb.AddDate(1, 0, 0))
	raw, err := directory.BuildWBA([]keystore.Key{key}, "")
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("go-jose parse: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	got, ok := set.Keys[0].Key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("key type = %T, want ed25519.PublicKey", set.Keys[0].Key)
	}
	if !got.Equal(key.Public) {
		t.Fatal("parsed public key does not match input")
	}
}

func TestBuildWBA_PreservesListOrderAndWindows(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.AddDate(1, 0, 0)
	keys := []keystore.Key{mustKey(t, nb, na), mustKey(t, nb, na)}
	raw, err := directory.BuildWBA(keys, "")
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	var doc wbaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(doc.Keys))
	}
	for i, k := range keys {
		wantX := rampwellknown.EncodeEd25519X(k.Public)
		if got := doc.Keys[i]["x"]; got != wantX {
			t.Errorf("key[%d].x = %v, want %v (order not preserved)", i, got, wantX)
		}
		if got := doc.Keys[i]["not_before"]; got != nb.Format(time.RFC3339) {
			t.Errorf("key[%d].not_before = %v, want %v", i, got, nb.Format(time.RFC3339))
		}
		if got := doc.Keys[i]["not_after"]; got != na.Format(time.RFC3339) {
			t.Errorf("key[%d].not_after = %v, want %v", i, got, na.Format(time.RFC3339))
		}
	}
}

func TestBuildWBA_DedupByX(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	k := mustKey(t, nb, nb.AddDate(1, 0, 0))
	raw, err := directory.BuildWBA([]keystore.Key{k, k}, "")
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	var doc wbaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d, want 1 (duplicate x not deduped)", len(doc.Keys))
	}
}

func TestBuildWBA_RevocationURLIncludedWhenSet(t *testing.T) {
	t.Parallel()
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, err := directory.BuildWBA([]keystore.Key{mustKey(t, nb, nb.AddDate(1, 0, 0))}, "https://x.rampmcp.org/rev")
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	var doc wbaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.RevocationURL != "https://x.rampmcp.org/rev" {
		t.Fatalf("revocation_url = %q, want the set value", doc.RevocationURL)
	}
}

func TestBuildWBA_EmptyRejected(t *testing.T) {
	t.Parallel()
	if _, err := directory.BuildWBA(nil, ""); err == nil {
		t.Fatal("BuildWBA(nil) = nil error, want a build error")
	}
}
