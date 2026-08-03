package comptest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

// repoRoot resolves the repository root (the dir holding go.mod) by anchoring on
// this source file (runtime.Caller) and walking up. Anchoring on the source —
// not the cwd — keeps the helpers robust to which package's test is running when
// a render slice consumes the oracle.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(self)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root (go.mod) not found above " + self)
		}
		dir = parent
	}
}

// canonicalDir resolves deploy/fixtures/comp/canonical (the vendored examples).
func canonicalDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "fixtures", "comp", "canonical")
}

// structFromMap builds a *structpb.Struct from a decoded JSON object, mirroring
// how a render slice hands its emitted ext.comp Package to Validate.
func structFromMap(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return s
}

// loadExample reads and decodes one vendored canonical package fixture.
func loadExample(t *testing.T, n int) map[string]any {
	t.Helper()
	p := filepath.Join(canonicalDir(t), fmt.Sprintf("example-%d-package.json", n))
	raw, err := os.ReadFile(p) //nolint:gosec // fixture path is test-controlled
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", p, err)
	}
	return m
}

// TestOracleAcceptsCanonicalExamples proves the oracle is correct: every one of
// the eight vendored canonical CoMP V1 package examples MUST validate. A render
// slice can only trust "a real CoMP parser would accept my output" if the oracle
// first accepts the canonical truth.
func TestOracleAcceptsCanonicalExamples(t *testing.T) {
	for n := 1; n <= 8; n++ {
		t.Run(fmt.Sprintf("example-%d", n), func(t *testing.T) {
			pkg := structFromMap(t, loadExample(t, n))
			if err := Validate(pkg); err != nil {
				t.Fatalf("canonical example %d rejected by oracle: %v", n, err)
			}
		})
	}
}

// TestOracleAcceptsBarePackage confirms Validate accepts the bare-package shape
// RAMP emits under ext.comp (no {"package": …} wrapper) as well as the wrapped
// shape the canonical examples use.
func TestOracleAcceptsBarePackage(t *testing.T) {
	wrapped := loadExample(t, 2)
	inner, ok := wrapped["package"].(map[string]any)
	if !ok {
		t.Fatal("example 2 has no package object")
	}
	if err := Validate(structFromMap(t, inner)); err != nil {
		t.Fatalf("bare package rejected: %v", err)
	}
}

// TestOracleRejectsBrokenDocuments is the other half of a correct oracle: it
// MUST reject documents that violate the canonical shape. Each case mutates a
// known-good example so exactly one property breaks.
func TestOracleRejectsBrokenDocuments(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(pkg map[string]any)
	}{
		{"id wrong type (int not string)", func(p map[string]any) { p["id"] = float64(7) }},
		{"missing required id", func(p map[string]any) { delete(p, "id") }},
		{"foreign key at package root", func(p map[string]any) { p["bogus"] = "x" }},
		{"foreign key inside scope", func(p map[string]any) {
			p["scope"] = map[string]any{"unitprice": 0.05, "leaked": true}
		}},
		{"unitprice wrong type (string not number)", func(p map[string]any) {
			p["scope"] = map[string]any{"unitprice": "free"}
		}},
		{"country element wrong type (string not int)", func(p map[string]any) {
			p["scope"] = map[string]any{"country": []any{"DE"}}
		}},
		{"scope is not an object", func(p map[string]any) { p["scope"] = "premium" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := map[string]any{"id": "PKG-OK", "title": "ok"}
			tc.mutate(pkg)
			if err := Validate(structFromMap(t, pkg)); err == nil {
				t.Fatalf("broken doc accepted by oracle (want rejection): %v", pkg)
			}
		})
	}
}

// TestOracleAllowsRampExtrasUnderExt confirms the merge convention: RAMP extras
// carried under a nested ext object are permitted (ext is opaque), while the
// same keys at a canonical CoMP path would be foreign.
func TestOracleAllowsRampExtrasUnderExt(t *testing.T) {
	pkg := map[string]any{
		"id":  "PKG-OK",
		"ext": map[string]any{"ramp_term_index": float64(0), "unit": "tokens"},
		"scope": map[string]any{
			"unitprice": 0.05,
			"ext":       map[string]any{"model": "PER_UNIT", "metering": "tokens"},
		},
	}
	if err := Validate(structFromMap(t, pkg)); err != nil {
		t.Fatalf("RAMP extras under ext rejected: %v", err)
	}
}
