package comptest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// compileCompSchema loads and compiles the authored CoMP V1 JSON Schema
// (schemas/comp/v1/comp-v1.schema.json) using the same Draft 2020-12 validator
// the rest of the repo uses (santhosh-tekuri/jsonschema/v6).
func compileCompSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const name = "comp-v1.schema.json"
	p := filepath.Join(repoRoot(t), "schemas", "comp", "v1", name)
	raw, err := os.ReadFile(p) //nolint:gosec // schema path is repo-controlled
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// instanceFromFile reads a canonical fixture as a generic JSON instance.
func instanceFromFile(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixture path is test-controlled
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return inst
}

// TestSchemaValidatesAllCanonicalExamples is the schema's self-proof: it MUST
// validate every canonical CoMP V1 document — both the supply-side package and
// the request-side aisystem halves of all eight worked examples.
func TestSchemaValidatesAllCanonicalExamples(t *testing.T) {
	sch := compileCompSchema(t)
	dir := canonicalDir(t)
	for n := 1; n <= 8; n++ {
		for _, side := range []string{"package", "aisystem"} {
			name := fmt.Sprintf("example-%d-%s.json", n, side)
			t.Run(name, func(t *testing.T) {
				inst := instanceFromFile(t, filepath.Join(dir, name))
				if err := sch.Validate(inst); err != nil {
					t.Fatalf("canonical %s rejected by schema: %v", name, err)
				}
			})
		}
	}
}

// TestSchemaRejectsBrokenDocuments is the other half: the schema MUST reject
// documents that violate canonical CoMP V1. Each case breaks exactly one rule.
func TestSchemaRejectsBrokenDocuments(t *testing.T) {
	sch := compileCompSchema(t)
	cases := []struct {
		name string
		doc  string
	}{
		{"foreign key at package root", `{"package":{"id":"X","bogus":1}}`},
		{"missing required package id", `{"package":{"title":"X"}}`},
		{"unitprice wrong type", `{"package":{"id":"X","scope":{"unitprice":"free"}}}`},
		{"ause out of enum", `{"package":{"id":"X","scope":{"ause":99}}}`},
		{"aiauth out of enum", `{"aisystem":{"name":"x","aisysuse":{"lid":"l","aiauth":99}}}`},
		{"missing required aisysuse", `{"aisystem":{"name":"x"}}`},
		{"empty document", `{}`},
		{"foreign key inside scope", `{"package":{"id":"X","scope":{"leaked":true}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(tc.doc)))
			if err != nil {
				t.Fatalf("parse case doc: %v", err)
			}
			if err := sch.Validate(inst); err == nil {
				t.Fatalf("broken doc accepted by schema (want rejection): %s", tc.doc)
			}
		})
	}
}
