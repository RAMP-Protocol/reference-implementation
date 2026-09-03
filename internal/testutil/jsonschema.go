package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// CompileSchema compiles the JSON Schema at path with the Draft 2020-12
// validator the rest of the repo uses, and fails the test on any error along
// the way. The file's base name becomes the resource name, so a schema that
// references a sibling by file name resolves.
//
// It lives here because the two suites that validate a published schema — the
// catalog-feed parity check and the CoMP conformance corpus — are in different
// packages, and a _test.go helper cannot be imported across a package boundary.
// Each had its own copy of the same five steps, so a change to how schemas are
// compiled had to be made twice.
func CompileSchema(tb testing.TB, path string) *jsonschema.Schema {
	tb.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // the caller supplies a repo-controlled path
	if err != nil {
		tb.Fatalf("read schema %s: %v", path, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("parse schema %s: %v", path, err)
	}
	name := filepath.Base(path)
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		tb.Fatalf("add schema %s: %v", path, err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		tb.Fatalf("compile schema %s: %v", path, err)
	}
	return sch
}
