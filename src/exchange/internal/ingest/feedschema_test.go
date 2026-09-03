package ingest_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// The published catalog-feed JSON Schema is a derived view of the wire contract:
// a publisher validates a feed against it before pushing, and the fields it
// describes map one-for-one onto ResourceEntry — mapRecord copies domain and
// path verbatim, so a rule protovalidate applies to the entry applies to the
// line that produced it.
//
// Nothing read that schema until this file. It drifted for exactly that reason:
// the pinned protocol module grew envelope rules on ResourceEntry — a host
// pattern and length cap on domain, a leading-slash pattern and length cap on
// path, caps on the optional scalars, non-negative counts, list caps — and the
// schema kept describing the shape from before them, so it told publishers a
// line was well-formed that the Exchange refuses at the RPC boundary.
//
// The test is two halves and needs both. The committed examples must validate,
// or the schema has been tightened past the feeds this repo ships. And the
// envelope violations must be refused by the schema AND by the SDK's own entry
// validation, asserted over one corpus, because a schema that refuses a line
// the Exchange accepts is as wrong as one that accepts a line the Exchange
// refuses — the point of the artifact is that its verdict is the Exchange's.
const (
	feedSchemaPath  = "../../../../schemas/catalog-feed/v1/catalog-feed-v1.schema.json"
	feedExamplePath = "../../../../schemas/catalog-feed/v1/example.jsonl"
	feedSamplePath  = "../../../../deploy/fixtures/publisher/sample.jsonl"
)

// compileFeedSchema compiles the published schema through the repo's shared
// schema helper, which registers the resource under the file's base name: the
// schema declares an absolute $id but every $ref inside it is local, so nothing
// has to resolve over the network.
func compileFeedSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return testutil.CompileSchema(t, filepath.Clean(feedSchemaPath))
}

// feedLines returns the non-blank lines of a JSON-L feed, failing when there
// are none: a replay over an empty file passes vacuously, and a truncated
// fixture would otherwise read as a clean run.
func feedLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20) // the format's own 16 MiB line bound
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(lines) == 0 {
		t.Fatalf("%s holds no feed lines — a replay over nothing passes vacuously", path)
	}
	return lines
}

// instanceOf decodes one feed line into the shape the validator takes.
func instanceOf(t *testing.T, line string) any {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
	if err != nil {
		t.Fatalf("parse feed line: %v", err)
	}
	return inst
}

// TestFeedSchema_AcceptsTheCommittedFeeds is the half that keeps the schema
// honest in the accepting direction. Both files are feeds this repo pushes, so
// a constraint that refuses one of them is a constraint the Exchange does not
// have.
func TestFeedSchema_AcceptsTheCommittedFeeds(t *testing.T) {
	t.Parallel()
	sch := compileFeedSchema(t)
	for _, path := range []string{feedExamplePath, feedSamplePath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			for i, line := range feedLines(t, path) {
				if err := sch.Validate(instanceOf(t, line)); err != nil {
					t.Errorf("line %d of %s is refused by the published schema: %v", i+1, path, err)
				}
			}
		})
	}
}

// envelopeViolations are lines that break one ResourceEntry envelope rule each
// — the rules the pinned protocol module authors and the schema had not been
// carrying. Every one must be refused twice: by the schema, which is what a
// publisher validates against, and by the SDK's entry validation, which is what
// the Exchange runs. Asserting both over one corpus is what stops the two
// drifting apart again.
//
// Every bound the schema carries has a case: both patterns, every maxLength,
// both maxItems, both minimums. The two minLength rules on domain and path are
// the exception, and deliberately: no string short enough to break one gets
// past the pattern beside it, so a case for them would exercise the pattern
// cases already here rather than the bound it claimed to cover.
//
// What this cannot catch is a bound the wire TIGHTENS. A line built to break
// the old bound breaks the tighter one too, so both sides still refuse it and
// nothing goes red. Only a derivation that read the rules off the descriptor
// would close that, and none exists.
var envelopeViolations = []struct {
	name string
	line string
}{
	{
		"path without a leading slash",
		`{"domain":"publisher.example","path":"article-without-slash","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"path carrying a query delimiter",
		`{"domain":"publisher.example","path":"/article?utm=x","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"path carrying a space",
		`{"domain":"publisher.example","path":"/article one","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"domain carrying a scheme",
		`{"domain":"https://publisher.example","path":"/a","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"domain carrying userinfo",
		`{"domain":"publisher.example@evil.example","path":"/a","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"domain carrying a path",
		`{"domain":"publisher.example/evil","path":"/a","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"negative word_count",
		`{"domain":"publisher.example","path":"/a","word_count":-1,"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"negative estimated_quantity",
		`{"domain":"publisher.example","path":"/a","estimated_quantity":-1,"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"title past its length cap",
		`{"domain":"publisher.example","path":"/a","title":"` + strings.Repeat("t", 513) +
			`","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"content_id past its length cap",
		`{"domain":"publisher.example","path":"/a","content_id":"` + strings.Repeat("c", 256) +
			`","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"hash_method past its length cap",
		`{"domain":"publisher.example","path":"/a","hash_method":"` + strings.Repeat("h", 65) +
			`","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"content_hash past its length cap",
		`{"domain":"publisher.example","path":"/a","content_hash":"` + strings.Repeat("c", 256) +
			`","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"provenance_source past its length cap",
		`{"domain":"publisher.example","path":"/a","provenance_source":"` + strings.Repeat("p", 261) +
			`","terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"domain past its length cap",
		`{"domain":"` + strings.Repeat("d", 253) + `.example","path":"/a",` +
			`"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"path past its length cap",
		`{"domain":"publisher.example","path":"/` + strings.Repeat("p", 2048) + `",` +
			`"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}`,
	},
	{
		"more terms than the list cap",
		`{"domain":"publisher.example","path":"/a","terms":[` +
			strings.TrimSuffix(strings.Repeat(
				`{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}},`, 33), ",") + `]}`,
	},
	{
		"more attestations than the list cap",
		`{"domain":"publisher.example","path":"/a",` +
			`"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}],` +
			`"attestations":[` + strings.TrimSuffix(strings.Repeat(`{"verifier":"v.example"},`, 65), ",") + `]}`,
	},
}

// TestFeedSchema_RefusesTheEnvelopeViolationsTheWireRefuses is the half that
// caught the drift. Each line breaks one envelope rule; the schema must refuse
// it, and so must the SDK's own entry validation, which is the verdict the
// Exchange reaches. A constraint dropped from the schema shows up here as a
// line the SDK refuses and the schema admits.
//
// Every case must reach the SDK leg, and a case that stops reaching it fails
// rather than passing quietly. ingest.Check returns an error only when the feed
// does not parse or does not map — a refusal too, but one that happens BEFORE
// the validation this test is about, so a case taking that exit would leave the
// SDK half of the comparison unasserted while the subtest still went green. All
// seventeen reach the SDK today; nothing pinned that until this line. A case
// that genuinely belongs on the mapper's path needs its own column here, not a
// silent return.
func TestFeedSchema_RefusesTheEnvelopeViolationsTheWireRefuses(t *testing.T) {
	t.Parallel()
	sch := compileFeedSchema(t)
	for _, tc := range envelopeViolations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := sch.Validate(instanceOf(t, tc.line)); err == nil {
				t.Errorf("the published schema accepts a line the wire refuses")
			}
			report, err := ingest.Check(strings.NewReader(tc.line + "\n"))
			if err != nil {
				t.Fatalf("the case no longer reaches the SDK's entry validation — "+
					"the parser or the mapper refused it first: %v", err)
			}
			if report.Violations() == 0 {
				t.Errorf("--check reports no violation for a line the schema refuses: %+v", report.Findings)
			}
		})
	}
}
