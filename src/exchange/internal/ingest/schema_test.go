package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// The published catalog-feed JSON Schema and this package's Go structs are two
// statements of one contract: the schema is what a publisher validates a feed
// against before pushing it, and the parser is what actually accepts the line.
// They are authored by hand and travel together to the public reference
// implementation, so nothing but a test keeps them from drifting apart. When
// they do drift the failure is silent and one-sided — a publisher is refused a
// field the ingester would have taken, or told a field is fine that the
// ingester rejects.
//
// TestFeedSchemaDeclaresEveryParserField below is the check that closes that
// gap for the field set. Value rules (patterns, cross-field conditionals) are
// still authored twice by hand.

// feedSchemaDir resolves the published catalog-feed schema directory relative
// to this package (src/exchange/internal/ingest is four levels below the repo
// root), matching how the other fixtures in this package are located.
func feedSchemaDir() string {
	return filepath.Join("..", "..", "..", "..", "schemas", "catalog-feed", "v1")
}

// compileFeedSchema compiles the published catalog-feed schema.
func compileFeedSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return testutil.CompileSchema(t, filepath.Join(feedSchemaDir(), "catalog-feed-v1.schema.json"))
}

// readExampleFeed returns the non-empty lines of the published example feed.
func readExampleFeed(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(feedSchemaDir(), "example.jsonl"))
	if err != nil {
		t.Fatalf("read example feed: %v", err)
	}
	var out []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatal("example feed is empty")
	}
	return out
}

// ingestLine drives one feed line through the whole ingester: the parser
// decodes it and the mapper validates its values. Both halves are needed to
// compare against the schema — the parser performs no value validation, so
// ParseJSONL alone accepts tokens the ingester as a whole refuses.
func ingestLine(line string) error {
	records, err := ParseJSONL(strings.NewReader(line))
	if err != nil {
		return err
	}
	for _, rec := range records {
		if _, err := mapRecord(rec); err != nil {
			return err
		}
	}
	return nil
}

// TestFeedSchemaAcceptsExampleFeed is the schema's self-proof, and the
// ingester's: every line of the published example feed must both validate
// against the schema and survive parse plus mapping. A line that only one of
// the two accepts is exactly the drift this file exists to catch.
func TestFeedSchemaAcceptsExampleFeed(t *testing.T) {
	sch := compileFeedSchema(t)
	lines := readExampleFeed(t)
	for i, line := range lines {
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatalf("line %d is not JSON: %v", i+1, err)
		}
		if err := sch.Validate(inst); err != nil {
			t.Errorf("line %d rejected by the schema: %v", i+1, err)
		}
	}
	records, err := ParseJSONL(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("example feed rejected by the parser: %v", err)
	}
	if len(records) != len(lines) {
		t.Errorf("parsed %d records from %d lines", len(records), len(lines))
	}
	for i, rec := range records {
		if _, err := mapRecord(rec); err != nil {
			t.Errorf("line %d rejected by the mapper: %v", i+1, err)
		}
	}
}

// TestFeedSchemaCarriesTheMeteringExample keeps the example feed exercising the
// one metering value with a behavioural consequence. A term priced with
// metering "none" is a one-time perpetual sale: the Exchange mints no reporting
// obligation for it. Without a line carrying the token, the schema's metering
// rule and the mapper's metering switch are both unexercised by the example a
// publisher is told to validate their own feed against first.
func TestFeedSchemaCarriesTheMeteringExample(t *testing.T) {
	records, err := ParseJSONL(strings.NewReader(strings.Join(readExampleFeed(t), "\n")))
	if err != nil {
		t.Fatalf("parse example feed: %v", err)
	}
	for _, rec := range records {
		for _, term := range rec.Terms {
			if term.Pricing != nil && strings.EqualFold(term.Pricing.Metering, "none") {
				return
			}
		}
	}
	t.Error(`no example line carries pricing.metering "none"`)
}

// schemaObject is the part of a JSON Schema object this test reads: the field
// set it declares and whether it is closed to anything else.
type schemaObject struct {
	Properties           map[string]json.RawMessage `json:"properties"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
}

// feedSchemaObjects returns the root object plus the named $defs entries,
// decoded far enough to compare field sets.
func feedSchemaObjects(t *testing.T) (root schemaObject, defs map[string]schemaObject) {
	t.Helper()
	const name = "catalog-feed-v1.schema.json"
	raw, err := os.ReadFile(filepath.Join(feedSchemaDir(), name))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc struct {
		schemaObject
		Defs map[string]schemaObject `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	return doc.schemaObject, doc.Defs
}

// jsonFieldNames returns the JSON object keys a Go struct encodes to, in
// declaration order. Fields tagged "-" are skipped; an untagged exported field
// would encode under its Go name, which the schema does not model, so it is
// reported as-is and will fail the comparison rather than pass silently.
func jsonFieldNames(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		out = append(out, tag)
	}
	return out
}

// TestFeedSchemaDeclaresEveryParserField holds the two statements of the feed
// line format together, in both directions. Every field the Go parser decodes
// must be a property the published schema allows, or a publisher who validates
// a feed before pushing it is refused a field the ingester would have taken.
// Every property the schema allows must be a field the parser decodes, or the
// schema promises a field that is silently dropped on ingest. Every object is
// also checked to be closed, because an open object makes the first direction
// vacuous.
func TestFeedSchemaDeclaresEveryParserField(t *testing.T) {
	root, defs := feedSchemaObjects(t)
	cases := []struct {
		def string // "" is the root object, one feed line
		typ reflect.Type
	}{
		{"", reflect.TypeFor[Record]()},
		{"Attestation", reflect.TypeFor[Attestation]()},
		{"License", reflect.TypeFor[License]()},
		{"Term", reflect.TypeFor[Term]()},
		{"Pricing", reflect.TypeFor[Pricing]()},
		{"Quota", reflect.TypeFor[Quota]()},
		{"Obligation", reflect.TypeFor[Obligation]()},
	}
	for _, tc := range cases {
		name := tc.def
		if name == "" {
			name = "(root)"
		}
		t.Run(name, func(t *testing.T) {
			obj := root
			if tc.def != "" {
				var ok bool
				if obj, ok = defs[tc.def]; !ok {
					t.Fatalf("schema declares no $defs.%s for Go type %s", tc.def, tc.typ)
				}
			}
			if obj.AdditionalProperties == nil || *obj.AdditionalProperties {
				t.Errorf("%s is not closed; additionalProperties must be false "+
					"or the field-set comparison below proves nothing", name)
			}
			assertSameFieldSet(t, name, tc.typ, obj)
		})
	}
}

// assertSameFieldSet reports each field the Go struct decodes that the schema
// does not declare, and each property the schema declares that the struct does
// not decode.
func assertSameFieldSet(t *testing.T, name string, typ reflect.Type, obj schemaObject) {
	t.Helper()
	for _, field := range jsonFieldNames(typ) {
		if _, ok := obj.Properties[field]; !ok {
			t.Errorf("%s decodes %q but the schema does not declare it: a publisher "+
				"validating a feed against the published schema is refused a field "+
				"the ingester accepts", typ, field)
		}
	}
	inGo := make(map[string]bool, typ.NumField())
	for _, field := range jsonFieldNames(typ) {
		inGo[field] = true
	}
	for prop := range obj.Properties {
		if !inGo[prop] {
			t.Errorf("the schema declares %s.%q but %s does not decode it: the schema "+
				"promises a field the ingester silently drops", name, prop, typ)
		}
	}
}

// TestFeedSchemaRejectsBadPricing is the negative half. Each case breaks
// exactly one rule this branch's metering work depends on, and each must be
// refused by the schema for the same reason the parser refuses it.
func TestFeedSchemaRejectsBadPricing(t *testing.T) {
	sch := compileFeedSchema(t)
	const prefix = `{"domain":"publisher.example","path":"/p","terms":[{"semantics":"enumerated","pricing":`
	cases := []struct {
		name    string
		pricing string
	}{
		{
			"unknown metering token",
			`{"model":"flat","rate":"1.00","metering":"sometimes"}`,
		},
		{
			"metering token with a typo the parser would also refuse",
			`{"model":"flat","rate":"1.00","metering":"offline"}`,
		},
		{
			"unknown pricing property",
			`{"model":"flat","rate":"1.00","billing_mode":"prepaid"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := prefix + tc.pricing + `}]}`
			inst, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
			if err != nil {
				t.Fatalf("case is not JSON: %v", err)
			}
			if err := sch.Validate(inst); err == nil {
				t.Errorf("schema accepted %s", tc.pricing)
			}
			if err := ingestLine(line); err == nil {
				t.Errorf("the ingester accepted %s", tc.pricing)
			}
		})
	}
}

// TestFeedSchemaAcceptsEveryMeteringSpelling pins the accepted set on both
// sides. The schema matches case-insensitively because the mapper lowercases
// and trims before matching; a lowercase-only rule would refuse a value the
// ingester goes on to accept.
func TestFeedSchemaAcceptsEveryMeteringSpelling(t *testing.T) {
	sch := compileFeedSchema(t)
	const prefix = `{"domain":"publisher.example","path":"/p","terms":[{"semantics":"enumerated","pricing":`
	for _, token := range []string{"online", "offline_self_reported", "none", "NONE", "Online", ""} {
		t.Run("metering="+token, func(t *testing.T) {
			line := prefix + `{"model":"flat","rate":"1.00","metering":"` + token + `"}}]}`
			inst, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
			if err != nil {
				t.Fatalf("case is not JSON: %v", err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Errorf("schema rejected metering %q: %v", token, err)
			}
			if err := ingestLine(line); err != nil {
				t.Errorf("the ingester rejected metering %q: %v", token, err)
			}
		})
	}
}
