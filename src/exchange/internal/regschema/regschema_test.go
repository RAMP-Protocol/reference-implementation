// Unit tests for the registration-schema loader. A loader is a parser, which
// the testing doctrine admits as a unit; what it produces is exercised end to
// end through the served manifest in src/exchange/internal/wellknown and
// through the composition root in src/exchange/cmd/server.
//
// What these tests own is the part those cannot see: WHICH refusal a bad schema
// gets, and where the line falls between "no schema configured" and "a schema I
// refuse". That line is the enforcement switch — read one way it turns checking
// off, read the other it stops the boot — so it is worth pinning directly
// rather than inferring from a manifest that came out empty.
package regschema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
)

// TestLoadAcceptedYieldsBothForms pins the property the single-source rule
// rests on: one compile produces the document the manifest publishes AND the
// validator the Register gate will check payloads with. A loader that returned
// only one would force the other reader to compile again, from bytes that have
// been through a round trip.
func TestLoadAcceptedYieldsBothForms(t *testing.T) {
	t.Parallel()
	s, err := regschema.Load(testutil.RegistrationSchemaJSON)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Document() == nil {
		t.Error("Document is nil for an accepted schema — nothing would be published")
	}
	if s.Validator() == nil {
		t.Error("Validator is nil for an accepted schema — the Register gate would have to compile it again")
	}
	if got := s.Document().GetFields()["type"].GetStringValue(); got != "object" {
		t.Errorf(`Document's "type" member = %q, want "object"`, got)
	}
}

// TestLoadTreatsBlankAsNoSchema pins the enforcement switch's off position.
// Reading a value as blank turns checking off, so the exact set of bytes that
// count is load-bearing rather than pedantic — and it is the SDK's answer, not
// this package's, because an agent reading the same manifest asks the same
// question in another language.
func TestLoadTreatsBlankAsNoSchema(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"empty":           "",
		"one space":       " ",
		"tab":             "\t",
		"newline":         "\n",
		"carriage return": "\r",
		"mixed run":       " \t\r\n ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, err := regschema.Load(raw)
			if err != nil {
				t.Fatalf("Load(%q): %v", raw, err)
			}
			if s != nil {
				t.Fatalf("Load(%q) returned a schema, want nil (no schema configured)", raw)
			}
		})
	}
}

// TestLoadRefusalNamesTheVerdict drives each way a configured schema can be
// unusable and asserts the error says WHICH — an operator who has to work out
// whether their schema was too big, aimed at another host, or written to an
// older draft is being handed the wrong error.
func TestLoadRefusalNamesTheVerdict(t *testing.T) {
	t.Parallel()
	for _, tc := range testutil.UnusableSchemas {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			s, err := regschema.Load(tc.Raw)
			if err == nil {
				t.Fatalf("Load accepted a schema that is %s", tc.Name)
			}
			if s != nil {
				t.Error("Load returned a schema alongside an error — a refused schema must publish nothing")
			}
			if !strings.Contains(err.Error(), tc.Verdict) {
				t.Errorf("error = %q, want it to name the verdict %q", err, tc.Verdict)
			}
		})
	}
}

// TestNilSchemaIsThePassThroughState pins both nil-receiver paths. A nil
// *Schema is the ordinary "operator configured nothing" state, not a mistake,
// so neither reader should have to check before asking.
func TestNilSchemaIsThePassThroughState(t *testing.T) {
	t.Parallel()
	var s *regschema.Schema
	if s.Document() != nil {
		t.Error("Document on a nil schema is non-nil — the manifest would publish a block")
	}
	if s.Validator() != nil {
		t.Error("Validator on a nil schema is non-nil — the gate would check against an empty rule set")
	}
}

// TestZeroValueSchemaPublishesNothing pins what the unexported field buys. Only
// Load can build a usable Schema, so a value constructed outside this package
// carries neither form and cannot smuggle an unchecked document into the
// manifest.
func TestZeroValueSchemaPublishesNothing(t *testing.T) {
	t.Parallel()
	s := &regschema.Schema{}
	if s.Document() != nil {
		t.Error("a zero-value Schema yields a document — an unchecked schema could reach the manifest")
	}
	if s.Validator() != nil {
		t.Error("a zero-value Schema yields a validator")
	}
}

// TestValidatorMatchesThePublishedDocumentPastFloat64Precision drives the one
// way the two forms can disagree. The published document is a structpb.Struct,
// which carries every JSON number as a float64, so an integer literal needing
// more than 53 bits of mantissa is rounded on the way to the wire —
// 9007199254740993 is served as 9007199254740992. An agent pre-checks its
// payload against the document it read, so a validator compiled from the
// operator's original text would refuse a payload the published document
// accepts, and the agent has no way to see why.
func TestValidatorMatchesThePublishedDocumentPastFloat64Precision(t *testing.T) {
	t.Parallel()
	// 9007199254740993 is 2^53 + 1, the first integer a float64 cannot hold.
	raw := `{"type":"object","properties":{"n":{"const":9007199254740993}}}`

	s, err := regschema.Load(raw)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	served, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(s.Document())
	if err != nil {
		t.Fatalf("marshal the published document: %v", err)
	}
	var doc struct {
		Properties struct {
			N struct {
				Const json.Number `json:"const"`
			} `json:"n"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(served, &doc); err != nil {
		t.Fatalf("parse the published document: %v", err)
	}
	published, err := doc.Properties.N.Const.Float64()
	if err != nil {
		t.Fatalf("published const %q is not a number: %v", doc.Properties.N.Const, err)
	}
	// The payload an agent builds from the document it actually read. Whatever
	// number the wire names is the number the validator must accept, whether or
	// not this protobuf release happens to round it.
	if errs := s.Validator().Validate(map[string]any{"n": published}); len(errs) != 0 {
		t.Errorf("the validator refuses %v, which is the value the published document names as const — "+
			"the schema an agent reads and the schema this Exchange enforces are different documents (%v)",
			published, errs)
	}
}

// TestEmptyObjectIsAPublishedSchema pins the case an operator reaches by
// accident: a template that rendered to "{}". An empty JSON object is a valid
// schema that accepts every payload, so it publishes the account_registration
// block and tells agents this Exchange has requirements while requiring
// nothing. It is deliberately NOT read as "no schema configured" — that
// position belongs to blank input alone, and widening it here would silently
// turn enforcement off for an operator whose template broke.
func TestEmptyObjectIsAPublishedSchema(t *testing.T) {
	t.Parallel()
	s, err := regschema.Load("{}")
	if err != nil {
		t.Fatalf("Load(\"{}\"): %v", err)
	}
	if s == nil {
		t.Fatal(`Load("{}") returned no schema — an empty object is a published schema that requires nothing, not an absent one`)
	}
	if s.Document() == nil {
		t.Error(`Load("{}") publishes no document — the account_registration block would be absent`)
	}
	if n := len(s.Document().GetFields()); n != 0 {
		t.Errorf("published document has %d members, want 0", n)
	}
	if s.Validator() == nil {
		t.Error(`Load("{}") yields no validator — the Register gate would have nothing to check against`)
	}
}

// TestDocumentIsACopy pins that a holder cannot change what the manifest
// publishes. The handler keeps the returned Struct for the life of the process
// and re-marshals it on every rebuild, so a write through a shared pointer
// would change the published document while leaving the compiled validator
// alone — the exact divergence this package exists to prevent, arriving without
// a second call to Load for a guard to catch.
func TestDocumentIsACopy(t *testing.T) {
	t.Parallel()
	s, err := regschema.Load(testutil.RegistrationSchemaJSON)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	first := s.Document()
	first.GetFields()["type"] = structpb.NewStringValue("array")
	delete(first.GetFields(), "required")

	second := s.Document()
	if got := second.GetFields()["type"].GetStringValue(); got != "object" {
		t.Errorf(`after a write through the returned document, Document's "type" = %q, want "object"`, got)
	}
	if _, ok := second.GetFields()["required"]; !ok {
		t.Error("after a delete through the returned document, Document is missing \"required\"")
	}
}

// TestSizeCapIsMeasuredOnTheServedBytes drives the boundary the two byte forms
// disagree on. The protocol's cap is defined over the bytes served in
// ramp.json, and an indented schema is larger as the operator wrote it than as
// this Exchange publishes it. Measuring the operator's text instead would stop
// the boot on a document every conformant agent reading the manifest accepts,
// and the operator could not reproduce the measurement from anything on the
// wire.
func TestSizeCapIsMeasuredOnTheServedBytes(t *testing.T) {
	t.Parallel()
	// Whitespace between the members is the only thing over the cap here: the
	// document is three members long once protojson has re-encoded it.
	raw := `{"$schema":"https://json-schema.org/draft/2020-12/schema",` +
		strings.Repeat(" ", 17<<10) + `"type":"object"}`
	if len(raw) <= 16384 {
		t.Fatalf("the fixture is %d bytes, which is under the cap — it proves nothing", len(raw))
	}

	s, err := regschema.Load(raw)
	if err != nil {
		t.Fatalf("Load refused a schema whose served form is well under the cap: %v", err)
	}
	if s == nil {
		t.Fatal("Load returned no schema for a document it accepted")
	}

	served, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(s.Document())
	if err != nil {
		t.Fatalf("marshal the published document: %v", err)
	}
	if len(served) > 16384 {
		t.Fatalf("the served form is %d bytes, over the cap — the fixture does not separate the two measurements", len(served))
	}
}

// TestOversizeAsServedIsStillRefused pins the other side of the same line. The
// cap moving to the served bytes must not become no cap at all: a document that
// is still over the limit after re-encoding is one an agent would refuse to
// read, so this Exchange must not advertise it. The refusal comes from the
// second compile, which is the only rule that pass decides.
func TestOversizeAsServedIsStillRefused(t *testing.T) {
	t.Parallel()
	// Real content rather than padding, so the size survives re-encoding.
	raw := `{"type":"object","title":"` + strings.Repeat("x", 17<<10) + `"}`

	s, err := regschema.Load(raw)
	if err == nil {
		t.Fatal("Load accepted a schema that is over the cap as served")
	}
	if s != nil {
		t.Error("Load returned a schema alongside an error — a refused schema must publish nothing")
	}
	if !strings.Contains(err.Error(), "too_large") {
		t.Errorf("error = %q, want it to name the too_large verdict", err)
	}
}
