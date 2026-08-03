package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixturePath resolves the committed reference JSON-L fixture relative to this
// package directory (src/exchange/internal/ingest -> repo root is four
// levels up, then deploy/fixtures/publisher/sample.jsonl).
func fixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "publisher", "sample.jsonl")
}

// parseFixture opens and parses the committed reference feed, asserting it
// yields the expected three records. Split out of the golden test so each
// record's assertions live in their own bounded helper (keeps per-function
// cyclomatic complexity under the lint budget).
func parseFixture(t *testing.T) []Record {
	t.Helper()
	f, err := os.Open(fixturePath(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	records, err := ParseJSONL(f)
	if err != nil {
		t.Fatalf("ParseJSONL returned error: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	return records
}

// TestParseFixtureGolden is the golden parse: each of the three committed lines
// must deserialize into a fully populated Record with no map[string]any.
func TestParseFixtureGolden(t *testing.T) {
	records := parseFixture(t)
	t.Run("record0_two_terms", func(t *testing.T) { assertFixtureRecord0(t, records[0]) })
	t.Run("record1_flat_attribution", func(t *testing.T) { assertFixtureRecord1(t, records[1]) })
	t.Run("record2_reference_only", func(t *testing.T) { assertFixtureRecord2(t, records[2]) })
}

// assertFixtureRecord0 checks record 1: two terms — academic FREE + commercial
// PER_UNIT(accesses).
func assertFixtureRecord0(t *testing.T, r0 Record) {
	t.Helper()
	assertRecord0Header(t, r0)
	if len(r0.Terms) != 2 {
		t.Fatalf("record 0 expected 2 terms, got %d", len(r0.Terms))
	}
	assertRecord0Term0(t, r0.Terms[0])
	assertRecord0Term1(t, r0.Terms[1])
}

// assertRecord0Header checks record 0's domain/path/title/license envelope.
func assertRecord0Header(t *testing.T, r0 Record) {
	t.Helper()
	if r0.Domain != "publisher.example" {
		t.Errorf("record 0 domain = %q, want publisher.example", r0.Domain)
	}
	if r0.Path != "/article/how-photosynthesis-works" {
		t.Errorf("record 0 path = %q", r0.Path)
	}
	if r0.Title != "How Photosynthesis Works" {
		t.Errorf("record 0 title = %q", r0.Title)
	}
	if r0.License == nil {
		t.Fatal("record 0 license is nil")
	}
	if r0.License.ID != "pub-ai-2026" || r0.License.URI != "https://publisher.example/licensing/ai" || r0.License.Name != "Publisher AI License" {
		t.Errorf("record 0 license = %+v", r0.License)
	}
}

// assertRecord0Term0 checks the academic FREE term (term 0.0).
func assertRecord0Term0(t *testing.T, t0 Term) {
	t.Helper()
	if t0.Semantics != "enumerated" {
		t.Errorf("term 0.0 semantics = %q", t0.Semantics)
	}
	if want := []string{"ai-input", "search"}; !equalStrings(t0.Functions, want) {
		t.Errorf("term 0.0 functions = %v, want %v", t0.Functions, want)
	}
	if want := []string{"ai-train"}; !equalStrings(t0.ProhibitedFunctions, want) {
		t.Errorf("term 0.0 prohibited = %v, want %v", t0.ProhibitedFunctions, want)
	}
	if want := []string{"academic"}; !equalStrings(t0.UserTypes, want) {
		t.Errorf("term 0.0 user_types = %v, want %v", t0.UserTypes, want)
	}
	if want := []string{"DE", "EU"}; !equalStrings(t0.Geos, want) {
		t.Errorf("term 0.0 geos = %v, want %v", t0.Geos, want)
	}
	if t0.Pricing == nil || t0.Pricing.Model != "free" || t0.Pricing.Rate != "0" || t0.Pricing.Currency != "EUR" {
		t.Errorf("term 0.0 pricing = %+v", t0.Pricing)
	}
}

// assertRecord0Term1 checks the commercial PER_UNIT term (term 0.1).
func assertRecord0Term1(t *testing.T, t1 Term) {
	t.Helper()
	if t1.Pricing == nil || t1.Pricing.Model != "per_unit" || t1.Pricing.Unit != "accesses" || t1.Pricing.Rate != "0.02" {
		t.Errorf("term 0.1 pricing = %+v", t1.Pricing)
	}
	if want := []string{"commercial_entity"}; !equalStrings(t1.UserTypes, want) {
		t.Errorf("term 0.1 user_types = %v", t1.UserTypes)
	}
	if len(t1.Quotas) != 1 || t1.Quotas[0].Metric != "accesses" || t1.Quotas[0].Limit != 1000 || t1.Quotas[0].Window != "daily" {
		t.Errorf("term 0.1 quotas = %+v", t1.Quotas)
	}
}

// assertFixtureRecord1 checks record 2: FLAT-priced term + attribution obligation.
func assertFixtureRecord1(t *testing.T, r1 Record) {
	t.Helper()
	if len(r1.Terms) != 1 {
		t.Fatalf("record 1 expected 1 term, got %d", len(r1.Terms))
	}
	t2 := r1.Terms[0]
	if t2.Pricing == nil || t2.Pricing.Model != "flat" || t2.Pricing.Rate != "4.99" || t2.Pricing.Unit != "" {
		t.Errorf("term 1.0 pricing = %+v (flat must carry no unit)", t2.Pricing)
	}
	if len(t2.Obligations) != 1 || t2.Obligations[0].Kind != "attribution" || t2.Obligations[0].Trigger != "on_use" {
		t.Errorf("term 1.0 obligations = %+v", t2.Obligations)
	}
}

// assertFixtureRecord2 checks record 3: REFERENCE_ONLY term with subscription
// scope and no machine fields.
func assertFixtureRecord2(t *testing.T, r2 Record) {
	t.Helper()
	if len(r2.Terms) != 1 {
		t.Fatalf("record 2 expected 1 term, got %d", len(r2.Terms))
	}
	t3 := r2.Terms[0]
	if t3.Semantics != "reference_only" {
		t.Errorf("term 2.0 semantics = %q", t3.Semantics)
	}
	if r2.License == nil || r2.License.URI == "" {
		t.Errorf("record 2 reference-only term requires license.uri, got %+v", r2.License)
	}
	if t3.Pricing == nil || t3.Pricing.Model != "free" {
		t.Errorf("term 2.0 pricing = %+v", t3.Pricing)
	}
	if want := []string{"subscription:premium"}; !equalStrings(t3.Scopes, want) {
		t.Errorf("term 2.0 scopes = %v, want %v", t3.Scopes, want)
	}
	if len(t3.Functions) != 0 || len(t3.ProhibitedFunctions) != 0 || len(t3.UserTypes) != 0 ||
		len(t3.Geos) != 0 || len(t3.Quotas) != 0 || len(t3.Obligations) != 0 {
		t.Errorf("term 2.0 reference-only must carry no machine fields, got %+v", t3)
	}
}

// TestParseMalformedLine asserts a malformed JSON-L line yields a clear,
// line-numbered error naming the actual defect rather than silently dropping
// or panicking.
func TestParseMalformedLine(t *testing.T) {
	cases := map[string]struct {
		input string
		want  string // substring the error must carry, tying it to the defect
	}{
		"invalid json": {
			input: `{"domain":"x","path":"/p","terms":[]}` + "\n" + `{not json}`,
			want:  "line 2",
		},
		"unknown field": {
			input: `{"domain":"x","path":"/p","terms":[],"bogus":true}`,
			want:  "bogus",
		},
		// pricing.rate is a decimal STRING on the wire (proto Pricing.rate);
		// a JSON number is a schema violation and must fail the line, not be
		// silently coerced through a float.
		"numeric rate": {
			input: `{"domain":"x","path":"/p","terms":[{"semantics":"enumerated",` +
				`"pricing":{"model":"flat","rate":4.99,"currency":"EUR"}}]}`,
			want: "rate",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJSONL(strings.NewReader(tc.input))
			if err == nil {
				t.Fatalf("expected error for %s input, got nil", name)
			}
			if !strings.Contains(err.Error(), "line") {
				t.Errorf("error should reference the offending line, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name the defect (want substring %q), got: %v", tc.want, err)
			}
		})
	}
}

// extensionLine is an extension-bearing feed line carrying every optional
// metadata field, used by TestParseExtensionFields. resource_mutability is a
// top-level typed scalar; ext (with previews) and the attestation claims are
// nested JSON objects the parser must preserve verbatim as json.RawMessage.
const extensionLine = `{"domain":"publisher.example","path":"/article/ext","title":"Ext",` +
	`"content_id":"pub-rt-0001","word_count":812,"estimated_quantity":1072,` +
	`"content_hash":"sha256:abc","hash_method":"sha256",` +
	`"source":"INGESTION_SOURCE_CMS_API","provenance_source":"wordpress-plugin",` +
	`"provenance_timestamp":"2026-03-18T09:30:00Z","resource_mutability":"RESOURCE_MUTABILITY_STATIC",` +
	`"ext":{"previews":[{"url":"https://cdn/x.jpg","media_type":"image/jpeg"}]},` +
	`"ext_critical":["previews"],` +
	`"attestations":[{"verifier":"publisher.example","kid":"pub-key-1","attested_at":"2026-03-18T09:31:00Z",` +
	`"uri":"https://publisher.example/article/ext","claims":{"language":"de"},"signature":"FIXTURE_SIG"}],` +
	`"license":{"id":"pub-ai-2026","uri":"https://publisher.example/licensing/ai","name":"Publisher AI License"},` +
	`"terms":[{"semantics":"enumerated","functions":["ai-input"],"pricing":{"model":"flat","rate":"4.99","currency":"EUR"}}]}`

// TestParseExtensionFields asserts the parser accepts the resource
// extension fields into the typed record — scalars/enums/timestamps as strings,
// ext + attestation claims preserved as raw JSON — while still rejecting a
// genuinely-unknown key alongside known extension fields (DisallowUnknownFields
// preserved).
func TestParseExtensionFields(t *testing.T) {
	records, err := ParseJSONL(strings.NewReader(extensionLine))
	if err != nil {
		t.Fatalf("ParseJSONL returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	assertExtensionScalars(t, r)
	assertExtensionRaw(t, r)
}

// assertExtensionScalars checks the scalar / enum / timestamp metadata fields
// land as typed values (no value validation — those stay raw strings/pointers).
func assertExtensionScalars(t *testing.T, r Record) {
	t.Helper()
	if r.ContentID != "pub-rt-0001" || r.ContentHash != "sha256:abc" || r.HashMethod != "sha256" {
		t.Errorf("scalar metadata = content_id %q hash %q method %q", r.ContentID, r.ContentHash, r.HashMethod)
	}
	if r.WordCount == nil || *r.WordCount != 812 || r.EstimatedQuantity == nil || *r.EstimatedQuantity != 1072 {
		t.Errorf("int32 metadata = word_count %v estimated_quantity %v", r.WordCount, r.EstimatedQuantity)
	}
	if r.Source != "INGESTION_SOURCE_CMS_API" || r.ProvenanceSource != "wordpress-plugin" {
		t.Errorf("source/provenance = %q / %q", r.Source, r.ProvenanceSource)
	}
	if r.ResourceMutability != "RESOURCE_MUTABILITY_STATIC" {
		t.Errorf("resource_mutability = %q (parser keeps it a raw string)", r.ResourceMutability)
	}
	if r.ProvenanceTimestamp != "2026-03-18T09:30:00Z" {
		t.Errorf("provenance_timestamp = %q (parser keeps it a raw string)", r.ProvenanceTimestamp)
	}
	if want := []string{"previews"}; !equalStrings(r.ExtCritical, want) {
		t.Errorf("ext_critical = %v, want %v", r.ExtCritical, want)
	}
}

// assertExtensionRaw checks ext and attestation claims survive as raw JSON
// objects (the parser owns no structpb conversion).
func assertExtensionRaw(t *testing.T, r Record) {
	t.Helper()
	if !strings.Contains(string(r.Ext), "previews") {
		t.Errorf("ext raw JSON missing previews key: %s", string(r.Ext))
	}
	if len(r.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(r.Attestations))
	}
	a := r.Attestations[0]
	if a.Verifier != "publisher.example" || a.Kid != "pub-key-1" || a.AttestedAt != "2026-03-18T09:31:00Z" ||
		a.URI != "https://publisher.example/article/ext" || a.Signature != "FIXTURE_SIG" {
		t.Errorf("attestation envelope = %+v", a)
	}
	if !strings.Contains(string(a.Claims), "language") {
		t.Errorf("attestation claims raw JSON missing keys: %s", string(a.Claims))
	}
}

// TestParseExtensionUnknownKeyRejected confirms an extension-bearing line that
// also carries a genuinely-unknown top-level key is still rejected — the new
// fields do NOT relax DisallowUnknownFields.
func TestParseExtensionUnknownKeyRejected(t *testing.T) {
	line := `{"domain":"x","path":"/p","terms":[],"content_id":"c","totally_unknown_field":1}`
	if _, err := ParseJSONL(strings.NewReader(line)); err == nil {
		t.Fatal("expected error for unknown key alongside extension fields, got nil")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
