package ingest

import (
	"os"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/licenseterm"
)

func loadFixture(t *testing.T) []Record {
	t.Helper()
	f, err := os.Open(fixturePath(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	records, err := ParseJSONL(f)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return records
}

// TestMapRecordGoldenArticle asserts record[0] maps to a proto-exact
// ResourceEntry with two terms (academic FREE + commercial PER_UNIT(accesses)).
func TestMapRecordGoldenArticle(t *testing.T) {
	records := loadFixture(t)
	got, err := mapRecord(records[0])
	if err != nil {
		t.Fatalf("mapRecord: %v", err)
	}

	license := &rampv1.License{
		Id:        proto.String("pub-ai-2026"),
		Uri:       proto.String("https://publisher.example/licensing/ai"),
		UriDigest: proto.String("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Name:      proto.String("Publisher AI License"),
	}
	want := &rampv1.ResourceEntry{
		Domain: "publisher.example",
		Path:   "/article/how-photosynthesis-works",
		Title:  proto.String("How Photosynthesis Works"),
		Terms: []*rampv1.LicenseTerm{
			{
				License:   license,
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Restrictions: []*rampv1.Restriction{
					{
						Kind:       rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
						Permitted:  []string{"ai-input", "search"},
						Prohibited: []string{"ai-train"},
					},
					{
						Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
						Permitted: []string{"academic"},
					},
					{
						Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
						Permitted: []string{"DE", "EU"},
					},
				},
				Pricing: &rampv1.Pricing{
					Model:    rampv1.PricingModel_PRICING_MODEL_FREE,
					Rate:     "0",
					Currency: "EUR",
				},
			},
			{
				License:   license,
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Restrictions: []*rampv1.Restriction{
					{
						Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
						Permitted: []string{"ai-input"},
					},
					{
						Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
						Permitted: []string{"commercial_entity"},
					},
					{
						Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
						Permitted: []string{"DE", "EU"},
					},
				},
				Quotas: []*rampv1.Quota{
					{
						Metric: "accesses",
						Limit:  1000,
						Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY,
					},
				},
				Pricing: &rampv1.Pricing{
					Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
					Rate:     "0.02",
					Currency: "EUR",
					Unit:     proto.String("accesses"),
				},
			},
		},
	}

	if !proto.Equal(got, want) {
		t.Errorf("mapRecord(record[0]) not proto-equal\n got: %v\nwant: %v", got, want)
	}
}

// TestMapRecordGoldenReferenceOnly asserts record[2] maps to a proto-exact
// REFERENCE_ONLY term: license.uri set, FREE, subscription scope, no machine fields.
func TestMapRecordGoldenReferenceOnly(t *testing.T) {
	records := loadFixture(t)
	got, err := mapRecord(records[2])
	if err != nil {
		t.Fatalf("mapRecord: %v", err)
	}

	want := &rampv1.ResourceEntry{
		Domain: "publisher.example",
		Path:   "/article/tax-return-tips-2026",
		Title:  proto.String("Tax Return Tips 2026"),
		Terms: []*rampv1.LicenseTerm{
			{
				License: &rampv1.License{
					Id:        proto.String("pub-premium-2026"),
					Uri:       proto.String("https://publisher.example/licensing/premium"),
					UriDigest: proto.String("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					Name:      proto.String("Publisher Premium License"),
				},
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				Pricing: &rampv1.Pricing{
					Model:    rampv1.PricingModel_PRICING_MODEL_FREE,
					Rate:     "0",
					Currency: "EUR",
				},
				Scopes: []string{"subscription:premium"},
			},
		},
	}

	if !proto.Equal(got, want) {
		t.Errorf("mapRecord(record[2]) not proto-equal\n got: %v\nwant: %v", got, want)
	}
}

// TestMappedTermsPassValidate is the contract proof: every term produced from
// every fixture record passes licenseterm.Validate with no hard error.
func TestMappedTermsPassValidate(t *testing.T) {
	records := loadFixture(t)
	vocab := licenseterm.NewInMemoryVocab()

	total := 0
	for ri, rec := range records {
		entry, err := mapRecord(rec)
		if err != nil {
			t.Fatalf("mapRecord(record[%d]): %v", ri, err)
		}
		for ti, term := range entry.GetTerms() {
			total++
			warnings, err := licenseterm.Validate(term, vocab)
			if err != nil {
				t.Errorf("record[%d] term[%d] failed Validate: %v", ri, ti, err)
			}
			if len(warnings) > 0 {
				t.Errorf("record[%d] term[%d] produced warnings (all fixture tokens are registered): %v", ri, ti, warnings)
			}
		}
	}
	if total != 4 {
		t.Fatalf("expected 4 mapped terms across the fixture, got %d", total)
	}
}

// TestPricingModelInvariants guards the closed-set invariants the proto enforces.
func TestPricingModelInvariants(t *testing.T) {
	records := loadFixture(t)
	for ri, rec := range records {
		entry, err := mapRecord(rec)
		if err != nil {
			t.Fatalf("mapRecord(record[%d]): %v", ri, err)
		}
		for ti, term := range entry.GetTerms() {
			p := term.GetPricing()
			switch p.GetModel() {
			case rampv1.PricingModel_PRICING_MODEL_PER_UNIT:
				if p.GetUnit() == "" {
					t.Errorf("record[%d] term[%d]: PER_UNIT must set a unit", ri, ti)
				}
			case rampv1.PricingModel_PRICING_MODEL_FLAT:
				if p.GetUnit() != "" {
					t.Errorf("record[%d] term[%d]: FLAT must not set a unit", ri, ti)
				}
			case rampv1.PricingModel_PRICING_MODEL_FREE:
				if p.GetRate() != "0" {
					t.Errorf("record[%d] term[%d]: FREE must have rate %q, got %q", ri, ti, "0", p.GetRate())
				}
			default:
				t.Errorf("record[%d] term[%d]: unexpected pricing model %v", ri, ti, p.GetModel())
			}
		}
	}
}

// pricedRecord builds a minimal record with one enumerated term per given
// pricing — the shared scaffold for the mapper rejection/canonicalization
// tests below.
func pricedRecord(pricings ...*Pricing) Record {
	terms := make([]Term, len(pricings))
	for i, p := range pricings {
		terms[i] = Term{Semantics: "enumerated", Pricing: p}
	}
	return Record{Domain: "x", Path: "/p", Terms: terms}
}

// TestMapRecordRejectsUnknownEnums asserts the mapper fails loud on unknown
// source enum spellings rather than emitting an UNSPECIFIED sentinel.
func TestMapRecordRejectsUnknownEnums(t *testing.T) {
	rec := pricedRecord(&Pricing{Model: "wat", Currency: "EUR"})
	if _, err := mapRecord(rec); err == nil {
		t.Fatal("expected error for unknown pricing model, got nil")
	}
}

// TestMapRecordRejectsBadRate asserts the mapper fails loud on a rate string
// that is not a canonical wire decimal (proto Pricing.rate pattern): signs,
// exponents, non-numeric text, and the empty string (a priced model requires
// an explicit rate) are all rejected.
func TestMapRecordRejectsBadRate(t *testing.T) {
	for name, rate := range map[string]string{
		"empty":       "",
		"negative":    "-0.05",
		"exponent":    "1e3",
		"non-numeric": "abc",
		"leading dot": ".5",
	} {
		t.Run(name, func(t *testing.T) {
			rec := pricedRecord(&Pricing{Model: "flat", Rate: rate, Currency: "EUR"})
			if _, err := mapRecord(rec); err == nil {
				t.Fatalf("expected error for rate %q, got nil", rate)
			}
		})
	}
}

// TestMapRecordRejectsNonZeroFreeRate asserts a FREE term declaring a
// non-zero rate is rejected — free requires rate "0" (or omitted). Malformed
// rate strings are covered by TestMapRecordRejectsBadRate.
func TestMapRecordRejectsNonZeroFreeRate(t *testing.T) {
	rec := pricedRecord(&Pricing{Model: "free", Rate: "0.05", Currency: "EUR"})
	if _, err := mapRecord(rec); err == nil {
		t.Fatal(`expected error for free rate "0.05", got nil`)
	}
}

// TestMapRecordCanonicalizesRate asserts a valid but non-canonical rate string
// is normalized to the wire form (trailing fractional zeros stripped), and
// FREE accepts any zero form (omitted or canonicalizing to "0", e.g. "0.00")
// while always emitting the canonical "0".
func TestMapRecordCanonicalizesRate(t *testing.T) {
	rec := pricedRecord(
		&Pricing{Model: "flat", Rate: "4.990", Currency: "EUR"},
		&Pricing{Model: "free", Rate: "", Currency: "EUR"},
		&Pricing{Model: "free", Rate: "0.00", Currency: "EUR"},
	)
	entry, err := mapRecord(rec)
	if err != nil {
		t.Fatalf("mapRecord: %v", err)
	}
	if got := entry.GetTerms()[0].GetPricing().GetRate(); got != "4.99" {
		t.Errorf("flat rate = %q, want canonicalized %q", got, "4.99")
	}
	for i, term := range entry.GetTerms()[1:] {
		if got := term.GetPricing().GetRate(); got != "0" {
			t.Errorf("free term %d rate = %q, want forced %q", i+1, got, "0")
		}
	}
}

// metadataBaseRecord is a minimal valid record (one priced enumerated term) used
// as the mutable base for the scalar-metadata mapper tests.
func metadataBaseRecord() Record {
	return Record{
		Domain: "publisher.example", Path: "/article/meta",
		Terms: []Term{{
			Semantics: "enumerated",
			Functions: []string{"ai-input"},
			Pricing:   &Pricing{Model: "flat", Rate: "4.99", Currency: "EUR"},
		}},
	}
}

// TestMapRecordScalarMetadata asserts the scalar / enum / timestamp resource
// extension fields map onto the ResourceEntry with correct typed
// values, including int32 round-trip and the IngestionSource enum + RFC3339
// provenance timestamp.
func TestMapRecordScalarMetadata(t *testing.T) {
	rec := metadataBaseRecord()
	wc, eq := int32(812), int32(1072)
	rec.ContentID = "pub-rt-0001"
	rec.WordCount = &wc
	rec.EstimatedQuantity = &eq
	rec.ContentHash = "sha256:abc"
	rec.HashMethod = "sha256"
	rec.Source = "INGESTION_SOURCE_CMS_API"
	rec.ProvenanceSource = "wordpress-plugin"
	rec.ProvenanceTimestamp = "2026-03-18T09:30:00Z"

	entry, err := mapRecord(rec)
	if err != nil {
		t.Fatalf("mapRecord: %v", err)
	}
	if entry.GetContentId() != "pub-rt-0001" || entry.GetContentHash() != "sha256:abc" || entry.GetHashMethod() != "sha256" {
		t.Errorf("scalar metadata = content_id %q hash %q method %q", entry.GetContentId(), entry.GetContentHash(), entry.GetHashMethod())
	}
	if entry.GetWordCount() != 812 || entry.GetEstimatedQuantity() != 1072 {
		t.Errorf("int32 metadata = word_count %d estimated_quantity %d", entry.GetWordCount(), entry.GetEstimatedQuantity())
	}
	if entry.GetSource() != rampv1.IngestionSource_INGESTION_SOURCE_CMS_API {
		t.Errorf("source = %v, want INGESTION_SOURCE_CMS_API", entry.GetSource())
	}
	if entry.GetProvenanceSource() != "wordpress-plugin" {
		t.Errorf("provenance_source = %q", entry.GetProvenanceSource())
	}
	if got := entry.GetProvenanceTimestamp().AsTime().Format(time.RFC3339); got != "2026-03-18T09:30:00Z" {
		t.Errorf("provenance_timestamp = %q, want 2026-03-18T09:30:00Z", got)
	}
}

// TestMapRecordRejectsUnknownSource asserts an unknown IngestionSource spelling
// fails loud at the mapper (the parser keeps source as a raw string).
func TestMapRecordRejectsUnknownSource(t *testing.T) {
	rec := metadataBaseRecord()
	rec.Source = "INGESTION_SOURCE_TELEPATHY"
	if _, err := mapRecord(rec); err == nil {
		t.Fatal("expected error for unknown ingestion source, got nil")
	}
}

// TestMapRecordRejectsInvalidMutability asserts that both an explicit UNSPECIFIED
// and an unknown resource_mutability spelling fail loud at the mapper — the ingest
// mirror of the Offer-side {not_in:[0]} rule.
func TestMapRecordRejectsInvalidMutability(t *testing.T) {
	for name, mutability := range map[string]string{
		"unspecified": "RESOURCE_MUTABILITY_UNSPECIFIED",
		"unknown":     "RESOURCE_MUTABILITY_TELEPATHY",
	} {
		t.Run(name, func(t *testing.T) {
			rec := metadataBaseRecord()
			rec.ResourceMutability = mutability
			_, err := mapRecord(rec)
			if err == nil {
				t.Fatalf("expected error for %s resource_mutability, got nil", name)
			}
			if !strings.Contains(err.Error(), "resource mutability") {
				t.Errorf("error must name the mutability rejection reason, got: %v", err)
			}
		})
	}
}

// TestMapRecordRejectsMalformedTimestamp asserts a non-RFC3339 provenance
// timestamp fails loud at the mapper.
func TestMapRecordRejectsMalformedTimestamp(t *testing.T) {
	rec := metadataBaseRecord()
	rec.ProvenanceTimestamp = "18.03.2026 09:30"
	if _, err := mapRecord(rec); err == nil {
		t.Fatal("expected error for malformed provenance_timestamp, got nil")
	}
}

// TestMapRecordStructuredMetadata asserts the typed resource_mutability scalar,
// ext (carrying a previews array), ext_critical, and attestations (claims kept as
// a Struct) are mapped onto the ResourceEntry — the mutability enum resolves to
// the typed field, ext keys and claims survive as structpb, the attestation
// envelope as typed proto.
func TestMapRecordStructuredMetadata(t *testing.T) {
	rec := metadataBaseRecord()
	rec.ResourceMutability = "RESOURCE_MUTABILITY_STATIC"
	rec.Ext = []byte(`{"previews":[{"url":"https://cdn/x.jpg","media_type":"image/jpeg"}]}`)
	rec.ExtCritical = []string{"previews"}
	rec.Attestations = []Attestation{{
		Verifier: "publisher.example", Kid: "pub-key-1", AttestedAt: "2026-03-18T09:31:00Z",
		URI: "https://publisher.example/article/meta", Claims: []byte(`{"language":"de"}`), Signature: "FIXTURE_SIG",
	}}

	entry, err := mapRecord(rec)
	if err != nil {
		t.Fatalf("mapRecord: %v", err)
	}
	if entry.GetResourceMutability() != rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC {
		t.Errorf("resource_mutability = %v, want STATIC", entry.GetResourceMutability())
	}
	ext := entry.GetExt().GetFields()
	if _, ok := ext["previews"]; !ok {
		t.Errorf("ext missing previews key: %v", ext)
	}
	if want := []string{"previews"}; !equalStrings(entry.GetExtCritical(), want) {
		t.Errorf("ext_critical = %v, want %v", entry.GetExtCritical(), want)
	}
	if len(entry.GetAttestations()) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(entry.GetAttestations()))
	}
	a := entry.GetAttestations()[0]
	if a.GetVerifier() != "publisher.example" || a.GetKeyid() != "pub-key-1" || a.GetSignature() != "FIXTURE_SIG" {
		t.Errorf("attestation envelope = %+v", a)
	}
	if a.GetClaims().GetFields()["language"].GetStringValue() != "de" {
		t.Errorf("attestation claims Struct not intact: %v", a.GetClaims())
	}
}

// TestMapRecordRejectsNonObjectExt asserts a wrong-typed (valid JSON string) ext
// fails loud at the mapper — the parser accepted it as raw JSON.
func TestMapRecordRejectsNonObjectExt(t *testing.T) {
	rec := metadataBaseRecord()
	rec.Ext = []byte(`"not-an-object"`)
	if _, err := mapRecord(rec); err == nil {
		t.Fatal("expected error for non-object ext, got nil")
	}
}

// TestMapRecordRejectsNonObjectClaims asserts wrong-typed attestation claims
// fail loud at the mapper.
func TestMapRecordRejectsNonObjectClaims(t *testing.T) {
	rec := metadataBaseRecord()
	rec.Attestations = []Attestation{{
		Verifier: "v", Claims: []byte(`"should-be-object"`),
	}}
	if _, err := mapRecord(rec); err == nil {
		t.Fatal("expected error for non-object attestation claims, got nil")
	}
}
