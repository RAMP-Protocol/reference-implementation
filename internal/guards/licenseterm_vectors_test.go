// Cross-implementation gate for the license-term corpus: the repo-root copy of
// the SDK's licenseterm-vectors.json must replay, list by list, through the
// pinned module's own faces (sdk/go/helpers in github.com/RAMP-Protocol/protocol).
//
// Provenance and refresh rule. testdata/licenseterm-vectors.json is a verbatim
// byte copy of sdk/go/helpers/testdata/licenseterm-vectors.json in that module,
// whose emitter (RAMP_UPDATE_VECTORS=1 go test ./sdk/go/helpers/ -run
// TestGenerateLicenseTermVectors) derives every value from the real Go face and
// is the drift gate upstream. The copy is refreshed from the module at every
// re-pin and never edited by hand, and scripts/check-sdk-pin-consistency.sh
// enforces that: its last section byte-compares the two files and fails when
// they differ, or when it could not reach the module to compare them at all.
// It is copied rather than read from the module cache because testdata cannot
// cross a module boundary (go:embed will not reach it) and a cache read breaks
// in vendored or air-gapped CI — which is why the comparison lives in a re-pin
// gate rather than in this test, whose job is to run anywhere. The thumbprint
// and proof-of-possession corpora under testdata/ are the same arrangement.
//
// What this file proves is that the COPY and the PINNED MODULE agree. A re-pin
// that changes a rule, a message or an alias without a matching refresh fails
// here rather than in the Exchange replay downstream
// (src/exchange/internal/transport/catalog_corpus_integration_test.go), whose
// oracle this copy is. What it does not prove is the Exchange's behaviour; that
// is the replay's job. Pure functions, no infrastructure, no build tag.
//
// Both polarities have to be present per list, not just some vectors. Each
// list's assertion has an accepting branch and a refusing branch, and which one
// a vector takes is decided by the vector itself, so a corpus that drifted to
// all-one-kind would run only one branch and still report green — the shape a
// non-empty check cannot see. The counts below are what make that a failure.
package guards_test

import (
	"errors"
	"slices"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// licenseTermVectors is the repo-root copy, relative to this package directory.
const licenseTermVectors = "../../testdata/licenseterm-vectors.json"

func loadLicenseTermCorpus(t *testing.T) testutil.LicenseTermCorpus {
	t.Helper()
	return testutil.LoadLicenseTermCorpus(t, licenseTermVectors)
}

// restrictionKind resolves the enum NAME the corpus carries to the Go enum,
// failing on a name the pinned proto does not declare.
func restrictionKind(t *testing.T, name string) rampv1.RestrictionKind {
	t.Helper()
	n, ok := rampv1.RestrictionKind_value[name]
	if !ok {
		t.Fatalf("corpus names RestrictionKind %q, which the pinned proto does not declare", name)
	}
	return rampv1.RestrictionKind(n)
}

func decodeTerm(t *testing.T, name string, raw []byte) *rampv1.LicenseTerm {
	t.Helper()
	var term rampv1.LicenseTerm
	if err := protojson.Unmarshal(raw, &term); err != nil {
		t.Fatalf("%s: decode term: %v", name, err)
	}
	return &term
}

// findingsOf renders the SDK's warnings in the corpus's shape so the two compare
// as whole findings.
func findingsOf(ws []helpers.RuleWarning) []testutil.LicenseTermFinding {
	out := make([]testutil.LicenseTermFinding, 0, len(ws))
	for _, w := range ws {
		out = append(out, testutil.LicenseTermFinding{Rule: w.Rule, Path: w.Path, Token: w.Token, Message: w.Message})
	}
	return out
}

func findingOf(v helpers.RuleViolation) testutil.LicenseTermFinding {
	return testutil.LicenseTermFinding{Rule: v.Rule, Path: v.Path, Token: v.Token, Message: v.Message}
}

// requireBothPolarities fails when either branch of a list's assertion had no
// vector to run on.
func requireBothPolarities(t *testing.T, list string, accepting, refusing int) {
	t.Helper()
	if accepting == 0 || refusing == 0 {
		t.Fatalf("%s list has %d accepting and %d refusing vectors; the replay needs at least one of each",
			list, accepting, refusing)
	}
}

// TestLicenseTermVectors_Fold replays CanonicalRestrictionToken. The refusing
// polarity here is a token the fold leaves alone: the non-ASCII rows are the
// load-bearing ones, since a port that reaches for a Unicode lowercase turns a
// homograph into a registered token.
func TestLicenseTermVectors_Fold(t *testing.T) {
	t.Parallel()
	var folded, untouched int
	for _, v := range loadLicenseTermCorpus(t).Fold {
		if v.Canonical == v.Token {
			untouched++
		} else {
			folded++
		}
		got := helpers.CanonicalRestrictionToken(restrictionKind(t, v.Kind), v.Token)
		if got != v.Canonical {
			t.Errorf("%s: CanonicalRestrictionToken(%s, %q) = %q, want %q", v.Name, v.Kind, v.Token, got, v.Canonical)
		}
	}
	requireBothPolarities(t, "fold", folded, untouched)
}

// TestLicenseTermVectors_Normalize replays NormalizeLicenseTerm and, as the
// emitter did before recording, checks the face is idempotent on every vector.
// The refusing polarity is a term normalization leaves unchanged.
func TestLicenseTermVectors_Normalize(t *testing.T) {
	t.Parallel()
	var changed, fixedPoint int
	for _, v := range loadLicenseTermCorpus(t).Normalize {
		term := decodeTerm(t, v.Name, v.Term)
		want := decodeTerm(t, v.Name, v.Normalized)
		if proto.Equal(term, want) {
			fixedPoint++
		} else {
			changed++
		}
		helpers.NormalizeLicenseTerm(term)
		if !proto.Equal(term, want) {
			t.Errorf("%s: normalized = %v, want %v", v.Name, term, want)
		}
		helpers.NormalizeLicenseTerm(term)
		if !proto.Equal(term, want) {
			t.Errorf("%s: NormalizeLicenseTerm is not idempotent: second pass = %v", v.Name, term)
		}
	}
	requireBothPolarities(t, "normalize", changed, fixedPoint)
}

// TestLicenseTermVectors_Known replays KnownRestrictionToken.
func TestLicenseTermVectors_Known(t *testing.T) {
	t.Parallel()
	var known, unknown int
	for _, v := range loadLicenseTermCorpus(t).Known {
		if v.Known {
			known++
		} else {
			unknown++
		}
		got := helpers.KnownRestrictionToken(restrictionKind(t, v.Kind), v.Token)
		if got != v.Known {
			t.Errorf("%s: KnownRestrictionToken(%s, %q) = %v, want %v", v.Name, v.Kind, v.Token, got, v.Known)
		}
	}
	requireBothPolarities(t, "known", known, unknown)
}

// TestLicenseTermVectors_Validate replays ValidateLicenseTerm: the violation,
// when the corpus records one, as a whole finding; the warnings as whole
// findings in order. A vector recording no violation must also produce none.
func TestLicenseTermVectors_Validate(t *testing.T) {
	t.Parallel()
	var accepted, rejected, warned int
	for _, v := range loadLicenseTermCorpus(t).Validate {
		if v.Violation == nil {
			accepted++
		} else {
			rejected++
		}
		if len(v.Warnings) > 0 {
			warned++
		}
		warnings, err := helpers.ValidateLicenseTerm(decodeTerm(t, v.Name, v.Term))
		var got *helpers.RuleViolation
		if err != nil && !errors.As(err, &got) {
			t.Errorf("%s: ValidateLicenseTerm returned a non-RuleViolation error: %v", v.Name, err)
			continue
		}
		switch {
		case v.Violation == nil && got != nil:
			t.Errorf("%s: unexpected violation %+v", v.Name, *got)
		case v.Violation != nil && got == nil:
			t.Errorf("%s: want violation %+v, got none", v.Name, *v.Violation)
		case v.Violation != nil && findingOf(*got) != *v.Violation:
			t.Errorf("%s: violation = %+v, want %+v", v.Name, findingOf(*got), *v.Violation)
		}
		if got := findingsOf(warnings); !slices.Equal(got, v.Warnings) {
			t.Errorf("%s: warnings = %+v, want %+v", v.Name, got, v.Warnings)
		}
	}
	requireBothPolarities(t, "validate", accepted, rejected)
	if warned == 0 {
		t.Fatal("validate list has no vector with warnings; the warning comparison never ran")
	}
}

// TestLicenseTermVectors_Entry replays ValidateResourceEntry and classifies its
// violations the way the emitter did: an ingest-tier rule id is a whole finding
// (term_rules), a message-level CEL id from the descriptor is a cross-field id
// (cross_field_rules), anything else is field-level and only flips the
// structural boolean. Beyond the accepted/refused polarities, every refusal tier
// has to be represented, or the list could lose one and the replay would not
// notice.
func TestLicenseTermVectors_Entry(t *testing.T) {
	t.Parallel()
	corpus := loadLicenseTermCorpus(t)
	celIDs := testutil.CrossFieldRuleIDs(t)
	termIDs := termRuleIDs(t, corpus)
	var accepted, refused, structural, crossField, termRules int
	for _, v := range corpus.Entry {
		if v.OK {
			accepted++
		} else {
			refused++
		}
		if v.Structural {
			structural++
		}
		if len(v.CrossFieldRules) > 0 {
			crossField++
		}
		if len(v.TermRules) > 0 {
			termRules++
		}
		var entry rampv1.ResourceEntry
		if err := protojson.Unmarshal(v.Entry, &entry); err != nil {
			t.Fatalf("%s: decode entry: %v", v.Name, err)
		}
		verdict := helpers.ValidateResourceEntry(&entry)
		if verdict.OK() != v.OK {
			t.Errorf("%s: ok = %v, want %v (violations %+v)", v.Name, verdict.OK(), v.OK, verdict.Violations)
		}
		gotStructural, gotCEL, gotTerm := classifyEntryViolations(verdict.Violations, celIDs, termIDs)
		if gotStructural != v.Structural {
			t.Errorf("%s: structural = %v, want %v", v.Name, gotStructural, v.Structural)
		}
		if !slices.Equal(gotCEL, v.CrossFieldRules) {
			t.Errorf("%s: cross_field_rules = %v, want %v", v.Name, gotCEL, v.CrossFieldRules)
		}
		if !slices.Equal(gotTerm, v.TermRules) {
			t.Errorf("%s: term_rules = %+v, want %+v", v.Name, gotTerm, v.TermRules)
		}
		if got := findingsOf(verdict.Warnings); !slices.Equal(got, v.Warnings) {
			t.Errorf("%s: warnings = %+v, want %+v", v.Name, got, v.Warnings)
		}
	}
	requireBothPolarities(t, "entry", accepted, refused)
	if structural == 0 || crossField == 0 || termRules == 0 {
		t.Fatalf("entry list has %d structural, %d cross-field and %d term-rule refusals; every tier needs at least one",
			structural, crossField, termRules)
	}
}

// termRuleIDs returns every rule id the ingest tier can refuse a term with, read
// out of the corpus's own per-term list rather than written down here: an
// ingest-tier reject IS an id that list can carry as a violation. A
// classification written down twice is a classification that can disagree with
// itself, and the list this one replaced was one of five copies across two
// repositories, so adding a rule to the tier meant five edits.
//
// Here, missing one is loud. The corpus records the term_rules the classifier
// then fails to produce, so the term_rules column disagrees on every vector that
// records one, and the structural boolean disagrees too on each of those that
// recorded it false — a term reject the classifier does not recognise falls to
// the structural bucket below. The entry replay names each disagreement. That is
// exactly how the id this file now derives arrived: the corpus refresh landed
// first and this classifier was left listing two ids, and the suite stopped. The
// quiet version of the failure needs the SDK's own emitter to be missing the same
// id, so that the corpus never records what the replay never classifies — which
// is upstream's concern, not this file's.
//
// It is a weaker derivation than the neighbouring testutil.CrossFieldRuleIDs, and
// worth knowing which. That one walks the pinned generated descriptor, so it
// cannot disagree with the implementation it classifies against. This one reads
// the same document the assertions below compare against, so a corpus that lost
// the column would take the expectation with it. Hence the guard below.
//
// Guard the guard — for the diagnosis, not the detection. A derivation that
// stopped reading the column would leave an empty set here and move every term
// reject into the structural bucket, and the entry replay would fail: it reports
// a mismatch for every vector that records a term rule. What it does not report
// is why. The guard turns that scatter into one message naming the id that went
// missing, at the place the derivation broke. Both long-standing ids are
// reachable from the per-term list, so requiring them pins that the column is
// still being read.
func termRuleIDs(t *testing.T, c testutil.LicenseTermCorpus) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, v := range c.Validate {
		if v.Violation != nil {
			ids[v.Violation.Rule] = true
		}
	}
	for _, want := range []string{helpers.RulePricingUnitRegistered, helpers.RuleQuotaMetricRegistered} {
		if !ids[want] {
			t.Fatalf("the per-term list carries no %q — the column this classification is derived from has moved", want)
		}
	}
	return ids
}

// classifyEntryViolations splits an entry verdict's violations into the three
// columns the corpus records. Slices are non-nil so an empty column compares
// equal to the corpus's empty list.
func classifyEntryViolations(
	violations []helpers.RuleViolation, celIDs, termIDs map[string]bool,
) (structural bool, crossField []string, termRules []testutil.LicenseTermFinding) {
	crossField = []string{}
	termRules = []testutil.LicenseTermFinding{}
	for _, viol := range violations {
		switch {
		case termIDs[viol.Rule]:
			termRules = append(termRules, findingOf(viol))
		case celIDs[viol.Rule]:
			crossField = append(crossField, viol.Rule)
		default:
			structural = true
		}
	}
	return structural, crossField, termRules
}
