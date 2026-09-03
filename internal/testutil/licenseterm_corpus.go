package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The license-term corpus: the SDK's Go-emitted oracle for token folding, term
// normalization, registry membership, the per-term ingest-tier verdict and the
// composed per-entry verdict, kept as a verbatim copy under testdata/ and read
// by two consumers with one loader. The guard in internal/guards replays it
// through the pinned module's own faces; the Exchange transport suite replays
// it through the public RPCs. Both decode the same shape, so the shape is
// defined once here rather than once per consumer.

// LicenseTermFinding is one violation or warning as the corpus records it and
// as the SDK reports it: the rule id, the snake_case proto-JSON path relative
// to the checked message, the offending token when the rule is about one, and
// the message — for a warning, the exact string the Exchange puts in
// PushResourcesResponse.warnings.
type LicenseTermFinding struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Token   string `json:"token"`
	Message string `json:"message"`
}

// LicenseTermFoldVector is one CanonicalRestrictionToken case. Kind is the
// RestrictionKind enum NAME, the form the JSON clients see on the wire.
type LicenseTermFoldVector struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	Canonical string `json:"canonical"`
}

// LicenseTermNormalizeVector is one NormalizeLicenseTerm case: a term as
// proto-JSON and the same term after normalization, which is a fixed point of
// the face.
type LicenseTermNormalizeVector struct {
	Name       string          `json:"name"`
	Term       json.RawMessage `json:"term"`
	Normalized json.RawMessage `json:"normalized"`
}

// LicenseTermKnownVector is one KnownRestrictionToken case.
type LicenseTermKnownVector struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Token string `json:"token"`
	Known bool   `json:"known"`
}

// LicenseTermValidateVector is one ValidateLicenseTerm case over a term the
// corpus documents as already canonical: the hard reject, if any, and the
// warnings the accepted term carries.
type LicenseTermValidateVector struct {
	Name      string               `json:"name"`
	Term      json.RawMessage      `json:"term"`
	Violation *LicenseTermFinding  `json:"violation"`
	Warnings  []LicenseTermFinding `json:"warnings"`
}

// LicenseTermEntryVector is one ValidateResourceEntry case, both tiers composed
// in the Exchange's order. Its refusal columns are recorded at three strengths,
// because the three SDK ports agree at three strengths: Structural is a boolean
// over the field-level wire violations (their ids are validator-local),
// CrossFieldRules are the message-level CEL ids (authored in the proto, so every
// port emits the same strings), TermRules are whole ingest-tier findings (the
// SDK owns that code in every language). Warnings are the accepted terms'
// warnings with entry-relative paths.
type LicenseTermEntryVector struct {
	Name            string               `json:"name"`
	Entry           json.RawMessage      `json:"entry"`
	OK              bool                 `json:"ok"`
	Structural      bool                 `json:"structural"`
	CrossFieldRules []string             `json:"cross_field_rules"`
	TermRules       []LicenseTermFinding `json:"term_rules"`
	Warnings        []LicenseTermFinding `json:"warnings"`
}

// LicenseTermCorpus is the whole corpus document.
type LicenseTermCorpus struct {
	Note      string                       `json:"note"`
	Fold      []LicenseTermFoldVector      `json:"fold"`
	Normalize []LicenseTermNormalizeVector `json:"normalize"`
	Known     []LicenseTermKnownVector     `json:"known"`
	Validate  []LicenseTermValidateVector  `json:"validate"`
	Entry     []LicenseTermEntryVector     `json:"entry"`
}

// LoadLicenseTermCorpus reads and decodes the corpus at path (relative to the
// caller's package directory). It fails the test when any of the five lists is
// empty: a replay over an empty list passes without checking anything, and a
// corpus that lost a list through a bad refresh would otherwise report green.
func LoadLicenseTermCorpus(tb testing.TB, path string) LicenseTermCorpus {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		tb.Fatalf("read license-term corpus: %v", err)
	}
	var c LicenseTermCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		tb.Fatalf("decode license-term corpus: %v", err)
	}
	for name, n := range map[string]int{
		"fold": len(c.Fold), "normalize": len(c.Normalize), "known": len(c.Known),
		"validate": len(c.Validate), "entry": len(c.Entry),
	} {
		if n == 0 {
			tb.Fatalf("license-term corpus list %q is empty — a replay over nothing passes vacuously", name)
		}
	}
	return c
}

// CrossFieldRuleIDs returns every message-level CEL rule id the pinned proto
// declares, read from the generated descriptor. It is how a corpus replay
// classifies a wire-tier violation the way the corpus emitter did: a rule id in
// this set is a cross-field rule and is compared by id; any other wire
// violation is field-level and counts only toward the structural boolean. The
// set is read rather than listed because a listed copy is the one that drifts,
// and the copy that drifts is the one deciding the classification. Fails the
// test when the walk yields nothing, since every cross-field violation would
// then be misclassified as field-level and the comparison would be vacuous.
func CrossFieldRuleIDs(tb testing.TB) map[string]bool {
	tb.Helper()
	ids := map[string]bool{}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := range mds.Len() {
			md := mds.Get(i)
			if opts := md.Options(); proto.HasExtension(opts, validate.E_Message) {
				rules, _ := proto.GetExtension(opts, validate.E_Message).(*validate.MessageRules)
				for _, c := range rules.GetCel() {
					ids[c.GetId()] = true
				}
			}
			walk(md.Messages())
		}
	}
	walk(rampv1.File_ramp_v1_ramp_proto.Messages())
	if len(ids) == 0 {
		tb.Fatal("no message-level CEL ids in the pinned descriptor — every cross-field violation " +
			"would be classified as field-level")
	}
	return ids
}
