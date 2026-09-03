// Structural guards for the RAMP protocol version on the wire. Two diseases,
// two checks, because a version field can go wrong in two ways and the older
// half of this guard could only see one of them.
//
// The wire contract: a sender MUST stamp `ver` from a single constant, never a
// literal. helpers.ProtocolVersion is that constant, exported by the SDK in all
// three languages. On receive `ver` is advisory -- it is not an authenticity or
// authorization control, a receiver need not check it, and one that does MAY
// reject an unrecognised major version but MUST NOT reject an unrecognised minor
// one. Authenticity rides on the RFC 9421 request signature and the Ed25519
// offer signature. Nothing here reads `ver` off an inbound message, so a wrong
// value surfaces as a functional skew rather than a rejection.
//
// The single-constant rule cannot be behavioral: a constant and a literal that
// both read "1.0" produce identical bytes. The VALUE is different -- six
// responses are read back and asserted against the literal in the integration
// suites, and these checks complement those rather than replace them.
// PushResourcesRequest.Ver genuinely has no observer; nothing here reads it back.
// A third check, in ver_constant_guard_test.go, covers the case neither these
// nor the assertions can see: a constant from the wrong namespace.
//
// TestVerIsSingleSourced catches a builder that stamps a bare literal -- that is
// how "0.3" survived alongside "1.0" long enough to be filed as a release
// blocker. TestVerIsNeverOmitted catches one that never sets the field, which the
// literal check is blind to by construction: no `Ver:` key, no match, pass. Four
// production builders shipped an empty version under exactly that blindness.
//
// The omission check takes its scope from the contract, not a list: it reads the
// generated descriptors for every message whose field 1 is named `ver`, so one
// added tomorrow is covered the day a builder for it is written. WellKnownManifest
// is excluded and must stay excluded -- it versions the /.well-known/ramp.json
// document schema, a namespace ramp.proto keeps separate, and its producers
// correctly stamp rampwellknown.Version.
//
// Scope: every non-generated .go file under src/ and internal/, FIXTURES
// INCLUDED. Every "0.3" this project shipped was in a _test.go file or the Python
// harness -- production Go never held one -- so a check that skipped fixtures
// could not have caught a single instance of the defect it is named after. The
// sibling guards keep the narrower appSourceFiles walk, because a fixture may
// legitimately hand-roll what they forbid. The harness is a sender too and is
// held to the same rule by its own guard, since nothing here can open a .py file.
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// verLiteralPattern matches a `Ver:` struct-field assignment whose value is a
// bare double-quoted string, e.g. `Ver: "1.0"`. Interior whitespace is collapsed
// by the caller, so a tab- or multi-space-aligned form (the formatter aligns
// struct keys) matches identically. `Ver: helpers.ProtocolVersion` and the echo
// form `Ver: req.GetVer()` do not match, because the value is not a quoted
// string. `Verifier:` and `VerifiedOffer:` do not match either, because `Ver` is
// required immediately before the colon.
var verLiteralPattern = regexp.MustCompile(`\bVer:\s*"[^"]*"`)

// countVerLiteral reports how many `Ver: "<literal>"` assignments occur in src
// after collapsing interior whitespace, so an alignment variant -- extra spaces,
// a tab, or a value pushed onto the next line -- is counted the same as the
// canonical spelling and cannot slip past.
func countVerLiteral(src string) int {
	normalized := strings.Join(strings.Fields(src), " ")
	return len(verLiteralPattern.FindAllString(normalized, -1))
}

// protoImportPaths are the generated packages whose messages carry the envelope
// `ver`. A composite literal only counts when its qualifier resolves to one of
// these in the file being read, so a local type that happens to be named
// UsageReportResponse cannot trip the omission check.
var protoImportPaths = []string{
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1",
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1",
}

// manifestMessage is the one `ver`-bearing message the single-constant rule does
// not reach: it versions the well-known document schema, not the RPC envelope.
const manifestMessage = "WellKnownManifest"

// verBearingMessages returns the Go type names of every contract message whose
// field 1 is named `ver`, read from the generated descriptors rather than
// restated here, minus the documented manifest exemption. Reading the descriptor
// is what makes the check self-extending: a new message with an envelope `ver`
// joins the set with no edit to this file.
func verBearingMessages(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, fd := range []protoreflect.FileDescriptor{
		rampv1.File_ramp_v1_ramp_proto,
		rampadminv1.File_ramp_admin_v1_admin_proto,
	} {
		msgs := fd.Messages()
		for i := range msgs.Len() {
			m := msgs.Get(i)
			f := m.Fields().ByNumber(1)
			if f == nil || f.Name() != "ver" {
				continue
			}
			if name := string(m.Name()); name != manifestMessage {
				out[name] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no ver-bearing messages found in the generated descriptors — " +
			"the omission check would pass vacuously, so this is a failure, not a skip")
	}
	return out
}

// protoQualifiers maps each identifier in file that refers to a ver-bearing
// generated package onto true, resolving whatever alias the file chose.
func protoQualifiers(file *ast.File) map[string]bool {
	return qualifiersFor(file, protoImportPaths...)
}

// hasVerKey reports whether a composite literal sets the Ver field explicitly,
// whatever it sets it to. The omission check is only about presence; whether the
// value is a constant or a literal is TestVerIsSingleSourced's question, and an
// echo (`Ver: req.GetVer()`) is a legitimate presence.
func hasVerKey(lit *ast.CompositeLit) bool {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Ver" {
			return true
		}
	}
	return false
}

// omissionAllowlist names the files whose ver-bearing constructions are NOT
// authored messages, with the reason each is exempt. A message decoded into, or
// handed to a call that never sends it, has nothing to stamp; the distinction is
// not visible in the syntax, so it is named here rather than guessed at. Every
// entry is asserted used and necessary by
// TestVerOmissionAllowlistEntriesAreUsedAndNecessary, so one cannot outlive its
// cause.
var omissionAllowlist = map[string]string{
	"internal/guards/items_only_descriptor_test.go":        "descriptor probes — (&rampv1.X{}).ProtoReflect() reads the shape and sends nothing",
	"src/broker/internal/xclient/pool_constructor_test.go": "empty query handed to a deliberately short-circuited transport; the call is expected to fail",
	"src/broker/internal/signing/cosign_test.go":           "a SignForward input, not a wire envelope — the signature covers domain|id|query|ts",
}

// literalAllowlist names the files whose bare Ver literals are not stamps. Only
// this guard qualifies: its own meta-cases have to spell the offending form to
// prove the matcher sees it.
var literalAllowlist = map[string]string{
	"internal/guards/ver_ssot_guard_test.go":     "meta-case data — the literal form is the thing under test",
	"internal/guards/ver_constant_guard_test.go": "meta-case data — one case states the literal so the split with this check is pinned",
}

// verOmission is one construction of a ver-bearing message that does not set Ver.
// The position is returned rather than a formatted line so the caller resolves it
// against whichever FileSet parsed the file — that is what lets the meta-tests
// drive this matcher over an in-memory snippet.
type verOmission struct {
	Pos     token.Pos
	Message string
}

// verBearingSelector reports the message name when expr is a qualified reference
// to a contract message carrying an envelope `ver`, e.g. `rampv1.UsageReport`.
// The qualifier must resolve to a generated contract package in THIS file, so a
// local type that happens to share a name cannot match.
func verBearingSelector(expr ast.Expr, quals, messages map[string]bool) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !quals[pkg.Name] || !messages[sel.Sel.Name] {
		return "", false
	}
	return sel.Sel.Name, true
}

// decodeTargets returns the names declared in file whose address is handed to an
// Unmarshal call, e.g. `var r rampv1.X` followed by `protojson.Unmarshal(b, &r)`.
// Such a variable is the RECEIVING end: the bytes decide its ver, so there is
// nothing for the declaration to stamp.
//
// This is a rule, not a list of exceptions, and the difference is load-bearing.
// Every zero-value declaration of a ver-bearing message in this repository —
// production and fixture alike — is an Unmarshal target. Naming eleven files in
// an allowlist would have recorded that fact eleven times and still left a new
// one to be argued about; matching on the address-taken-into-Unmarshal shape
// says it once. A declaration that is never decoded into is still reported,
// which is the case the check exists for.
func decodeTargets(file *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fn.Sel.Name != "Unmarshal" {
			return true
		}
		for _, arg := range call.Args {
			unary, ok := arg.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			if id, ok := unary.X.(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// verOmissionSites returns every construction in file of a ver-bearing contract
// message that leaves Ver unset. This is THE matcher: the tree scan and the
// meta-tests both call it, so a break in the traversal turns the meta-tests red
// instead of leaving them green over a private copy.
//
// Two syntactic forms carry a construction:
//
//   - a composite literal, `&rampv1.UsageReport{...}`, with no Ver key;
//   - a zero-value declaration, `var r rampv1.UsageReport`, which has no literal
//     to carry Ver at all. A `var r = rampv1.UsageReport{...}` has a composite
//     literal and is read by the first form, so it is skipped here, and one that
//     is decoded into is not a construction at all — see decodeTargets.
//
// An echo (`Ver: req.GetVer()`) satisfies presence and is not an omission;
// whether a present value is a constant or a literal is the other check's
// question.
func verOmissionSites(file *ast.File, messages map[string]bool) []verOmission {
	quals := protoQualifiers(file)
	if len(quals) == 0 {
		return nil
	}
	decoded := decodeTargets(file)
	var out []verOmission
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			if name, ok := verBearingSelector(node.Type, quals, messages); ok && !hasVerKey(node) {
				out = append(out, verOmission{Pos: node.Pos(), Message: name})
			}
		case *ast.ValueSpec:
			if len(node.Values) > 0 {
				return true
			}
			name, ok := verBearingSelector(node.Type, quals, messages)
			if !ok {
				return true
			}
			for _, id := range node.Names {
				if !decoded[id.Name] {
					out = append(out, verOmission{Pos: node.Pos(), Message: name})
					break
				}
			}
		}
		return true
	})
	return out
}

// TestVerIsSingleSourced fails when a production builder stamps a bare string
// literal on a `Ver:` field. Every sender must route through
// helpers.ProtocolVersion, so a protocol bump is one edit here plus a re-pin and
// can never silently skew a subset of authored messages.
func TestVerIsSingleSourced(t *testing.T) {
	t.Parallel() // pure source scan — no shared DB, safe to parallelize.

	root := repoRoot(t)
	var offenders []string
	for _, rel := range appSourceAndTestFiles(t, root) {
		if _, exempt := literalAllowlist[rel]; exempt {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if countVerLiteral(string(src)) > 0 {
			offenders = append(offenders, rel)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("builder(s) stamp a bare Ver string literal in %v — route the version "+
			"through the constant its OWN namespace owns, so a bump flips one constant "+
			"and can never silently skew a subset of authored messages. An RPC envelope "+
			"takes helpers.ProtocolVersion; a /.well-known/ramp.json manifest takes "+
			"rampwellknown.Version. The two read the same value today and the proto says "+
			"they must not be coupled, so reaching for the wrong one is not a no-op",
			offenders)
	}
}

// TestVerIsNeverOmitted fails when a production builder constructs a contract
// message that carries an envelope `ver` without setting the field. Such a
// message goes out with an empty version, which no test catches because nothing
// reads `ver` off an inbound message.
//
// It reads the two syntactic forms a construction takes — see verOmissionSites,
// which is the matcher and is shared with the meta-tests. A file whose
// constructions are decode targets rather than authored messages is named in
// omissionAllowlist with its reason; that distinction is not visible in the
// syntax, so it is stated rather than inferred. Do not relax the match instead,
// which would re-open the omission this check exists to close.
func TestVerIsNeverOmitted(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	messages := verBearingMessages(t)
	fset := token.NewFileSet()

	var offenders []string
	for _, rel := range appSourceAndTestFiles(t, root) {
		if _, exempt := omissionAllowlist[rel]; exempt {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, site := range verOmissionSites(file, messages) {
			offenders = append(offenders, fmt.Sprintf("%s:%d %s",
				rel, fset.Position(site.Pos).Line, site.Message))
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("builder(s) construct a RAMP message without setting Ver, so it ships "+
			"an empty protocol version: %v — a sender MUST stamp ver from "+
			"helpers.ProtocolVersion", offenders)
	}
}

// TestVerAllowlistEntriesAreUsedAndNecessary fails when an entry in EITHER
// allowlist names a file that no longer exists, or one the check it exempts would
// not flag anyway. Without this an entry outlives its cause and quietly exempts a
// file that later starts authoring messages.
func TestVerAllowlistEntriesAreUsedAndNecessary(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	messages := verBearingMessages(t)
	fset := token.NewFileSet()

	for rel, reason := range literalAllowlist {
		if reason == "" {
			t.Errorf("%s: literal-allowlisted with no reason", rel)
		}
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s: literal-allowlisted but unreadable (%v) — drop the entry if the file is gone", rel, err)
			continue
		}
		if countVerLiteral(string(src)) == 0 {
			t.Errorf("%s: literal-allowlisted but carries no bare Ver literal — "+
				"the entry is no longer necessary and should be dropped", rel)
		}
	}

	for rel, reason := range omissionAllowlist {
		if reason == "" {
			t.Errorf("%s: allowlisted with no reason", rel)
		}
		file, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("%s: allowlisted but unreadable (%v) — drop the entry if the file is gone", rel, err)
			continue
		}
		if len(verOmissionSites(file, messages)) == 0 {
			t.Errorf("%s: allowlisted but the check would not flag it — the entry is "+
				"no longer necessary and should be dropped", rel)
		}
	}
}

// TestVerLiteralMatcher_MetaTests pins the literal matcher itself: a bare
// literal in any whitespace or alignment form is detected, while the constant
// and the echo-back GetVer() forms are not — so a formatting variant cannot slip
// past and a sanctioned form cannot false-positive.
func TestVerLiteralMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"positive_bare_literal", `Ver: "1.0",`, 1},
		{"negative_constant", `Ver: helpers.ProtocolVersion,`, 0},
		{"negative_echo_req", `Ver: req.GetVer(),`, 0},
		{"negative_echo_tx", `Ver: txReq.GetVer(),`, 0},
		{"negative_echo_manifest", `Ver: m.GetVer(),`, 0},
		{"negative_similar_field", `Verifier: "x",`, 0},
		// regex-slip: the formatter aligns struct keys with extra spaces or tabs;
		// a literal padded apart from the colon must still be detected.
		{"slip_multi_space", `Ver:               "1.0",`, 1},
		{"slip_tab", "Ver:\t\"1.0\",", 1},
		{"slip_split_across_lines", "Ver:\n\t\t\"1.0\",", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := countVerLiteral(c.src); got != c.want {
				t.Fatalf("countVerLiteral(%q) = %d, want %d", c.src, got, c.want)
			}
		})
	}
}

// TestVerOmissionMatcher_MetaTests pins the omission matcher: a literal that
// sets Ver in any sanctioned form passes, one that omits it is caught, and a
// same-named type from another package is ignored.
func TestVerOmissionMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	messages := verBearingMessages(t)
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"positive_omitted", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.UsageReportResponse{ReportId: "r"}`, 1},
		{"positive_empty_literal", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.UsageReportResponse{}`, 1},
		{"negative_constant", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion}`, 0},
		{"negative_echo", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.TransactionRequest{Ver: req.GetVer()}`, 0},
		{"negative_aliased_import_still_matched", `package p
import pb "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &pb.UsageReportResponse{Ver: helpers.ProtocolVersion}`, 0},
		{"positive_aliased_import_omitted", `package p
import pb "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &pb.UsageReportResponse{ReportId: "r"}`, 1},
		{"negative_other_package_same_name", `package p
import rampv1 "example.com/other"
var _ = &rampv1.UsageReportResponse{ReportId: "r"}`, 0},
		{"negative_message_without_ver", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.TransactionResultItem{}`, 0},
		{"negative_manifest_is_exempt", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
var _ = &rampv1.WellKnownManifest{Domain: "d"}`, 0},
		{"positive_zero_value_declaration", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
func f() { var r rampv1.UsageReportResponse; _ = r }`, 1},
		{"negative_declaration_with_literal_value", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
func f() { var r = rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion}; _ = r }`, 0},
		{"negative_pointer_declaration_constructs_nothing", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
func f() { var r *rampv1.UsageReportResponse; _ = r }`, 0},
		{"negative_declaration_decoded_into", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
func f(b []byte) { var r rampv1.UsageReportResponse; _ = protojson.Unmarshal(b, &r) }`, 0},
		{"positive_declaration_decoded_into_a_different_name", `package p
import rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
func f(b []byte) { var r rampv1.UsageReportResponse; var other rampv1.UsageReport; _ = protojson.Unmarshal(b, &other); _ = r }`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// Drives the SAME matcher the tree scan calls, over a snippet. If the
			// traversal in verOmissionSites breaks, these go red with it — which is
			// the whole reason the matcher is a function and not an inline closure.
			if got := len(verOmissionSites(parseSnippet(t, c.src), messages)); got != c.want {
				t.Fatalf("omission matches = %d, want %d", got, c.want)
			}
		})
	}
}
