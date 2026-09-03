// This file pins the PRODUCER half of the canonical snake_case JSON encoding:
// every hand-written protojson marshal in this repository chooses the naming
// explicitly, rather than inheriting protojson's default.
//
// This is where the defect that prompted the whole property actually lived. The
// identity service's execute relay called bare protojson.Marshal on a plain HTTP
// route and posted camelCase field names to the Broker. No Connect mount was
// involved, so the mount half in wirecodec_guard_test.go would not have caught
// it and will not catch the next one.
//
// Nothing noticed at the time, because a Go peer reads both spellings. A reader
// built from the generated Pydantic or Zod schemas does not: those declare proto
// names only and drop what they do not recognise, so an aliased body parses into
// a message with the aliased fields missing and reports nothing wrong.
//
// Scope: every non-generated .go file under src/ and internal/, FIXTURES
// INCLUDED. That is not thoroughness for its own sake. Seven of the calls this
// widening found build a request body and POST it to the Broker's real relay
// routes, which is the same wire the relay defect above was on — so while the
// production side was being fixed, every test of that route went on feeding the
// receiver the other spelling, and nothing drove it end to end in the one
// production emits. A guard that read production only could not have said so.
package guards

import (
	"go/ast"
	"testing"
)

const protojsonPath = "google.golang.org/protobuf/encoding/protojson"

// TestEveryProtoJSONProducerPinsProtoNames fails when a hand-written proto-JSON
// producer leaves the field naming to protojson's default.
//
// The mount half above covers Connect handlers, which is not where the defect
// this file exists for was found. That one was a plain HTTP route: the identity
// service's execute relay called bare protojson.Marshal and posted camelCase
// field names to the Broker, and nothing noticed because the Broker decodes both
// spellings. No Connect mount was involved, so a check that reads only mounts
// would not have caught it and will not catch the next one.
//
// Unmarshal is untouched on purpose — reading accepts both spellings either way,
// and it is only what a producer WRITES that a snake-only reader can lose.
func TestEveryProtoJSONProducerPinsProtoNames(t *testing.T) {
	t.Parallel()
	forEachProtoJSONFile(t, func(rel string, f *ast.File, quals map[string]bool) {
		for _, lit := range marshalOptionLiterals(f, quals) {
			if !litSetsField(lit, "UseProtoNames") {
				t.Errorf("%s: a protojson.MarshalOptions literal does not set UseProtoNames, "+
					"so it writes the camelCase json_name alias — the RAMP wire is snake_case "+
					"proto-JSON and a reader built from the generated Pydantic or Zod schemas "+
					"drops what it does not recognise", rel)
			}
		}
	})
}

// TestNoBareProtoJSONMarshal forbids protojson.Marshal itself. The package-level
// function takes no options, so calling it IS the decision to accept the default
// naming, and it reads like a neutral encode rather than a choice.
//
// There is no allowlist, and the two calls with the best claim to one do not
// have it. Both marshal a structpb.Struct, whose members are the schema author's
// own keys rather than proto field names, so the option has nothing to rename
// and the bytes are identical either way — measured. They set it anyway, for the
// same reason the production site next to them does: a rule with one sanctioned
// exception is a rule the next reader argues from.
func TestNoBareProtoJSONMarshal(t *testing.T) {
	t.Parallel()
	forEachProtoJSONFile(t, func(rel string, f *ast.File, quals map[string]bool) {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isQualifiedCall(call, quals, "Marshal") {
				return true
			}
			t.Errorf("%s: protojson.Marshal takes no options, so it writes the camelCase "+
				"json_name alias. Marshal through protojson.MarshalOptions{UseProtoNames: true} "+
				"instead — set it even where it changes nothing, so the rule has no exception", rel)
			return true
		})
	})
}

// forEachProtoJSONFile hands fn every file that imports protojson, together
// with the local names it bound for it, and fails when NO file does.
//
// The empty-scan check is the point of routing both producer checks through one
// helper. Each is a ban: it reports what it finds and says nothing when it finds
// nothing, so a resolver that stopped resolving would leave both passing over a
// tree they were no longer reading. The mount half in wirecodec_guard_test.go
// counts its subject for the same reason.
func forEachProtoJSONFile(t *testing.T, fn func(rel string, f *ast.File, quals map[string]bool)) {
	t.Helper()
	found := 0
	forEachAppAndTestFile(t, func(rel string, f *ast.File) {
		quals := qualifiersFor(f, protojsonPath)
		if len(quals) == 0 {
			return
		}
		found++
		fn(rel, f, quals)
	})
	if found == 0 {
		t.Fatal("no file importing protojson matched — the detector has stopped seeing them, " +
			"so this guard is passing without checking anything")
	}
}

// marshalOptionLiterals returns every protojson.MarshalOptions composite literal
// in f, under whatever alias the file binds the import to.
func marshalOptionLiterals(f *ast.File, quals map[string]bool) []*ast.CompositeLit {
	var found []*ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "MarshalOptions" {
			return true
		}
		if pkg, isPkg := sel.X.(*ast.Ident); isPkg && quals[pkg.Name] {
			found = append(found, lit)
		}
		return true
	})
	return found
}

// litSetsField reports whether lit names field as a keyed element. Only the
// keyed form is read: protojson.MarshalOptions is a large struct nobody fills
// positionally, and a positional literal would not compile against a version
// that adds a field.
func litSetsField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, isIdent := kv.Key.(*ast.Ident); isIdent && key.Name == field {
			return true
		}
	}
	return false
}

// isQualifiedCall reports whether call invokes sel on one of quals — pkg.Sel(…)
// and nothing else. A method call on a VALUE of that package's type, such as an
// options variable's own Marshal, has an identifier that is not a package name
// and is left alone: those options were checked where the literal was written.
func isQualifiedCall(call *ast.CallExpr, quals map[string]bool, sel string) bool {
	fun, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || fun.Sel.Name != sel {
		return false
	}
	pkg, isPkg := fun.X.(*ast.Ident)
	return isPkg && quals[pkg.Name]
}

// producerSource wraps a body in a compilable file importing protojson under
// whatever alias a caller chose.
func producerSource(alias, body string) string {
	return "package p\n\nimport (\n\t" + alias + " \"" + protojsonPath + "\"\n)\n\nfunc encode() {\n" + body + "\n}\n"
}

// producerFindings runs both producer checks over one synthetic file and reports
// what each concluded: the number of MarshalOptions literals missing
// UseProtoNames, and the number of bare package-level Marshal calls.
func producerFindings(t *testing.T, src string) (unpinned, bare int) {
	t.Helper()
	f := parseSnippet(t, src)
	quals := qualifiersFor(f, protojsonPath)
	for _, lit := range marshalOptionLiterals(f, quals) {
		if !litSetsField(lit, "UseProtoNames") {
			unpinned++
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isQualifiedCall(call, quals, "Marshal") {
			bare++
		}
		return true
	})
	return unpinned, bare
}

// TestMeta_ProducerDetectorFlagsAnUnpinnedLiteral is the positive case for the
// options half, written multi-line and through an alias — the two forms a
// text match would walk past.
func TestMeta_ProducerDetectorFlagsAnUnpinnedLiteral(t *testing.T) {
	t.Parallel()
	src := producerSource("pj", `	mo := pj.MarshalOptions{
		EmitUnpopulated: true,
	}
	_, _ = mo.Marshal(nil)`)
	unpinned, bare := producerFindings(t, src)
	if unpinned != 1 {
		t.Errorf("found %d unpinned literals, want 1", unpinned)
	}
	if bare != 0 {
		t.Errorf("found %d bare marshals in a file that has none", bare)
	}
}

// TestMeta_ProducerDetectorPassesAPinnedLiteral is the negative case. Without it
// the test above is satisfied by a check that reports every literal.
func TestMeta_ProducerDetectorPassesAPinnedLiteral(t *testing.T) {
	t.Parallel()
	src := producerSource("protojson", `	_, _ = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(nil)`)
	if unpinned, _ := producerFindings(t, src); unpinned != 0 {
		t.Errorf("found %d unpinned literals in a pinned file, want none", unpinned)
	}
}

// TestMeta_ProducerDetectorFlagsABareMarshal is the positive case for the other
// half: the exact call the execute relay used to make.
func TestMeta_ProducerDetectorFlagsABareMarshal(t *testing.T) {
	t.Parallel()
	src := producerSource("pj", `	_, _ = pj.Marshal(nil)`)
	if _, bare := producerFindings(t, src); bare != 1 {
		t.Errorf("found %d bare marshals, want 1", bare)
	}
}

// TestMeta_ProducerDetectorIgnoresUnmarshalAndMethodCalls is the discriminating
// case. Unmarshal reads, and reading accepts both spellings, so flagging it
// would be wrong. A Marshal on an options VALUE is likewise not the bare call —
// those options were already checked where their literal was written.
func TestMeta_ProducerDetectorIgnoresUnmarshalAndMethodCalls(t *testing.T) {
	t.Parallel()
	src := producerSource("protojson", `	_ = protojson.Unmarshal(nil, nil)
	mo := protojson.MarshalOptions{UseProtoNames: true}
	_, _ = mo.Marshal(nil)`)
	unpinned, bare := producerFindings(t, src)
	if bare != 0 {
		t.Errorf("flagged %d calls that are not a bare protojson.Marshal, want none", bare)
	}
	if unpinned != 0 {
		t.Errorf("flagged %d pinned literals, want none", unpinned)
	}
}
