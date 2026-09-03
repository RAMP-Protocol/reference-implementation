// Third half of the RAMP protocol-version guards -- the one the other two, and
// every round-trip assertion, are blind to.
//
// The sibling file bans a bare literal and a missing field. Neither says anything
// about WHICH constant a builder stamps, and the case that matters shares a value
// with the right one: internal/rampwellknown.Version reads "1.0" today, exactly
// like helpers.ProtocolVersion. Stamp the manifest-schema version on an RPC
// envelope and the bytes are identical, so the integration assertions pass, the
// literal check passes, and the omission check passes. It was verified to pass
// all of them before this check existed.
//
// It is not harmless. ramp.proto states the two are separate namespaces and must
// not be coupled: the /.well-known/ramp.json document version carries a MUST-equal
// rule and is rejected outright when it differs, while the envelope version is
// advisory. They agree today and would silently diverge the day either moves,
// with nothing failing at the moment the coupling was introduced.
//
// The coupling has two directions and this check reads both. An envelope stamped
// from the manifest is caught by requiring an echo's receiver to be an envelope
// message the enclosing function actually declares -- a bare `X.GetVer()` sanctions
// whatever X happens to be, and a manifest is exactly what would be in scope on the
// paths that fetch one. A manifest stamped from helpers.ProtocolVersion is caught by
// holding manifest constructions to rampwellknown.Version, under both spellings:
// the generated rampv1.WellKnownManifest and the rampwellknown.Manifest alias most
// callers use. Only the second spelling is common in this tree, and the alias
// qualifier is not a generated package, so a check scoped to the envelope message
// set could not see it at all.
//
// Only source can see any of this, which is why it is a structural check.
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"testing"
)

// rampwellknownPath is the package that owns the manifest document-schema version
// and the Manifest alias for the generated message.
const rampwellknownPath = "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"

// manifestAlias is what rampwellknown re-exports rampv1.WellKnownManifest as. Most
// constructions in this tree use it rather than the generated name.
const manifestAlias = "Manifest"

// manifestVersionConst is the only value a manifest may stamp.
const manifestVersionConst = "Version"

// verScope is what one file supplies to the value check: which identifiers resolve
// to which package, which message names carry an envelope `ver`, and the file's own
// package, so a construction inside rampwellknown may name its constant unqualified.
type verScope struct {
	proto     map[string]bool
	manifest  map[string]bool
	messages  map[string]bool
	inPackage string
}

// verConstantOffence is one `Ver:` key set from a value its namespace does not own.
type verConstantOffence struct {
	Pos      token.Pos
	Value    string
	Manifest bool
}

// manifestQualifiers maps each identifier in file that refers to rampwellknown
// onto true, resolving whatever alias the file chose.
func manifestQualifiers(file *ast.File) map[string]bool {
	return qualifiersFor(file, rampwellknownPath)
}

// manifestSelector reports whether expr names the well-known manifest, under
// either spelling: the generated rampv1.WellKnownManifest or the rampwellknown.Manifest
// alias.
func manifestSelector(expr ast.Expr, sc verScope) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return (sc.proto[pkg.Name] && sel.Sel.Name == manifestMessage) ||
		(sc.manifest[pkg.Name] && sel.Sel.Name == manifestAlias)
}

// sanctionedManifestValue reports whether v is rampwellknown.Version -- qualified,
// or bare inside the package that declares it.
func sanctionedManifestValue(v ast.Expr, sc verScope) bool {
	switch e := v.(type) {
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		return ok && sc.manifest[pkg.Name] && e.Sel.Name == manifestVersionConst
	case *ast.Ident:
		return sc.inPackage == "rampwellknown" && e.Name == manifestVersionConst
	}
	return false
}

// sanctionedVerValue reports whether an envelope `Ver:` value is one this project
// may stamp: the SDK constant, or an echo relaying an inbound peer's own version.
// Everything else -- another package's constant, a local one, a concatenation --
// is a second owner of a value the protocol repo owns.
//
// The echo arm checks the RECEIVER, not just the method name. `GetVer` is generated
// on every ver-bearing message including the manifest, so sanctioning the call by
// name alone lets `Ver: manifest.GetVer()` couple the two namespaces on an envelope.
// envelopes holds the names the enclosing function declares as envelope messages;
// anything else relaying a version is not an echo of the caller's own contract.
func sanctionedVerValue(v ast.Expr, envelopes map[string]bool) bool {
	switch e := v.(type) {
	case *ast.SelectorExpr: // helpers.ProtocolVersion
		pkg, ok := e.X.(*ast.Ident)
		return ok && pkg.Name == "helpers" && e.Sel.Name == "ProtocolVersion"
	case *ast.CallExpr: // req.GetVer() — relaying a peer's own version
		fn, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || fn.Sel.Name != "GetVer" {
			return false
		}
		recv, ok := fn.X.(*ast.Ident)
		return ok && envelopes[recv.Name]
	}
	return false
}

// envelopeType reports whether expr is a (possibly pointer) reference to a
// ver-bearing envelope message.
func envelopeType(expr ast.Expr, sc verScope) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	_, ok := verBearingSelector(expr, sc.proto, sc.messages)
	return ok
}

// envelopeTypedNames returns the identifiers fn declares whose type is a ver-bearing
// envelope message: its receiver, its parameters, and any local `var x rampv1.X`.
// Those are the only receivers an echo may legitimately read a version from.
func envelopeTypedNames(fn *ast.FuncDecl, sc verScope) map[string]bool {
	out := map[string]bool{}
	fields := []*ast.Field{}
	if fn.Recv != nil {
		fields = append(fields, fn.Recv.List...)
	}
	if fn.Type.Params != nil {
		fields = append(fields, fn.Type.Params.List...)
	}
	for _, f := range fields {
		if !envelopeType(f.Type, sc) {
			continue
		}
		for _, name := range f.Names {
			out[name.Name] = true
		}
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || spec.Type == nil || !envelopeType(spec.Type, sc) {
			return true
		}
		for _, name := range spec.Names {
			out[name.Name] = true
		}
		return true
	})
	return out
}

// verValueOf returns the expression a composite literal binds to Ver, and whether
// the key is present at all. A quoted string is reported as absent: that edit
// belongs to the literal check, so one mistake is never reported twice.
func verValueOf(lit *ast.CompositeLit) (ast.Expr, bool) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Ver" {
			continue
		}
		if basic, isLit := kv.Value.(*ast.BasicLit); isLit && basic.Kind == token.STRING {
			return nil, false
		}
		return kv.Value, true
	}
	return nil, false
}

// verOffencesIn reports every `Ver:` key inside node whose value its namespace does
// not own. envelopes names the identifiers an echo may read from, which is empty
// outside a function body.
func verOffencesIn(node ast.Node, sc verScope, envelopes map[string]bool) []verConstantOffence {
	var out []verConstantOffence
	ast.Inspect(node, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		isManifest := manifestSelector(lit.Type, sc)
		_, isEnvelope := verBearingSelector(lit.Type, sc.proto, sc.messages)
		if !isManifest && !isEnvelope {
			return true
		}
		value, present := verValueOf(lit)
		if !present {
			return true
		}
		sanctioned := sanctionedVerValue(value, envelopes)
		if isManifest {
			sanctioned = sanctionedManifestValue(value, sc)
		}
		if !sanctioned {
			out = append(out, verConstantOffence{
				Pos: value.Pos(), Value: types.ExprString(value), Manifest: isManifest,
			})
		}
		return true
	})
	return out
}

// verWrongConstantSites returns every `Ver:` key on a message this guard owns whose
// value belongs to the other namespace, or to no owner at all.
func verWrongConstantSites(file *ast.File, messages map[string]bool) []verConstantOffence {
	sc := verScope{
		proto:     protoQualifiers(file),
		manifest:  manifestQualifiers(file),
		messages:  messages,
		inPackage: file.Name.Name,
	}
	if len(sc.proto) == 0 && len(sc.manifest) == 0 {
		return nil
	}
	var out []verConstantOffence
	for _, decl := range file.Decls {
		envelopes := map[string]bool{}
		if fn, ok := decl.(*ast.FuncDecl); ok {
			envelopes = envelopeTypedNames(fn, sc)
		}
		out = append(out, verOffencesIn(decl, sc, envelopes)...)
	}
	return out
}

// TestVerStampsTheSDKConstant fails when a builder sets a version from the wrong
// namespace's constant: an envelope from anything but helpers.ProtocolVersion or an
// echo of an inbound envelope, or a manifest from anything but rampwellknown.Version.
func TestVerStampsTheSDKConstant(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	messages := verBearingMessages(t)
	fset := token.NewFileSet()

	var envelopes, manifests []string
	for _, rel := range appSourceAndTestFiles(t, root) {
		if _, exempt := literalAllowlist[rel]; exempt {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, site := range verWrongConstantSites(file, messages) {
			line := fmt.Sprintf("%s:%d Ver: %s", rel, fset.Position(site.Pos).Line, site.Value)
			if site.Manifest {
				manifests = append(manifests, line)
			} else {
				envelopes = append(envelopes, line)
			}
		}
	}
	if len(envelopes) > 0 {
		t.Errorf("builder(s) stamp an RPC envelope Ver from something other than "+
			"helpers.ProtocolVersion: %v — the envelope version has one owner, and the "+
			"/.well-known/ramp.json document version is a separate namespace the proto "+
			"says must not be coupled to it", envelopes)
	}
	if len(manifests) > 0 {
		t.Errorf("builder(s) stamp a well-known manifest Ver from something other than "+
			"rampwellknown.Version: %v — the manifest versions the document SCHEMA, and "+
			"the RPC envelope version is a separate namespace; the two read the same "+
			"value today and would diverge silently the day either moves", manifests)
	}
}

// metaSrc wraps a `Ver:` field in a minimal envelope-message construction, so
// each case below states only the value under test.
func metaSrc(field string) string {
	return "package p\n" +
		"import rampv1 \"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1\"\n" +
		"var _ = &rampv1.UsageReport{" + field + "}"
}

// metaEchoSrc wraps the same construction in a function taking recvType, so the
// echo arm can be exercised against a receiver whose type the file declares.
func metaEchoSrc(recvType, field string) string {
	return "package p\n" +
		"import rampv1 \"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1\"\n" +
		"import \"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown\"\n" +
		"func f(src " + recvType + ") { _ = &rampv1.UsageReport{" + field + "} }"
}

// metaManifestSrc constructs a manifest under the given spelling.
func metaManifestSrc(typeName, field string) string {
	return "package p\n" +
		"import rampv1 \"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1\"\n" +
		"import \"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown\"\n" +
		"var _ = &" + typeName + "{" + field + "}"
}

// TestVerConstantMatcher_MetaTests pins the matcher, including the two crossings
// that motivate the whole check: a constant from the wrong namespace carrying the
// right value, in each direction.
func TestVerConstantMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	messages := verBearingMessages(t)
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"negative_sdk_constant", metaSrc(`Ver: helpers.ProtocolVersion`), 0},
		{"negative_literal_belongs_to_the_other_check", metaSrc(`Ver: "1.0"`), 0},
		{"positive_wrong_namespace_same_value", metaSrc(`Ver: rampwellknown.Version`), 1},
		{"positive_local_constant", metaSrc(`Ver: myVer`), 1},
		{"positive_concatenation", metaSrc(`Ver: helpers.ProtocolVersion + "-dev"`), 1},

		// The echo arm. A request parameter is the shape both production echo sites
		// have; a manifest parameter is the crossing the receiver check exists for.
		{
			"negative_echo_from_a_request_parameter",
			metaEchoSrc("*rampv1.TransactionRequest", `Ver: src.GetVer()`), 0,
		},
		{
			"positive_echo_from_a_manifest_parameter",
			metaEchoSrc("*rampwellknown.Manifest", `Ver: src.GetVer()`), 1,
		},
		{
			"positive_echo_from_an_undeclared_receiver",
			metaSrc(`Ver: req.GetVer()`), 1,
		},

		// The manifest direction, under both spellings.
		{
			"negative_manifest_keeps_its_own_constant",
			metaManifestSrc("rampv1.WellKnownManifest", `Ver: rampwellknown.Version`), 0,
		},
		{
			"negative_manifest_alias_keeps_its_own_constant",
			metaManifestSrc("rampwellknown.Manifest", `Ver: rampwellknown.Version`), 0,
		},
		{
			"positive_manifest_stamped_from_the_sdk_constant",
			metaManifestSrc("rampv1.WellKnownManifest", `Ver: helpers.ProtocolVersion`), 1,
		},
		{
			"positive_manifest_alias_stamped_from_the_sdk_constant",
			metaManifestSrc("rampwellknown.Manifest", `Ver: helpers.ProtocolVersion`), 1,
		},
		{
			"negative_manifest_literal_belongs_to_the_other_check",
			metaManifestSrc("rampwellknown.Manifest", `Ver: "1.0"`), 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := len(verWrongConstantSites(parseSnippet(t, c.src), messages)); got != c.want {
				t.Fatalf("wrong-constant matches = %d, want %d", got, c.want)
			}
		})
	}
}
