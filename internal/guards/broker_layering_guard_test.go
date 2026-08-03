// Broker layering guards: pin the target topology of the broker layering
// pass ("shared SHAPE, not shared PACKAGE" — mirror the Exchange
// thin-adapter→service exemplar locally in the broker).
//
// This is a behavior-preserving refactor: its BEHAVIORAL coverage is the
// existing broker transport integration suite (discover_relay, selection
// audit, replay, batch/denial/repackage/budget, wellknown byte-parity),
// which must pass UNCHANGED. These guards pin only the structural target
// that suite cannot see:
//
//  1. src/broker/internal/relay exists and owns the relay security
//     pipeline + batch fan-out (transport keeps only ServeHTTP adapters
//     and write sinks).
//  2. internal/relay never imports transport and never touches
//     http.ResponseWriter (the sink is inverted to typed returns).
//  3. Neither service composes the well-known manifest+WBA handler pair
//     inline; the compose lives once below both services (root internal/).
//
// The depguard slice (broker-relay-no-transport + fixing the negation-only
// no-circular-internal files list) is lint config, not a test; the
// implementer must prove each new rule bites with a throwaway forbidden
// import before trusting it.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// relayPackageDir is the target home of the broker relay service layer.
const relayPackageDir = "src/broker/internal/relay"

// brokerTransportDir is the thin-adapter layer the pipeline moves OUT of.
const brokerTransportDir = "src/broker/internal/transport"

// brokerTransportImport is the import path internal/relay must never name.
const brokerTransportImport = "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/" + brokerTransportDir

// movedDownSymbols are the pipeline declarations that leave the transport
// package. The guard is a NEGATION on transport ownership: rename-and-move
// satisfies it (transport must simply not declare the symbol any more).
// Deliberately excludes generic or adapter-legit names (serve, serveBatch,
// readBody, audit, forward — the write sinks and orchestration stay in
// transport per the recorded refinement).
var movedDownSymbols = map[string]string{
	// Relay security pipeline (bounded read, SSRF allowlist, sig1
	// verify, replay guard) moves down to internal/relay.
	"verifyAndGuardReplay":      "relay security pipeline",
	"verifyAgentSignature":      "relay security pipeline",
	"endpointAllowed":           "relay security pipeline",
	"preflight":                 "relay security pipeline",
	"unregisteredEndpointError": "relay security pipeline",
	// Batch fan-out moves down to internal/relay (types crossing the
	// boundary move DOWN; serveBatch stays as the transport adapter).
	"batchGroup":              "batch fan-out",
	"fanOutBatch":             "batch fan-out",
	"resolveBatchGroups":      "batch fan-out",
	"resolveBatchEndpoint":    "batch fan-out",
	"mergeBatchResults":       "batch fan-out",
	"collectGroupDenials":     "batch fan-out",
	"contentUnavailableItem":  "batch fan-out",
	"resolveExchangeEndpoint": "batch fan-out",
}

// goSourceFilesUnder yields every non-test, non-generated .go file under
// rel (repo-root-relative), as repo-root-relative paths. A missing
// directory yields nil without failing — existence is asserted separately.
func goSourceFilesUnder(t *testing.T, root, rel string) []string {
	t.Helper()
	dir := filepath.Join(root, rel)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
			strings.HasSuffix(name, ".pb.go") || strings.HasSuffix(name, "connect.go") ||
			strings.Contains(path, string(filepath.Separator)+"sqlc"+string(filepath.Separator)) {
			return nil
		}
		relPath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(relPath))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", rel, err)
	}
	return files
}

// parseGoFile parses a repo-root-relative Go file.
func parseGoFile(t *testing.T, root, rel string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return f
}

// topLevelDeclNames collects every top-level func/method, type, const, and
// var name declared in the file. Method names are included (the pipeline
// substance is mostly methods on relayCore/ExchangeRelayHandler).
func topLevelDeclNames(f *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			names[decl.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					names[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names[n.Name] = true
					}
				}
			}
		}
	}
	return names
}

// astReferencesIdent reports whether any identifier in the file has the
// given name. Ident-anchored (not import-alias-anchored), so an aliased
// import (nh.ResponseWriter, srv.NewWBAHandler) or a dot-import cannot
// slip it.
func astReferencesIdent(f *ast.File, name string) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

// TestBrokerRelayServiceLayerExists fails while the broker has no
// internal/relay package — i.e. while the relay security pipeline and the
// batch fan-out still live in the transport package. The Exchange exemplar
// (and the broker's own internal/resolve) is a real package with non-test
// source files.
func TestBrokerRelayServiceLayerExists(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	files := goSourceFilesUnder(t, root, relayPackageDir)
	if len(files) == 0 {
		t.Errorf("%s has no non-test Go source files — the broker relay service layer "+
			"(relay security pipeline + batch fan-out) must live there, mirroring "+
			"src/broker/internal/resolve; transport keeps only ServeHTTP adapters and write sinks",
			relayPackageDir)
	}
}

// TestRelayPipelineSymbolsLeftTransport fails while the transport package
// still DECLARES the relay-pipeline / batch-fan-out substance. The guard is
// ownership-negative: moving a symbol down (renamed or not) satisfies it;
// keeping it in transport does not.
func TestRelayPipelineSymbolsLeftTransport(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range goSourceFilesUnder(t, root, brokerTransportDir) {
		decls := topLevelDeclNames(parseGoFile(t, root, rel))
		for sym, group := range movedDownSymbols {
			if decls[sym] {
				t.Errorf("%s declares %s (%s) — that logic moves DOWN to %s; "+
					"transport keeps only ServeHTTP adapters and write sinks",
					rel, sym, group, relayPackageDir)
			}
		}
	}
}

// TestRelayPackagePurity pins the target invariants of internal/relay for
// every source file it gains: it never imports the transport package (the
// dependency points transport→relay only) and never names
// http.ResponseWriter (the write sink is inverted to typed
// result/*broker.Error returns; transport owns every write). Vacuously
// green while the package is absent — TestBrokerRelayServiceLayerExists
// owns existence.
func TestRelayPackagePurity(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range goSourceFilesUnder(t, root, relayPackageDir) {
		f := parseGoFile(t, root, rel)
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == brokerTransportImport {
				t.Errorf("%s imports the broker transport package — internal/relay must never "+
					"import transport (ports are locally-owned structural interfaces; "+
					"types crossing the boundary move down)", rel)
			}
		}
		if astReferencesIdent(f, "ResponseWriter") {
			t.Errorf("%s references ResponseWriter — internal/relay receives NO "+
				"http.ResponseWriter; return typed results/*broker.Error and let the "+
				"transport adapter own every write", rel)
		}
	}
}

// TestWellKnownComposeLivesBelowServices fails while either service still
// composes the well-known manifest+WBA handler pair inline (the
// server.NewHandler+server.NewWBAHandler sequence). The compose is written
// ONCE below both services — under root internal/ (a wellknownbuild
// builder, or folded into internal/rampwellknown/server) — and the
// services call the builder. Anchored on NewWBAHandler: the inline compose
// always names it, the builder call never does.
func TestWellKnownComposeLivesBelowServices(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, top := range []string{"src/broker", "src/exchange"} {
		for _, rel := range goSourceFilesUnder(t, root, top) {
			if astReferencesIdent(parseGoFile(t, root, rel), "NewWBAHandler") {
				t.Errorf("%s composes the well-known WBA handler inline — compose "+
					"manifest+WBA once in the shared builder under root internal/ "+
					"(wellknownbuild) and call that from both services", rel)
			}
		}
	}
}

// --- meta-tests: prove the detectors themselves work -----------------------

// parseSnippet parses an in-memory Go source snippet.
func parseSnippet(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "snippet.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse snippet: %v", err)
	}
	return f
}

// TestMeta_ResponseWriterDetectorCatchesAliasedImport is the positive
// meta-test: an aliased net/http import must not slip the ResponseWriter
// detector (it is ident-anchored, not alias-anchored).
func TestMeta_ResponseWriterDetectorCatchesAliasedImport(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport nh \"net/http\"\n\nfunc sink(w nh.ResponseWriter) {}\n")
	if !astReferencesIdent(f, "ResponseWriter") {
		t.Fatal("detector missed an aliased nh.ResponseWriter parameter — alias-slip regression")
	}
}

// TestMeta_ResponseWriterDetectorPassesTypedReturns is the negative
// meta-test: the sanctioned inverted shape (typed result/error returns,
// plain net/http request usage) must NOT match.
func TestMeta_ResponseWriterDetectorPassesTypedReturns(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport \"net/http\"\n\n"+
		"func preflight(r *http.Request) ([]byte, error) { return nil, nil }\n")
	if astReferencesIdent(f, "ResponseWriter") {
		t.Fatal("detector wrongly flagged the sanctioned typed-return shape")
	}
}

// TestMeta_WBAComposeDetectorCatchesAliasedCall is the positive meta-test
// for the well-known compose detector: an aliased server import must still
// match.
func TestMeta_WBAComposeDetectorCatchesAliasedCall(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport srv \"example.com/server\"\n\n"+
		"func compose() { _, _ = srv.NewWBAHandler(srv.WBAConfig{}) }\n")
	if !astReferencesIdent(f, "NewWBAHandler") {
		t.Fatal("detector missed an aliased srv.NewWBAHandler call — alias-slip regression")
	}
}

// TestMeta_WBAComposeDetectorPassesBuilderCall is the negative meta-test:
// calling the shared builder must NOT match.
func TestMeta_WBAComposeDetectorPassesBuilderCall(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport \"example.com/wellknownbuild\"\n\n"+
		"func compose() { _, _ = wellknownbuild.Build(nil, nil, \"\") }\n")
	if astReferencesIdent(f, "NewWBAHandler") {
		t.Fatal("detector wrongly flagged the sanctioned shared-builder call")
	}
}
