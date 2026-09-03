// Structural guard: each registration schema is compiled in exactly one place,
// and the environment variable that carries the Exchange's own is read in
// exactly one place.
//
// There are TWO schemas in this repository and they belong to different
// parties, so there are two one-place rules rather than one rule with two
// entries. The Exchange compiles the schema its OPERATOR configured, and
// publishing it commits the Exchange to enforcing it. The identity adapter
// compiles a schema it FETCHED from a third-party Exchange, to warn an agent
// before signing. Same SDK call, different document, different owner, different
// failure if it is done twice — so an allowlist shared between them would let a
// second Exchange-side compile hide behind the identity entry.
//
// The configured schema has two readers — the manifest that publishes it as
// account_registration.data_schema, and the Register gate that checks an
// incoming registration_data against it. Publishing a schema is a commitment to
// enforce that schema, so the two must be the same document; an Exchange
// advertising one shape while refusing on another is wrong in a way neither
// reader can detect from where it stands. Both readers now take the value
// loadRegistrationConfig produced, which is what this guard keeps true.
//
// The terms digest the Exchange publishes has the same two readers and the same
// failure. The manifest serves it as terms_digest and the Register gate refuses
// a registration that names a different revision, so an Exchange advertising one
// revision while checking against another is wrong in the same undetectable way.
// It is configuration rather than a compiled document, so it has no Load call to
// watch — the environment read IS its only route to a second value, and that
// route is watched here beside the schema's.
//
// regschema.Load produces both forms from one document, so a single call
// satisfies both readers. What this file forbids is every route to a SECOND
// value. There are three, and a guard that closed only the first would report a
// clean tree while the other two stood open:
//
//  1. a second regschema.Load call;
//  2. a direct helpers.CompileRegistrationSchema call, which is what Load is
//     made of and is one import away in any file in this repo;
//  3. a second read of EXCHANGE_REGISTRATION_SCHEMA or of EXCHANGE_TERMS_DIGEST,
//     which is how a second value gets its input.
//
// Each route has its own detector, its own allowlist of exactly one file, and
// its own meta-tests, so each has been seen to fire and to stay quiet. The
// environment route runs every one of its detector and rule meta-tests over BOTH
// variables: a second detector with fewer meta-tests behind it than the one
// beside it is a weaker guard wearing the same name.
package guards

import (
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sdkHelpersImportPath is the SDK package whose compile face regschema.Load is
// made of. Most of this repo imports it for other reasons, which is exactly why
// a direct call to this one function needs its own detector.
const sdkHelpersImportPath = "github.com/RAMP-Protocol/protocol/sdk/go/helpers"

// regschemaImportPath is the package that owns loading. A caller names it in an
// import, whatever local name it then binds.
const regschemaImportPath = "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"

// exchregImportPath is the package that owns reading another Exchange's
// published requirements. Watched for the same reason regschema is: a caller
// that dot-imported it would make its references invisible to every qualified
// matcher in this file.
const exchregImportPath = "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchreg"

// regschemaLoadRoot is the one file sanctioned to load the schema: the
// Exchange's composition root, which hands the loaded value to both readers.
const regschemaLoadRoot = "src/exchange/cmd/server/registration.go"

// exchangeCompileHome is the one file under src/exchange sanctioned to call the
// SDK's compile face. Its call count is deliberately unbounded: the two compiles
// it makes — one over the operator's bytes, one over the bytes about to be
// served — build a single Schema value, which is the opposite of the divergence
// this guard is about. What matters is that no OTHER file in that tree compiles
// at all.
const exchangeCompileHome = "src/exchange/internal/regschema/regschema.go"

// fetchedCompileHome is the one file sanctioned to compile a schema this
// repository did not configure: the one an identity agent's target Exchange
// publishes. It is a separate rule from the Exchange's rather than a second
// entry on it, because the two answer different questions — "does this Exchange
// have one answer to what it enforces" and "does the adapter have one place
// where third-party input is compiled".
const fetchedCompileHome = "src/identity/internal/exchreg/schema.go"

// countIsWrong reports whether n uses in rel break the one-place rule: the
// sanctioned file holds exactly one, every other file none.
//
// Zero in the sanctioned file is a failure, not a pass. A guard that only
// objected to a SECOND use would stay quiet after a rename of the variable or a
// deletion of the load — the tree would then have no load at all and a green
// gate saying it had exactly one.
func countIsWrong(rel, allowed string, n int) bool {
	if rel == allowed {
		return n != 1
	}
	return n > 0
}

// the file's own comment says the value is read once.
func TestRegistrationSchemaLoadedOnce(t *testing.T) {
	t.Parallel()
	forEachAppFile(t, func(rel string, f *ast.File) {
		n := countSelectorCalls(f, regschemaImportPath, "Load")
		if !countIsWrong(rel, regschemaLoadRoot, n) {
			return
		}
		if rel == regschemaLoadRoot {
			t.Errorf("%s calls regschema.Load %d times, want exactly 1 — the registration schema is loaded ONCE and the single value is handed to both the manifest and the Register gate. Zero calls fails here too: the schema would then be loaded nowhere.", rel, n)
			return
		}
		t.Errorf("%s calls regschema.Load — the registration schema is loaded once, at %s, and handed to both the manifest and the Register gate. Take the already-loaded value instead of reading it again.", rel, regschemaLoadRoot)
	})
}

// TestExchangeRegistrationSchemaCompiledOnlyInsideItsLoader fails when any file
// under src/exchange other than the loader calls the SDK's compile face
// directly. That call is the whole body of regschema.Load, the SDK is imported
// by most of this repo, and a caller reaching it produces a second compiled
// schema without ever naming the package the load-once rule is written about.
//
// Bounded to src/exchange, and the bound is not a weakening. The rule is that
// this Exchange has ONE compiled answer to what it enforces, because publishing
// a schema commits it to enforcing that schema. A file compiling a schema it
// fetched from somebody else's Exchange is a different document with a
// different owner; it cannot become a second answer to what this Exchange
// enforces, and it has its own one-place rule below.
func TestExchangeRegistrationSchemaCompiledOnlyInsideItsLoader(t *testing.T) {
	t.Parallel()
	forEachAppFile(t, func(rel string, f *ast.File) {
		if rel == exchangeCompileHome || !strings.HasPrefix(rel, "src/exchange/") {
			return
		}
		if countSelectorCalls(f, sdkHelpersImportPath, "CompileRegistrationSchema") > 0 {
			t.Errorf("%s calls helpers.CompileRegistrationSchema directly — compiling is %s's job, and a second compiled schema is a second answer to what this Exchange enforces. Call regschema.Load, or take the value it already produced.", rel, exchangeCompileHome)
		}
	})
}

// TestFetchedRegistrationSchemaCompiledOnlyInsideItsReader fails when a schema
// fetched from another party's manifest is compiled anywhere but the one file
// that owns doing it.
//
// A published data_schema is attacker-influenced input: it arrives from a
// third-party Exchange an authenticated agent named. Everything that makes
// compiling it safe — the SDK's caps, discarding a refused verdict's validator
// so a nil one reports no failures, and paying the bounded compile at most once
// per distinct document — lives in that file. A second call site anywhere else
// re-decides all three, and the way it fails is silent: a locally-refused
// payload the Exchange would have taken.
//
// Zero calls in the sanctioned file fails too. A pre-check that was deleted or
// a file that was renamed would otherwise leave the tree compiling nothing and
// a green gate saying it compiles in exactly one place.
func TestFetchedRegistrationSchemaCompiledOnlyInsideItsReader(t *testing.T) {
	t.Parallel()
	forEachAppFile(t, func(rel string, f *ast.File) {
		if strings.HasPrefix(rel, "src/exchange/") {
			return
		}
		n := countSelectorCalls(f, sdkHelpersImportPath, "CompileRegistrationSchema")
		if !countIsWrong(rel, fetchedCompileHome, n) {
			return
		}
		if rel == fetchedCompileHome {
			t.Errorf("%s calls helpers.CompileRegistrationSchema %d times, want exactly 1 — a schema fetched from another party's manifest is compiled in ONE place, where the refusal handling and the per-document memo live. Zero calls fails here too: the adapter would then pre-check nothing.", rel, n)
			return
		}
		t.Errorf("%s calls helpers.CompileRegistrationSchema — compiling a FETCHED schema is %s's job. Take the Requirements it already produced; a second call site re-decides how a refused verdict is handled and pays the bounded compile again.", rel, fetchedCompileHome)
	})
}

// --- meta-tests: prove each detector fires, and stays quiet on clean source --

// TestMeta_RegschemaLoadDetectorCatchesAnAliasedImport is the positive
// meta-test for the load detector, driven through the form a source-text match
// misses: the import is aliased, so the call never spells the package name.
func TestMeta_RegschemaLoadDetectorCatchesAnAliasedImport(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport rs \""+regschemaImportPath+"\"\n\n"+
		"func wire() { _, _ = rs.Load(\"\") }\n")
	if got := countSelectorCalls(f, regschemaImportPath, "Load"); got != 1 {
		t.Fatalf("detector counted %d aliased regschema.Load calls, want 1 — alias-slip regression", got)
	}
}

// TestMeta_RegschemaLoadDetectorCatchesADotImport is the other form the source
// text cannot show: a dot-import leaves the call as a bare Load(.
func TestMeta_RegschemaLoadDetectorCatchesADotImport(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport . \""+regschemaImportPath+"\"\n\n"+
		"func wire() { _, _ = Load(\"\") }\n")
	if got := countSelectorCalls(f, regschemaImportPath, "Load"); got != 1 {
		t.Fatalf("detector counted %d dot-imported Load calls, want 1", got)
	}
}

// TestMeta_RegschemaLoadDetectorCountsRepeats proves the allowlisted file is
// counted rather than skipped: a second call in the sanctioned file must show.
func TestMeta_RegschemaLoadDetectorCountsRepeats(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport \""+regschemaImportPath+"\"\n\n"+
		"func wire() { _, _ = regschema.Load(\"\"); _, _ = regschema.Load(\"\") }\n")
	if got := countSelectorCalls(f, regschemaImportPath, "Load"); got != 2 {
		t.Fatalf("detector counted %d calls, want 2 — a repeat inside the allowlisted file would pass unseen", got)
	}
}

// TestMeta_RegschemaLoadDetectorPassesCleanSource is the negative meta-test:
// reading the already-loaded value must not match, and neither must a
// same-named call on some other package.
func TestMeta_RegschemaLoadDetectorPassesCleanSource(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport \"example.com/tls\"\n\n"+
		"func wire(d deps) { cfg.RegistrationDataSchema = d.registration.schema; _ = tls.Load(\"\") }\n")
	if got := countSelectorCalls(f, regschemaImportPath, "Load"); got != 0 {
		t.Fatalf("detector counted %d calls in clean source, want 0", got)
	}
}

// TestMeta_CompileDetectorCatchesAnAliasedImport is the positive meta-test for
// the compile-face detector.
func TestMeta_CompileDetectorCatchesAnAliasedImport(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport h \""+sdkHelpersImportPath+"\"\n\n"+
		"func second(raw []byte) { _, _ = h.CompileRegistrationSchema(raw) }\n")
	if got := countSelectorCalls(f, sdkHelpersImportPath, "CompileRegistrationSchema"); got != 1 {
		t.Fatalf("detector counted %d aliased CompileRegistrationSchema calls, want 1", got)
	}
}

// TestMeta_CompileDetectorPassesOtherHelperCalls is the negative meta-test: the
// SDK helpers package is imported by most of this repo for other reasons, and
// none of those uses may trip this guard.
func TestMeta_CompileDetectorPassesOtherHelperCalls(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport \""+sdkHelpersImportPath+"\"\n\n"+
		"func other(m any) { _ = helpers.Validate(m) }\n")
	if got := countSelectorCalls(f, sdkHelpersImportPath, "CompileRegistrationSchema"); got != 0 {
		t.Fatalf("detector counted %d calls where the file only uses other helpers, want 0", got)
	}
}

// TestMeta_RegschemaGuardAllowlistsHoldOneFileEach pins each route's allowlist
// to the single file it names. An allowlist that grows is a guard that stopped
// guarding, and growing one is exactly the change these tests exist to make
// visible. That the sanctioned files still CONTAIN what they are allowlisted
// for is the exactly-one half of the rule above, not this test's job.
func TestMeta_RegschemaGuardAllowlistsHoldOneFileEach(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	allowed := make([]string, 0, 2+len(registrationEnvVars))
	allowed = append(allowed, exchangeCompileHome, fetchedCompileHome)
	for _, v := range registrationEnvVars {
		allowed = append(allowed, v.allowed)
	}
	for _, rel := range allowed {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("allowlisted file %s: %v — an allowlist naming a file that does not exist guards nothing, and each of these routes is sanctioned in exactly one place", rel, err)
		}
	}
}

// TestMeta_TheTwoCompileHomesSitInDisjointTrees pins the split the two compile
// rules divide the repo by. Each skips the other's tree, so the split is what
// makes them add up to whole coverage.
//
// It closes a blind spot that is quiet rather than loud. Move the fetched-schema
// reader under src/exchange and the identity rule skips it — including its
// zero-uses arm, which only ever runs for that one path — so the tree would
// compile a third-party schema in a file no rule watches while both guards
// reported clean.
func TestMeta_TheTwoCompileHomesSitInDisjointTrees(t *testing.T) {
	t.Parallel()
	const exchangeTree = "src/exchange/"
	if !strings.HasPrefix(exchangeCompileHome, exchangeTree) {
		t.Errorf("%s is outside %s, so the Exchange rule no longer covers it", exchangeCompileHome, exchangeTree)
	}
	if strings.HasPrefix(fetchedCompileHome, exchangeTree) {
		t.Errorf("%s is inside %s, so the fetched-schema rule skips it and its zero-uses arm can never run", fetchedCompileHome, exchangeTree)
	}
}

// watchedQualifierPaths are the imports whose local name this package resolves
// in order to match a qualified reference. They are listed together because the
// blind spot they share is a property of the matching, not of any one guard.
//
// Every path a guard here hands to qualifiersFor belongs on this list. The wire
// guards resolve four more of them — protojson for the producer checks, the two
// connect packages for the mount and option checks, and the SDK's own connect
// package for the validation-strictness check — and each is matched with a
// SelectorExpr, so each shares the blind spot this list exists to close.
func watchedQualifierPaths() []string {
	return append([]string{
		rampwellknownPath, regschemaImportPath, exchregImportPath, sdkHelpersImportPath,
		protojsonPath, connectserverPath, connectrpcPath, sdkconnectPath,
	}, protoImportPaths...)
}

// TestWatchedPackagesAreNotDotImported closes the blind spot every qualifier
// resolver in this package shares. Each of them answers "what local name does
// this file bind for this import", and every check built on that answer then
// looks for a SelectorExpr — a qualified reference. A dot-import produces a
// bare identifier instead, so the reference is invisible and the guard reports
// a clean file.
//
// Forbidding the import form is what closes it. No file in this repo
// dot-imports any of these packages, so this costs nothing today, and a file
// that started to would be switching several guards off at once without saying
// so anywhere in the diff.
//
// It reads test files as well as production ones, because the guards it backs
// now do. A ban that covered half the files those guards read would leave the
// blind spot open in exactly the half that was added.
func TestWatchedPackagesAreNotDotImported(t *testing.T) {
	t.Parallel()
	forEachAppAndTestFile(t, func(rel string, f *ast.File) {
		for _, p := range dotImportsOf(f, watchedQualifierPaths()...) {
			t.Errorf("%s dot-imports %s — references to it then carry no package qualifier, and the structural guards in this package match qualified references only. Import it under its own name or an alias.", rel, p)
		}
	})
}

// TestMeta_DotImportDetectorFires is the positive meta-test: a dot-import of a
// watched package must be reported.
func TestMeta_DotImportDetectorFires(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport . \""+rampwellknownPath+"\"\n\nfunc use() { _ = Version }\n")
	if got := dotImportsOf(f, watchedQualifierPaths()...); len(got) != 1 {
		t.Fatalf("detector reported %v for a dot-imported watched package, want exactly one path", got)
	}
}

// TestMeta_DotImportDetectorPassesOrdinaryImports is the negative meta-test:
// the plain and aliased forms are how every file in the repo imports these, and
// neither may trip the check.
func TestMeta_DotImportDetectorPassesOrdinaryImports(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport (\n\t\""+rampwellknownPath+"\"\n\trs \""+regschemaImportPath+"\"\n\t. \"example.com/other\"\n)\n\n"+
		"func use() { _ = rampwellknown.Version; _, _ = rs.Load(\"\") }\n")
	if got := dotImportsOf(f, watchedQualifierPaths()...); len(got) != 0 {
		t.Fatalf("detector reported %v for plain and aliased imports, want none", got)
	}
}

// TestMeta_QualifiersForResolvesEveryImportForm pins the one resolver the three
// guards now share. Before it there were three copies of this answer and they
// had drifted: two of them hardcoded the default local name and neither could
// be driven with more than one path.
func TestMeta_QualifiersForResolvesEveryImportForm(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, "package x\n\nimport (\n\t\""+rampwellknownPath+"\"\n\trs \""+regschemaImportPath+"\"\n)\n")
	quals := qualifiersFor(f, rampwellknownPath, regschemaImportPath, sdkHelpersImportPath)
	for _, want := range []string{"rampwellknown", "rs"} {
		if !quals[want] {
			t.Errorf("qualifiersFor did not resolve %q; got %v", want, quals)
		}
	}
	if quals["helpers"] {
		t.Error("qualifiersFor resolved a package the file does not import")
	}
}
