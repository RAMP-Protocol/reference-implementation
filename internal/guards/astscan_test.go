// Shared AST scanning for this package's structural guards.
//
// Three guards here ask the same two questions of a file: what local name does
// it bind for an import, and how many times does it call a given function
// through that name. Written per guard, the answers drifted. Two copies
// hardcoded the default local name, and only one of the three noticed a
// dot-import at all, so a reference written that way was invisible to the other
// two. One copy of each question is what stops that happening again.
package guards

import (
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"testing"
)

// localNameFor returns the name path is bound to in f, and whether f imports it
// at all. An aliased import returns the alias; a dot-import returns "."; a
// plain import returns the package's own name, which for every package in this
// repo is the last element of its path.
func localNameFor(f *ast.File, importPath string) (string, bool) {
	for _, imp := range f.Imports {
		if imp.Path == nil || imp.Path.Value != `"`+importPath+`"` {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return path.Base(importPath), true
	}
	return "", false
}

// qualifiersFor maps every local name f binds for any of paths onto true,
// resolving whatever alias each import chose.
//
// It is expressed over localNameFor so this package answers "what is this
// import called in this file" in exactly one place. Three copies of that
// question had drifted apart, and only one of them handled every import form.
func qualifiersFor(f *ast.File, paths ...string) map[string]bool {
	quals := map[string]bool{}
	for _, p := range paths {
		if local, ok := localNameFor(f, p); ok {
			quals[local] = true
		}
	}
	return quals
}

// dotImportsOf returns the paths among paths that f imports with a dot.
//
// A dot-imported reference is a bare identifier carrying no package qualifier,
// so every check in this package that matches a SelectorExpr walks straight
// past it. Forbidding the import form is the cheaper half of that fix: no file
// here dot-imports these packages, and one that started to would be switching
// off several guards at once without saying so.
func dotImportsOf(f *ast.File, paths ...string) []string {
	var dotted []string
	for _, p := range paths {
		if local, ok := localNameFor(f, p); ok && local == "." {
			dotted = append(dotted, p)
		}
	}
	return dotted
}

// countSelectorCalls counts calls to sel on whatever local name f binds path
// to. It resolves the import rather than matching a package qualifier, so an
// aliased import (rs.Load) and a dot-import (Load) are both caught — the two
// forms a source-text match for "regschema.Load(" cannot see. A file that does
// not import path counts zero, which is also the right answer for the defining
// package's own unqualified calls.
func countSelectorCalls(f *ast.File, importPath, sel string) int {
	local, ok := localNameFor(f, importPath)
	if !ok {
		return 0
	}
	count := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if id, isIdent := fun.X.(*ast.Ident); isIdent && id.Name == local && fun.Sel.Name == sel {
				count++
			}
		case *ast.Ident:
			if local == "." && fun.Name == sel {
				count++
			}
		}
		return true
	})
	return count
}

// stringValue unquotes a string literal and reports whether e was one.
// go/ast keeps the source delimiters in BasicLit.Value, so a comparison against
// the double-quoted spelling alone is blind to the same string written with
// backquotes — and a second read of the variable written that way would leave
// the guard reporting a clean tree.
func stringValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// stringConstsIn maps each string constant declared in f to its value, so a
// read written through a named constant resolves the same as one written with
// the literal. Without this a file could declare the name once and read it from
// three places while a literal count answered one.
func stringConstsIn(f *ast.File) map[string]string {
	consts := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if i >= len(spec.Values) {
				continue
			}
			if v, isString := stringValue(spec.Values[i]); isString {
				consts[name.Name] = v
			}
		}
		return true
	})
	return consts
}

// forEachAppFile parses every app source file and hands its path and AST to fn.
func forEachAppFile(t *testing.T, fn func(rel string, f *ast.File)) {
	t.Helper()
	root := repoRoot(t)
	for _, rel := range appSourceFiles(t, root) {
		fn(rel, parseGoFile(t, root, rel))
	}
}

// forEachAppAndTestFile is forEachAppFile plus _test.go files.
//
// It is a SEPARATE walker rather than a flag on the one above, for the reason
// appSourceAndTestFiles is a separate helper: most guards here bind production
// code and would misfire on a fixture that legitimately hand-rolls what they
// forbid, so widening one guard must not be able to widen the rest. Eleven
// checks read forEachAppFile and want the narrow set.
//
// The guards that want this one are the wire-naming pair. Both describe a
// property of what this repository PUTS ON THE WIRE, and a fixture posting a
// body to a real route puts it on the wire exactly as production does — the
// same reasoning the ver guards give for reading fixtures, where every wrong
// version this project shipped was in a _test.go file.
func forEachAppAndTestFile(t *testing.T, fn func(rel string, f *ast.File)) {
	t.Helper()
	root := repoRoot(t)
	for _, rel := range appSourceAndTestFiles(t, root) {
		fn(rel, parseGoFile(t, root, rel))
	}
}

// TestRegistrationSchemaLoadedOnce fails when regschema.Load is called anywhere
// but the composition root, and when the composition root calls it more than
// once. The allowlisted file is COUNTED rather than skipped: two calls there
// produce the same two compiled schemas as one call in each of two files, and
