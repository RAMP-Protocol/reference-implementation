// This file requires the canonical snake_case JSON encoding to be chosen
// EXPLICITLY, everywhere this repository writes proto-JSON. It has two halves,
// because a body reaches the wire two ways.
//
// The MOUNT half: every Connect handler must register the emit-unpopulated
// codec. connectserver.WithEmitUnpopulated is opt-in sugar, so a mount that
// omits it falls back to Connect-Go's stock codec and serves the camelCase
// json_name alias.
//
// The PRODUCER half lives in protojson_names_guard_test.go: every hand-written
// protojson marshal must pin UseProtoNames. That is where the defect which
// prompted all of it actually lived — a plain HTTP route, no Connect mount
// anywhere near it.
//
// Both halves fail the same way, which is why neither is optional: a Go peer
// reads both spellings, so nothing in this repo notices, while a reader built
// from the generated Pydantic or Zod schemas drops what it does not recognise
// because those declare proto names only.
//
// sdkplumbing_guard_test.go carries the complementary ban: no hand-rolled
// emit-unpopulated codec. Requiring the sanctioned one and forbidding a
// look-alike are not the same check.
//
// mountoptions_guard_test.go carries everything else each mount is built from.
// This file answers "does a codec reach the mount, and which one"; that one
// answers "what else is in the set", which is a different question and was
// pinned by nothing.
//
// Scope: fixtures included, for a reason particular to the mount half. Seven
// mounts here stand in for a peer — a fake Exchange the Broker relays to, a fake
// Broker the MCP adapter calls. A double that answers in the camelCase alias
// exercises the client's decode against a wire form no RAMP service produces,
// and every one of the seven did until this guard was widened to see them.
package guards

import (
	"go/ast"
	"go/token"
	"regexp"
	"testing"
)

const (
	connectserverPath = "github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	connectrpcPath    = "connectrpc.com/connect"
)

// handlerCtor matches the generated Connect handler constructors — the SDK's
// wrapped NewExchangeServiceHandler and NewBrokerServiceHandler, and the raw
// generated NewCatalogServiceHandler and NewAdminServiceHandler. Matching the
// NAME rather than a fixed list keeps a service added later inside the guard
// instead of outside it.
var handlerCtor = regexp.MustCompile(`^New[A-Za-z0-9]*ServiceHandler$`)

// mount is one Connect handler-constructor call and the option expressions it
// registers.
type mount struct {
	ctor string
	opts []ast.Expr
}

// TestEveryConnectMountRegistersTheCanonicalCodec fails when a Connect handler
// is mounted without the emit-unpopulated, snake_case JSON codec.
func TestEveryConnectMountRegistersTheCanonicalCodec(t *testing.T) {
	t.Parallel()
	found := 0
	forEachAppAndTestFile(t, func(rel string, f *ast.File) {
		for _, m := range mountCalls(f) {
			found++
			if !registersCodec(f, m.opts) {
				t.Errorf("%s: %s is mounted without the canonical JSON codec — pass "+
					"connectserver.WithEmitUnpopulated() or connect.WithCodec("+
					"connectserver.EmitUnpopulatedJSONCodec())", rel, m.ctor)
			}
		}
	})
	if found == 0 {
		t.Fatal("no Connect handler mounts matched — the detector has stopped seeing them, " +
			"so this guard is passing without checking anything")
	}
}

// TestCodecProvidersRegisterTheCodec follows the indirection a mount provider
// opens: a mount that calls one is treated as covered, so each provider must
// itself register the codec, and must exist. A name left in mountProviders after
// its function is gone would silently keep admitting mounts that call something
// else by that name.
func TestCodecProvidersRegisterTheCodec(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	forEachAppFile(t, func(rel string, f *ast.File) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !isMountProvider(fn.Name.Name) {
				continue
			}
			seen[fn.Name.Name] = true
			if !registersCodec(f, callsIn(fn.Body)) {
				t.Errorf("%s: %s is allowlisted as a source of the canonical codec "+
					"but its body never registers one", rel, fn.Name.Name)
			}
		}
	})
	for name := range mountProviders {
		if !seen[name] {
			t.Errorf("%s is allowlisted as a codec provider, but no such function exists", name)
		}
	}
}

// mountCalls returns every handler-constructor call in f, paired with the
// option expressions it registers. The enclosing function is tracked because a
// spread argument is resolved against that function's body.
func mountCalls(f *ast.File) []mount {
	var found []mount
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, isCtor := ctorName(call); isCtor {
				found = append(found, mount{ctor: name, opts: optionExprs(fn, call)})
			}
			return true
		})
	}
	return found
}

// ctorName reports the constructor name a call invokes, qualified or not.
func ctorName(call *ast.CallExpr) (string, bool) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name, handlerCtor.MatchString(fun.Sel.Name)
	case *ast.Ident:
		return fun.Name, handlerCtor.MatchString(fun.Name)
	}
	return "", false
}

// optionExprs returns the option arguments of a mount call. Every mount in this
// repo builds its options into a slice and spreads it, so the arguments alone
// say nothing; a spread is resolved back to the expressions that reached that
// slice inside fn.
func optionExprs(fn *ast.FuncDecl, call *ast.CallExpr) []ast.Expr {
	if len(call.Args) < 2 {
		return nil
	}
	args := call.Args[1:]
	if call.Ellipsis == token.NoPos {
		return args
	}
	spread, ok := args[len(args)-1].(*ast.Ident)
	if !ok {
		return args
	}
	fixed := args[: len(args)-1 : len(args)-1]
	return append(fixed, sliceSources(fn.Body, spread.Name, call.Pos())...)
}

// sliceSources returns the option expressions the spread slice holds AT the
// mount call, reading the enclosing function's own top-level statements in
// order. before is the position of that call.
//
// Reading order and nesting is what makes this a check rather than a survey.
// Collecting every assignment anywhere in the function, which is what this did
// first, passed three mounts it was written to fail — each measured returning
// covered:
//
//   - A codec appended inside an `if`. Only statements of body itself are read
//     now, so the append is never seen. Production would otherwise serve the
//     camelCase alias whenever that condition is false, which is exactly the
//     shape a codec change staged behind an environment variable takes.
//   - A codec appended AFTER the mount call. The loop stops at before, so it
//     cannot count toward a slice that was already spread.
//   - A slice seeded with the codec and then reassigned. An assignment that is
//     not an append to the same slice discards what the slice held, so it
//     replaces the set rather than adding to it.
func sliceSources(body *ast.BlockStmt, name string, before token.Pos) []ast.Expr {
	var out []ast.Expr
	for _, stmt := range body.List {
		if stmt.Pos() >= before {
			break
		}
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || !assignsTo(assign, name) {
			continue
		}
		if extras, isAppend := appendExtras(assign, name); isAppend {
			out = append(out, extras...)
			continue
		}
		out = nil
		for _, rhs := range assign.Rhs {
			out = append(out, sourcesOf(rhs)...)
		}
	}
	return out
}

// appendExtras reports the option expressions an `x = append(x, …)` adds, and
// whether the assignment is that shape at all.
//
// The first argument has to be the slice itself. An append to a DIFFERENT slice
// does not add to this one — it overwrites it with somebody else's contents —
// so it is a replacement, and the caller treats it as one.
func appendExtras(assign *ast.AssignStmt, name string) ([]ast.Expr, bool) {
	if len(assign.Rhs) != 1 {
		return nil, false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	fn, isIdent := call.Fun.(*ast.Ident)
	if !isIdent || fn.Name != "append" || len(call.Args) == 0 {
		return nil, false
	}
	first, isIdent := call.Args[0].(*ast.Ident)
	if !isIdent || first.Name != name {
		return nil, false
	}
	return call.Args[1:], true
}

// assignsTo reports whether assign writes to name.
func assignsTo(assign *ast.AssignStmt, name string) bool {
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
			return true
		}
	}
	return false
}

// sourcesOf turns one REPLACING right-hand side into the option expressions it
// contributes: a composite literal's elements, or the call itself where it
// returns a ready-made set. Appending to the slice is handled by appendExtras
// before this is reached, because an append adds and everything else replaces.
func sourcesOf(rhs ast.Expr) []ast.Expr {
	switch v := rhs.(type) {
	case *ast.CompositeLit:
		return v.Elts
	case *ast.CallExpr:
		return []ast.Expr{v}
	}
	return nil
}

// callsIn returns every call expression inside body.
func callsIn(body *ast.BlockStmt) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			out = append(out, call)
		}
		return true
	})
	return out
}

// registersCodec reports whether any of exprs puts the canonical codec on a
// mount. Import aliases are resolved, so connectrpc.WithCodec and
// connect.WithCodec both read the same.
func registersCodec(f *ast.File, exprs []ast.Expr) bool {
	server := qualifiersFor(f, connectserverPath)
	rpc := qualifiersFor(f, connectrpcPath)
	for _, e := range exprs {
		if callRegistersCodec(e, server, rpc) {
			return true
		}
	}
	return false
}

// callRegistersCodec is registersCodec for one expression.
func callRegistersCodec(e ast.Expr, server, rpc map[string]bool) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return isMountProvider(fun.Name)
	case *ast.SelectorExpr:
		pkg, isPkg := fun.X.(*ast.Ident)
		switch {
		case !isPkg:
			return false
		case server[pkg.Name] && fun.Sel.Name == "WithEmitUnpopulated":
			return true
		case rpc[pkg.Name] && fun.Sel.Name == "WithCodec":
			return len(call.Args) == 1 && namesCanonicalCodec(call.Args[0], server)
		default:
			return isMountProvider(fun.Sel.Name)
		}
	}
	return false
}

// namesCanonicalCodec reports whether e is connectserver.EmitUnpopulatedJSONCodec().
// WithCodec takes any codec, so the argument is what decides.
func namesCanonicalCodec(e ast.Expr, server map[string]bool) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && server[pkg.Name] && sel.Sel.Name == "EmitUnpopulatedJSONCodec"
}

// --- meta-tests: the detector itself ---
//
// Every mount in this repo spreads an options slice, so the interesting
// question is not "does it read an argument list" but "does it follow the slice
// back to where the options were put in". These drive the three shapes the repo
// actually uses, plus the two ways a mount can look right and be wrong.

// mountSource wraps a mount call in a compilable file with the imports the
// detector resolves against, under whatever aliases a caller chose.
func mountSource(serverAlias, rpcAlias, body string) string {
	return "package p\n\nimport (\n\t" + rpcAlias + " \"" + connectrpcPath + "\"\n\t" +
		serverAlias + " \"" + connectserverPath + "\"\n)\n\nfunc mountIt() {\n" + body + "\n}\n"
}

// mountIsCovered runs the whole detector over one synthetic file and reports
// what it concluded about the single mount in it.
func mountIsCovered(t *testing.T, src string) bool {
	t.Helper()
	f := parseSnippet(t, src)
	mounts := mountCalls(f)
	if len(mounts) != 1 {
		t.Fatalf("meta source has %d mounts, want exactly 1", len(mounts))
	}
	return registersCodec(f, mounts[0].opts)
}

// TestMeta_MountDetectorFlagsAMountWithNoCodec is the positive case: a mount whose
// option slice carries everything except the codec.
func TestMeta_MountDetectorFlagsAMountWithNoCodec(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connectserver.ServerOption{
		connectserver.WithValidation(connect.ValidationStrict),
	}
	_, _ = connectserver.NewExchangeServiceHandler(nil, opts...)`)
	if mountIsCovered(t, src) {
		t.Error("detector passed a mount whose options never register the codec")
	}
}

// TestMeta_MountDetectorFollowsASpreadSlice is the shape both SDK-wrapped mounts
// use. Reading the argument list alone would see one identifier and conclude
// nothing.
func TestMeta_MountDetectorFollowsASpreadSlice(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connectserver.ServerOption{
		connectserver.WithEmitUnpopulated(),
	}
	_, _ = connectserver.NewBrokerServiceHandler(nil, opts...)`)
	if !mountIsCovered(t, src) {
		t.Error("detector missed WithEmitUnpopulated inside a spread option slice")
	}
}

// TestMeta_MountDetectorFollowsAProviderThroughAnAppend is the shape the catalog
// mount had before its read cap moved into CatalogMountOptions: the options come
// back from an allowlisted provider, and a second option is appended before the
// spread. No mount in the repo appends today. The detector keeps reading appends
// because that is exactly how a mount would come to serve an option no provider
// registers, and a shape the guard stopped reading is a shape it stopped
// checking.
func TestMeta_MountDetectorFollowsAProviderThroughAnAppend(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts, _ := RawValidatedMountOptions(nil)
	opts = append(opts, connect.WithReadMaxBytes(1))
	_, _ = NewCatalogServiceHandler(nil, opts...)`)
	if !mountIsCovered(t, src) {
		t.Error("detector missed an allowlisted provider reached through append")
	}
}

// TestMeta_MountDetectorResolvesImportAliases pins the alias handling. The exchange
// binds connectrpc.com/connect as "connectrpc"; a check written against the
// package's own name would walk straight past it.
func TestMeta_MountDetectorResolvesImportAliases(t *testing.T) {
	t.Parallel()
	src := mountSource("cs", "connectrpc", `	opts := []connectrpc.HandlerOption{
		connectrpc.WithCodec(cs.EmitUnpopulatedJSONCodec()),
	}
	_, _ = NewAdminServiceHandler(nil, opts...)`)
	if !mountIsCovered(t, src) {
		t.Error("detector missed WithCodec written through aliased imports")
	}
}

// TestMeta_MountDetectorReadsWhichCodecWasRegistered is the case a check for the
// word WithCodec would pass: the option is there, and it installs some other
// codec.
func TestMeta_MountDetectorReadsWhichCodecWasRegistered(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connect.HandlerOption{
		connect.WithCodec(someOtherCodec()),
	}
	_, _ = NewCatalogServiceHandler(nil, opts...)`)
	if mountIsCovered(t, src) {
		t.Error("detector accepted WithCodec carrying a codec that is not the canonical one")
	}
}

// --- the three shapes that used to slip through ---
//
// Each of these was measured returning COVERED before sliceSources read the
// enclosing function in order. They are the reason that read order exists, so
// they are pinned rather than left to the comment on it.

// TestMeta_MountDetectorRefusesACodecRegisteredConditionally is the realistic
// regression: staging a codec change behind a flag. Whenever the condition is
// false the mount serves the camelCase alias, so a guard that counts the append
// regardless reports a mount that is only sometimes correct.
func TestMeta_MountDetectorRefusesACodecRegisteredConditionally(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connectserver.ServerOption{
		connectserver.WithValidation(connect.ValidationStrict),
	}
	if featureFlag() {
		opts = append(opts, connectserver.WithEmitUnpopulated())
	}
	_, _ = connectserver.NewExchangeServiceHandler(nil, opts...)`)
	if mountIsCovered(t, src) {
		t.Error("detector passed a mount whose codec is registered inside a conditional")
	}
}

// TestMeta_MountDetectorRefusesASliceReassignedBeforeTheMount pins that a later
// assignment discards the earlier one. The codec is registered on a value the
// mount never receives.
func TestMeta_MountDetectorRefusesASliceReassignedBeforeTheMount(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connectserver.ServerOption{
		connectserver.WithEmitUnpopulated(),
	}
	opts = []connectserver.ServerOption{
		connectserver.WithValidation(connect.ValidationStrict),
	}
	_, _ = connectserver.NewExchangeServiceHandler(nil, opts...)`)
	if mountIsCovered(t, src) {
		t.Error("detector passed a mount whose option slice was replaced before it was spread")
	}
}

// TestMeta_MountDetectorRefusesACodecAppendedAfterTheMount pins the position check.
// The slice was already spread, so appending to it afterwards changes nothing
// the handler was built with.
func TestMeta_MountDetectorRefusesACodecAppendedAfterTheMount(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	opts := []connectserver.ServerOption{
		connectserver.WithValidation(connect.ValidationStrict),
	}
	_, _ = connectserver.NewExchangeServiceHandler(nil, opts...)
	opts = append(opts, connectserver.WithEmitUnpopulated())`)
	if mountIsCovered(t, src) {
		t.Error("detector passed a mount whose codec is appended after the handler is built")
	}
}

// TestMeta_MountDetectorIgnoresCallsThatAreNotMounts keeps the constructor pattern
// from matching ordinary constructors.
func TestMeta_MountDetectorIgnoresCallsThatAreNotMounts(t *testing.T) {
	t.Parallel()
	src := mountSource("connectserver", "connect", `	_ = NewExchangeService(nil)
	_ = connectserver.NewKeyResolver(nil)`)
	if got := mountCalls(parseSnippet(t, src)); len(got) != 0 {
		t.Errorf("detector matched %d non-mount calls, want none", len(got))
	}
}
