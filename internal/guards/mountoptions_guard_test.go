// This file pins the WHOLE option set each Connect mount is built from, not
// just the codec.
//
// Four functions hand a ready-made option set to a mount, and each service's
// production wiring and its integration harness both call the one that belongs
// to them. That is what makes the mount under test the mount that ships — and
// it is also what makes a deletion inside one of them invisible: every caller
// keeps compiling, every test keeps passing, and the option is simply gone.
//
// Measured, not argued. Deleting connectserver.WithValidation from the Broker's
// option set leaves the whole src/broker/internal/transport suite passing, and
// so does deleting connectserver.WithOnReject. The validation case is the worse
// of the two: connect.ValidationOff is the ZERO VALUE of the enum, so a deleted
// line and an explicit ValidationOff are the same request, and both turn
// protovalidate off in BOTH directions on a mount that still serves.
//
// wirecodec_guard_test.go carries the codec half — which mounts reach a codec,
// and which codec they reach. This file carries everything else in the set.
package guards

import (
	"go/ast"
	"slices"
	"sort"
	"testing"
)

// sdkconnectPath is the SDK's own connect package, which owns the Validation
// enum. It is NOT connectrpc.com/connect: mount_options.go imports both, under
// separate names, and the strictness check below reads a constant from this one.
const sdkconnectPath = "github.com/RAMP-Protocol/protocol/sdk/go/connect"

// mountProviders maps each option-set function to every option its body must
// register. This is the file's whole claim, and each entry is a property a
// deletion would otherwise carry away in silence:
//
//   - WithKeyResolver and WithReplayStore: without them the RFC 9421 verify
//     pass has no keys to resolve against and no replay memory, so a replayed
//     signature is accepted.
//   - WithValidation: protovalidate, both directions. See the file header for
//     why its absence and its off-by-zero-value spelling are the same defect.
//   - WithEmitUnpopulated: the snake_case, zero-valued-fields-retained JSON
//     contract. wirecodec_guard_test.go checks this one on the mount side too;
//     it is listed here because a provider is where it now comes from.
//   - WithInterceptors: the recipient check. A mount without it accepts a
//     request addressed to a different Exchange.
//   - WithOnReject: the audit line for every gate rejection. Dropped, a refusal
//     leaves no trace at all.
//   - WithMaxSignatures and WithMaxRequestBytes are the ExchangeService mount's
//     alone: the hop bound is Exchange-terminal policy, and the request cap
//     bounds both the raw body the verify face buffers before authentication
//     and the decompressed message the handler decodes. Dropped, the mount
//     falls back to the SDK's own default rather than to no cap at all, which
//     is exactly why nothing else in the suite would notice.
//   - WithReadMaxBytes is the catalog mount's message cap, the one quantity a
//     raw connect mount can bound through an option. The raw body on that
//     mount is bounded by the middleware that captures it, which no option
//     list can show; its integration tests are what pin that half. The codec
//     and the interceptor beside it in that entry arrive through
//     RawValidatedMountOptions rather than from the provider's own body — the
//     list is what the MOUNT ends up with, not what one function literal
//     spells, so rewriting the provider to build its own set without the
//     delegate is a gap rather than a rearrangement.
//   - WithVerifyGate is the Broker's alone: it is what makes an unsigned Resolve
//     reach the handler instead of being refused at the seam.
//
// The Broker's set names no request cap. Since the SDK began modelling one its
// mount runs under the SDK default rather than under nothing, but no option
// here pins that value and this map cannot see a default — recorded as an
// absence rather than left for a reader to infer from a shorter list.
var mountProviders = map[string][]string{
	"RawValidatedMountOptions": {
		"WithCodec",
		"WithInterceptors",
	},
	"CatalogMountOptions": {
		"WithCodec",
		"WithInterceptors",
		"WithReadMaxBytes",
	},
	"ExchangeMountOptions": {
		"WithKeyResolver",
		"WithReplayStore",
		"WithMaxSignatures",
		"WithValidation",
		"WithEmitUnpopulated",
		"WithInterceptors",
		"WithOnReject",
		"WithMaxRequestBytes",
	},
	"BrokerMountOptions": {
		"WithKeyResolver",
		"WithReplayStore",
		"WithValidation",
		"WithEmitUnpopulated",
		"WithInterceptors",
		"WithVerifyGate",
		"WithOnReject",
	},
}

// isMountProvider reports whether name is one of the option-set functions above.
//
// The codec half reads this to follow the indirection a provider opens: a mount
// that calls one is covered, which is only safe because the checks here confirm
// each provider registers what it claims. Both halves ask the question of the
// SAME map, so a provider added to one cannot be a mount the other never checks.
func isMountProvider(name string) bool {
	_, ok := mountProviders[name]
	return ok
}

// TestMountProvidersRegisterEveryRequiredOption fails when an option-set
// function stops registering something its mount depends on, and when a name in
// the map has no function to check.
//
// Both directions matter. A missing option is the defect this exists for; a map
// entry with no function behind it means the guard is checking a name nobody
// calls, which reads as coverage and is not.
func TestMountProvidersRegisterEveryRequiredOption(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	forEachAppFile(t, func(rel string, f *ast.File) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			required, watched := mountProviders[fn.Name.Name]
			if !watched {
				continue
			}
			seen[fn.Name.Name] = true
			if gaps := providerGaps(f, fn.Body, required); len(gaps) > 0 {
				t.Errorf("%s: %s no longer registers %v — every option in that list is a "+
					"check the mount stops making, and nothing else in the suite fails when "+
					"one goes. Put it back rather than shortening the required set",
					rel, fn.Name.Name, gaps)
			}
			if !validationIsStrict(f, callsIn(fn.Body)) {
				t.Errorf("%s: %s passes something other than ValidationStrict to "+
					"WithValidation — ValidationOff is the enum's zero value, so this "+
					"turns protovalidate off in both directions on a mount that still serves",
					rel, fn.Name.Name)
			}
		}
	})
	for name := range mountProviders {
		if !seen[name] {
			t.Errorf("%s is listed as a mount-option provider, but no such function exists — "+
				"the entry is checking a name nobody calls", name)
		}
	}
}

// providerGaps returns the required option names body does not register, sorted
// so a failure reads the same on every run.
//
// It reads every call in the body, nested calls included, rather than only the
// top-level elements of the returned slice. That is deliberately looser than
// the mount-side detector, which reads statements in order: a provider is one
// function whose whole job is to return one literal option set, so there is no
// ordering or reassignment to lose. It also means WithReadMaxBytes is found
// where it actually sits in CatalogMountOptions: as an argument of the append
// that adds it to the shared raw-mount set, not as an element of a literal.
func providerGaps(f *ast.File, body *ast.BlockStmt, required []string) []string {
	registered := optionNamesIn(f, callsIn(body))
	var gaps []string
	for _, want := range required {
		if !registered[want] {
			gaps = append(gaps, want)
		}
	}
	sort.Strings(gaps)
	return gaps
}

// optionNamesIn returns the set of option-constructor names called in exprs,
// under whatever aliases the file binds for the two packages that own them.
// Resolving the import rather than matching a package qualifier is what keeps
// an aliased import (connectrpc.WithCodec) reading the same as a plain one.
//
// A call to ANOTHER provider in the map counts as registering everything that
// provider is required to register. CatalogMountOptions is built that way: it
// returns RawValidatedMountOptions' set with one option appended, so a check
// that read only its own body would see one option and its map entry could only
// ever name that one — leaving the codec and the recipient interceptor
// unpinned, and a rewrite that dropped the delegate silently green. The codec
// half follows the same indirection (callRegistersCodec), and it is sound for
// the same reason: both halves ask the SAME map, and the test above checks
// every provider against its own entry, so a delegate's claim is verified where
// the delegate is declared rather than taken on trust here.
func optionNamesIn(f *ast.File, exprs []ast.Expr) map[string]bool {
	quals := qualifiersFor(f, connectserverPath, connectrpcPath)
	names := map[string]bool{}
	for _, e := range exprs {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			continue
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			// A bare call: RawValidatedMountOptions(audience), the shape a
			// provider in this package's own file takes.
			addProviderOptions(fun.Name, names)
		case *ast.SelectorExpr:
			pkg, isPkg := fun.X.(*ast.Ident)
			if !isPkg {
				continue
			}
			if quals[pkg.Name] {
				names[fun.Sel.Name] = true
				continue
			}
			// A qualified call: transport.CatalogMountOptions(...), the shape a
			// provider takes when a mount in another package reaches it.
			addProviderOptions(fun.Sel.Name, names)
		}
	}
	return names
}

// addProviderOptions unions in what the named provider is required to register.
// A name that is not a provider adds nothing, so an ordinary helper call is
// invisible here rather than accidentally satisfying a requirement.
func addProviderOptions(name string, names map[string]bool) {
	for _, opt := range mountProviders[name] {
		names[opt] = true
	}
}

// validationIsStrict reports whether every WithValidation call in exprs names
// ValidationStrict. A file that never calls it is strict by vacuity — the
// missing call is providerGaps' finding, and reporting it twice would say the
// same thing in two voices.
func validationIsStrict(f *ast.File, exprs []ast.Expr) bool {
	server := qualifiersFor(f, connectserverPath)
	sdk := qualifiersFor(f, sdkconnectPath)
	for _, e := range exprs {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "WithValidation" {
			continue
		}
		if pkg, isPkg := sel.X.(*ast.Ident); !isPkg || !server[pkg.Name] {
			continue
		}
		if len(call.Args) != 1 || !namesStrictValidation(call.Args[0], sdk) {
			return false
		}
	}
	return true
}

// namesStrictValidation reports whether e is the SDK's ValidationStrict
// constant. WithValidation takes the whole enum, so the argument is what
// decides, exactly as the codec check reads WithCodec's.
func namesStrictValidation(e ast.Expr, sdk map[string]bool) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ValidationStrict" {
		return false
	}
	pkg, isPkg := sel.X.(*ast.Ident)
	return isPkg && sdk[pkg.Name]
}

// --- meta-tests: prove the detector itself works ---------------------------

// optionSource wraps an option list in a compilable provider function, under
// whatever aliases a caller chose for the three packages involved.
func optionSource(serverAlias, rpcAlias, sdkAlias, body string) string {
	return "package p\n\nimport (\n\t" + rpcAlias + " \"" + connectrpcPath + "\"\n\t" +
		sdkAlias + " \"" + sdkconnectPath + "\"\n\t" +
		serverAlias + " \"" + connectserverPath + "\"\n)\n\n" +
		"func BrokerMountOptions() []" + serverAlias + ".ServerOption {\n" +
		"\treturn []" + serverAlias + ".ServerOption{\n" + body + "\n\t}\n}\n"
}

// providerBodyOf returns the single provider function declared in a synthetic
// source, failing the test if the fixture does not hold exactly one.
func providerBodyOf(t *testing.T, f *ast.File) *ast.BlockStmt {
	t.Helper()
	var found []*ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && isMountProvider(fn.Name.Name) {
			found = append(found, fn.Body)
		}
	}
	if len(found) != 1 {
		t.Fatalf("meta source declares %d watched providers, want exactly 1", len(found))
	}
	return found[0]
}

// brokerOptions is the Broker's real set, written out so each case below can
// remove exactly one line from a set that otherwise passes.
const brokerOptions = `		connectserver.WithKeyResolver(nil),
		connectserver.WithReplayStore(nil),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		connectserver.WithInterceptors(nil),
		connectserver.WithVerifyGate(nil),
		connectserver.WithOnReject(nil),`

// TestMeta_ProviderDetectorPassesACompleteSet is the negative case. Without it
// the cases below are satisfied by a check that reports every provider.
func TestMeta_ProviderDetectorPassesACompleteSet(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, optionSource("connectserver", "connect", "sdkconnect", brokerOptions))
	if gaps := providerGaps(f, providerBodyOf(t, f), mountProviders["BrokerMountOptions"]); len(gaps) > 0 {
		t.Errorf("reported %v missing from a complete set, want none", gaps)
	}
}

// TestMeta_ProviderDetectorFlagsADeletedOption is the positive case, driven
// with the deletion that was measured to leave the real suite passing.
func TestMeta_ProviderDetectorFlagsADeletedOption(t *testing.T) {
	t.Parallel()
	withoutReject := `		connectserver.WithKeyResolver(nil),
		connectserver.WithReplayStore(nil),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		connectserver.WithInterceptors(nil),
		connectserver.WithVerifyGate(nil),`
	f := parseSnippet(t, optionSource("connectserver", "connect", "sdkconnect", withoutReject))
	gaps := providerGaps(f, providerBodyOf(t, f), mountProviders["BrokerMountOptions"])
	if len(gaps) != 1 || gaps[0] != "WithOnReject" {
		t.Errorf("reported %v for a set missing WithOnReject, want exactly that one", gaps)
	}
}

// TestMeta_ProviderDetectorResolvesImportAliases pins the alias handling. The
// Exchange binds connectrpc.com/connect as connectrpc and the SDK's connect as
// sdkconnect, so a detector anchored on either default name reads a clean file.
func TestMeta_ProviderDetectorResolvesImportAliases(t *testing.T) {
	t.Parallel()
	aliased := `		srv.WithKeyResolver(nil),
		srv.WithReplayStore(nil),
		srv.WithValidation(sdkc.ValidationStrict),
		srv.WithEmitUnpopulated(),
		srv.WithInterceptors(nil),
		srv.WithVerifyGate(nil),
		srv.WithOnReject(nil),`
	f := parseSnippet(t, optionSource("srv", "rpc", "sdkc", aliased))
	if gaps := providerGaps(f, providerBodyOf(t, f), mountProviders["BrokerMountOptions"]); len(gaps) > 0 {
		t.Errorf("reported %v for an aliased but complete set, want none", gaps)
	}
	if !validationIsStrict(f, callsIn(providerBodyOf(t, f))) {
		t.Error("read an aliased ValidationStrict as not strict")
	}
}

// TestMeta_ProviderDetectorFlagsValidationOff is the case a name-only check
// cannot see: WithValidation is present, and it switches protovalidate off.
func TestMeta_ProviderDetectorFlagsValidationOff(t *testing.T) {
	t.Parallel()
	off := `		connectserver.WithValidation(sdkconnect.ValidationOff),`
	f := parseSnippet(t, optionSource("connectserver", "connect", "sdkconnect", off))
	if validationIsStrict(f, callsIn(providerBodyOf(t, f))) {
		t.Error("read ValidationOff as strict — a name-only check would pass this, which is why the argument is read")
	}
}

// delegatingOptionSource wraps a body in a provider that returns another
// provider's set with something appended — the shape CatalogMountOptions has.
// The function is named CatalogMountOptions so the map entry under test is its
// real one, and RawValidatedMountOptions appears only as a CALL: declaring it
// too would give providerBodyOf two watched providers to choose between, and
// the fixture is only parsed, never compiled, so the callee need not exist.
func delegatingOptionSource(body string) string {
	return "package p\n\nimport (\n\tconnect \"" + connectrpcPath + "\"\n)\n\n" +
		"func CatalogMountOptions() ([]connect.HandlerOption, error) {\n" +
		"\topts, err := RawValidatedMountOptions(nil)\n" +
		"\tif err != nil {\n\t\treturn nil, err\n\t}\n" +
		"\treturn " + body + ", nil\n}\n"
}

// TestMeta_ProviderDetectorFollowsADelegatedSet is the case the catalog mount
// needs. Its provider registers one option itself and inherits the rest from
// RawValidatedMountOptions, so a detector that read only the calls into the two
// SDK packages would find one name and could pin only that one. Reading the
// delegation is what lets its entry name the whole set the mount ends up with.
func TestMeta_ProviderDetectorFollowsADelegatedSet(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, delegatingOptionSource("append(opts, connect.WithReadMaxBytes(1))"))
	if gaps := providerGaps(f, providerBodyOf(t, f), mountProviders["CatalogMountOptions"]); len(gaps) > 0 {
		t.Errorf("reported %v missing from a provider that delegates for them, want none", gaps)
	}
}

// TestMeta_ProviderDetectorFlagsADroppedDelegate is the defect the delegation
// arm exists to catch: the provider builds its own set instead of extending the
// shared one, so the mount silently loses the codec and the recipient
// interceptor while still registering the option it is named for.
func TestMeta_ProviderDetectorFlagsADroppedDelegate(t *testing.T) {
	t.Parallel()
	standalone := "package p\n\nimport (\n\tconnect \"" + connectrpcPath + "\"\n)\n\n" +
		"func CatalogMountOptions() ([]connect.HandlerOption, error) {\n" +
		"\treturn []connect.HandlerOption{connect.WithReadMaxBytes(1)}, nil\n}\n"
	f := parseSnippet(t, standalone)
	gaps := providerGaps(f, providerBodyOf(t, f), mountProviders["CatalogMountOptions"])
	want := []string{"WithCodec", "WithInterceptors"}
	if !slices.Equal(gaps, want) {
		t.Errorf("reported %v for a provider that dropped its delegate, want %v", gaps, want)
	}
}

// TestMeta_ProviderDetectorIgnoresANonProviderCall pins that the delegation arm
// resolves names through the map rather than treating any call as a set: a
// helper the provider happens to call must satisfy nothing.
func TestMeta_ProviderDetectorIgnoresANonProviderCall(t *testing.T) {
	t.Parallel()
	f := parseSnippet(t, optionSource("connectserver", "connect", "sdkconnect",
		"\t\tconnectserver.WithOnReject(nil),"))
	names := optionNamesIn(f, callsIn(providerBodyOf(t, f)))
	if names["WithCodec"] || names["WithKeyResolver"] {
		t.Errorf("a set registering only WithOnReject read as %v", names)
	}
}

// TestMeta_ProviderDetectorFindsAnOptionNestedInAnother pins that a call inside
// another call is read. The catalog provider needs it: its read cap is an
// argument of the append that extends the shared set, so a check reading only
// the returned literal's own elements would miss it. The fixture nests the
// option inside another option call instead, because the meta source wraps a
// literal; the property under test is the nesting, not the outer call.
func TestMeta_ProviderDetectorFindsAnOptionNestedInAnother(t *testing.T) {
	t.Parallel()
	nested := `		connectserver.WithHandlerOptions(connect.WithReadMaxBytes(1)),`
	f := parseSnippet(t, optionSource("connectserver", "connect", "sdkconnect", nested))
	names := optionNamesIn(f, callsIn(providerBodyOf(t, f)))
	for _, want := range []string{"WithHandlerOptions", "WithReadMaxBytes"} {
		if !names[want] {
			t.Errorf("did not find %s; got %v", want, names)
		}
	}
}
