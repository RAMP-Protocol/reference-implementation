package guards

import (
	"go/ast"
	"strings"
	"testing"
)

// The MCP adapter builds the context an outbound leg runs under in exactly one
// place, toolset.callCtx. This guard is what keeps it that way.
//
// callCtx is caller.outbound plus the request-scoped logger. Both forms carry
// this call's correlation id, so a handler that used the bare one behaves
// identically TODAY — exchacct is the only service under the tool layer that
// reads the logger off the context, so nothing else can be mis-stamped yet. That
// is exactly why a test cannot catch this and a structural check has to: the
// defect is invisible until someone adds a log line one layer down, and by then
// the wrong request id is already in production logs.
//
// The failure it prevents is the one callCtx's own comment describes. The logger
// already on a handler's context belongs to whichever request opened the SESSION,
// not to this call. Two spellings for one concept leave the next tool author
// picking one at random, and the choice decides which request id a line a layer
// down carries.

// mcpPackage is the adapter this guard is about. Handlers live in files under it.
const mcpPackage = "src/identity/internal/mcp/"

// outboundCallSites returns the name of every function in f that calls a method
// named "outbound", one entry per call.
//
// It matches on the method name rather than on the receiver's type, because a
// guard that resolved types would need the whole package loaded and would go
// quiet the moment it could not. A false positive here is a method someone else
// named "outbound", which is a name worth a second look anyway.
func outboundCallSites(f *ast.File) []string {
	var sites []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "outbound" {
				sites = append(sites, fn.Name.Name)
			}
			return true
		})
	}
	return sites
}

// TestOutboundContextIsBuiltInOnePlace fails when anything in the MCP adapter
// builds an outbound context other than callCtx itself.
//
// Both directions fail, and both matter. A second caller is the drift this
// exists to stop. No caller at all means callCtx no longer builds on
// caller.outbound, so the correlation id it was carrying has gone somewhere this
// guard is not watching.
func TestOutboundContextIsBuiltInOnePlace(t *testing.T) {
	t.Parallel()
	const builder = "callCtx"
	var callers []string
	forEachAppFile(t, func(rel string, f *ast.File) {
		if !strings.HasPrefix(rel, mcpPackage) {
			return
		}
		for _, fn := range outboundCallSites(f) {
			callers = append(callers, rel+":"+fn)
		}
	})
	if len(callers) != 1 || !strings.HasSuffix(callers[0], ":"+builder) {
		t.Errorf("caller.outbound is called from %v, want exactly one call, in %s — "+
			"a handler building its own outbound context leaves the session's logger "+
			"in place, so a line added one layer down carries the request id of "+
			"whichever request opened the session rather than this call's",
			callers, builder)
	}
}

// TestMeta_OutboundDetectorFires is the guard's own negative. A structural check
// that cannot see the thing it forbids reports a clean tree forever, which is
// the failure mode this repository has hit before.
func TestMeta_OutboundDetectorFires(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"the bare call a handler would write": `t.ramp.Execute(who.outbound(ctx), rpc)`,
		"assigned first":                      `c := who.outbound(ctx); use(c)`,
		"through another receiver name":       `t.reports.Report(caller.outbound(ctx), r)`,
		"nested in a further call":            `t.deliver(wrap(who.outbound(ctx)), log)`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc handler() { "+body+" }\n")
			if got := outboundCallSites(f); len(got) == 0 {
				t.Fatalf("detector passed a hand-built outbound context: %s", body)
			}
		})
	}
}

// TestMeta_OutboundDetectorPassesWhatItShould keeps the guard from objecting to
// the form every handler is supposed to use. A guard that flagged callCtx calls
// would be removed rather than obeyed.
func TestMeta_OutboundDetectorPassesWhatItShould(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"the form handlers use":     `t.ramp.Execute(t.callCtx(ctx, who), rpc)`,
		"an unrelated method":       `t.reports.Report(who.inbound(ctx), r)`,
		"a field, not a call":       `use(who.outbound)`,
		"a same-named local string": `outbound := "x"; use(outbound)`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc handler() { "+body+" }\n")
			if got := outboundCallSites(f); len(got) != 0 {
				t.Fatalf("detector flagged a line the adapter is meant to have: %s", body)
			}
		})
	}
}
