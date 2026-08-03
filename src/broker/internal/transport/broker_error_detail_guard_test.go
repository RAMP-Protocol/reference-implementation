package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is a STRUCTURAL guard, not a behavioral test. It pins the NON-behavioral
// half of the ADR-019 broker error-parity disease: a future broker fault sink
// must NOT assemble a rampv1.ErrorDetail inline (struct literal or
// connect.NewErrorDetail) — it must route through the single shared
// brokerDetail/attachDetail builders in broker_error_detail.go, so the
// Domain + Message + metadata-ride cannot drift between sinks. Inline assembly
// produces byte-identical wire output when metadata is empty, so no integration
// test can observe the bypass; only a source-level guard catches a new sink that
// re-inlines the envelope. (Sanctioned structural-disease exception: a
// source/structural check IS the test where the disease has no runtime-observable
// behavior.) The behavioral half — that the offending field rides as typed
// ErrorDetail.metadata — is pinned by the per-fault integration tests, not here.

// canonicalDetailFile is the ONE place inline ErrorDetail assembly is allowed:
// the shared builder/attach helpers every sink delegates to.
const canonicalDetailFile = "broker_error_detail.go"

// inlineDetailBanned reports whether src contains an inline rampv1.ErrorDetail
// assembly form (struct literal or the connect.NewErrorDetail constructor). It
// normalizes interior whitespace so a "rampv1.ErrorDetail {" or
// "connect.NewErrorDetail (" spacing variant cannot slip the check.
func inlineDetailBanned(src string) bool {
	normalized := strings.Join(strings.Fields(src), " ")
	// Collapse "Foo {" -> "Foo{" and "Foo (" -> "Foo(" so a spacing variant of
	// the banned form is caught the same as the canonical spelling.
	normalized = strings.ReplaceAll(normalized, " {", "{")
	normalized = strings.ReplaceAll(normalized, " (", "(")
	return strings.Contains(normalized, "rampv1.ErrorDetail{") ||
		strings.Contains(normalized, "connect.NewErrorDetail(")
}

// TestNoInlineErrorDetailAssembly walks every non-test .go file in the broker
// transport package (except the canonical builder) and fails if any re-inlines
// the ErrorDetail envelope instead of delegating to brokerDetail/attachDetail.
func TestNoInlineErrorDetailAssembly(t *testing.T) {
	t.Parallel() // pure source scan — no shared DB, safe to parallelize.

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") || name == canonicalDetailFile {
			continue
		}
		b, rerr := os.ReadFile(filepath.Clean(name))
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		if inlineDetailBanned(string(b)) {
			offenders = append(offenders, name)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("inline rampv1.ErrorDetail assembly found in %v — route the fault "+
			"through brokerDetail/attachDetail (%s) instead so the Domain + metadata "+
			"ride cannot drift between sinks (ADR-019)", offenders, canonicalDetailFile)
	}
}

// TestInlineDetailMatcher_MetaTests pins the matcher itself: a positive case it
// MUST flag, a negative case it MUST pass, and a whitespace "would-be-missed"
// slip variant it MUST still catch.
func TestInlineDetailMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"positive_struct_literal", `d := &rampv1.ErrorDetail{Message: m}`, true},
		{"positive_constructor", `detail, _ := connect.NewErrorDetail(d)`, true},
		{"negative_uses_builder", `body, _ := protojson.Marshal(brokerDetail(err))`, false},
		{"negative_attachDetail", `return attachDetail(ce, brokerDetail(err))`, false},
		{"slip_space_before_brace", "d := &rampv1.ErrorDetail {Message: m}", true},
		{"slip_space_before_paren", "connect.NewErrorDetail (d)", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineDetailBanned(c.src); got != c.want {
				t.Fatalf("inlineDetailBanned(%q) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}
