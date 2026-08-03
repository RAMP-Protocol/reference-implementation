package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is a STRUCTURAL guard, not a behavioral test. It pins the DE-DUP half of
// the registry-result reject disease: the SSRF-gate fault "resolved endpoint %q
// is not a registered exchange" was historically emitted from TWO
// byte-identical sites (the discover preflight and the batch per-group
// resolution). They were collapsed into the ONE shared constructor —
// relay.UnregisteredEndpointError, now owned by the relay service layer
// (src/broker/internal/relay) — which also rides the rejected endpoint as
// typed ErrorDetail.metadata. A future sink that re-inlines the message
// literal would (a) drift the wire text and (b) skip the metadata ride, while
// producing byte-identical output whenever metadata happens to be empty — so
// only a source-level guard catches the re-duplication. The metadata-ride
// half is pinned structurally by broker_error_detail_guard_test.go (no inline
// ErrorDetail assembly) and behaviorally by the per-fault integration tests.

// unregisteredEndpointLiteral is the SSRF-gate reject message. It must appear
// across the transport + relay package sources EXACTLY ONCE — inside
// relay.UnregisteredEndpointError — so the two historical call sites cannot
// drift back apart.
const unregisteredEndpointLiteral = "resolved endpoint %q is not a registered exchange"

// constructorDefFile is the ONE file allowed to spell the literal: the shared
// constructor every reject site delegates to, in the relay service layer.
const constructorDefFile = "relay.go"

// scannedDirs are the packages the guard sweeps: the transport adapter (where
// the disease historically lived) and the relay service layer (where the
// single constructor now lives).
var scannedDirs = []string{".", "../relay"}

// countLiteral reports how many times the SSRF-gate literal occurs in src after
// collapsing interior whitespace, so a re-inlined copy split across lines or
// padded with extra spaces is counted the same as the canonical spelling.
func countLiteral(src string) int {
	normalized := strings.Join(strings.Fields(src), " ")
	return strings.Count(normalized, unregisteredEndpointLiteral)
}

// TestUnregisteredEndpointLiteralIsSingleSourced walks every non-test .go file
// in the broker transport and relay packages and fails if the SSRF-gate reject
// literal appears anywhere other than the single shared constructor (or more
// than once there) — i.e. if a new fault site re-inlined the message instead
// of calling relay.UnregisteredEndpointError.
func TestUnregisteredEndpointLiteralIsSingleSourced(t *testing.T) {
	t.Parallel() // pure source scan — no shared DB, safe to parallelize.

	var offenders []string
	total := 0
	for _, dir := range scannedDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read package dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, rerr := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
			if rerr != nil {
				t.Fatalf("read %s: %v", name, rerr)
			}
			n := countLiteral(string(b))
			total += n
			if n > 0 && (name != constructorDefFile || dir == ".") {
				offenders = append(offenders, filepath.Join(dir, name))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("SSRF-gate reject literal re-inlined in %v — call the shared "+
			"relay.UnregisteredEndpointError(endpoint) constructor (../relay/%s) instead "+
			"so the message and the resolved_endpoint metadata ride cannot drift between "+
			"sites (ADR-019 + jscpd-zero)", offenders, constructorDefFile)
	}
	if total != 1 {
		t.Fatalf("SSRF-gate reject literal appears %d times across transport+relay, want "+
			"exactly 1 (in ../relay/%s) — a duplicate re-introduces the disease",
			total, constructorDefFile)
	}
}

// TestUnregisteredEndpointMatcher_MetaTests pins the matcher itself: a single
// occurrence and a constructor call (no literal) are fine; two occurrences and a
// whitespace "would-be-missed" slip variant are both counted.
func TestUnregisteredEndpointMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"negative_constructor_call", `return "", unregisteredEndpointError(endpoint)`, 0},
		{"positive_single", `broker.Newf(k, "resolved endpoint %q is not a registered exchange", ep)`, 1},
		{"positive_duplicate", `a("resolved endpoint %q is not a registered exchange"); b("resolved endpoint %q is not a registered exchange")`, 2},
		{
			"slip_split_across_lines",
			"broker.Newf(k,\n\t\t\"resolved endpoint %q is not a registered exchange\",\n\t\tep)",
			1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := countLiteral(c.src); got != c.want {
				t.Fatalf("countLiteral(%q) = %d, want %d", c.src, got, c.want)
			}
		})
	}
}
