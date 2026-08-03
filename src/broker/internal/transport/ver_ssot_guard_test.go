package transport

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This is a STRUCTURAL guard, not a behavioral test. It pins the Ver-SSOT
// invariant: there is exactly ONE source of truth for the RAMP wire-protocol
// version stamped on every system-authored proto message — internal/proto.Ver
// (rampproto.Ver) — so a proto major-version bump flips a single constant and
// can never silently skew a subset of authored messages.
//
// The disease is system-authored RAMP response builders that stamp a bare
// string literal `Ver: "1.0"` instead of routing through rampproto.Ver.
// rampproto.Ver == "1.0" today, so this is a behavioral no-op; only a
// source-level guard can lock the single-bump-point invariant (a behavioral
// test would merely assert "1.0" == "1.0", which existing integration tests
// already do).
//
// The guard goes RED on HEAD: the 4 MIGRATE sites still stamp the literal —
//   - src/exchange/internal/service/exchange.go      (ResourceResponse)
//   - src/exchange/internal/service/exchange_batch.go (TransactionResponse)
//   - src/broker/internal/transport/exchange_relay_batch.go (merged TransactionResponse)
//   - src/broker/internal/transport/canonical.go     (DiscoveryResponse)
//
// After the fix they read `Ver: rampproto.Ver` and the guard goes GREEN.
//
// ALLOWLISTed sites are NOT bare string literals so they never trip the guard:
//   - resolve.go (`Ver: rampproto.Ver`) — the exemplar.
//   - the 3 echo sites (`Ver: req.GetVer()` / `txReq.GetVer()` / `m.GetVer()`) —
//     they relay an inbound agent's own ver verbatim, not system-authored.
//   - internal/rampwellknown/... (`Ver: rampwellknown.Version`) — a different
//     namespace AND under internal/, not src/, so doubly excluded by scope.
//
// Modeled on unregistered_endpoint_guard_test.go: whitespace-normalized source
// scan + matcher meta-tests (positive / negative / regex-slip).

// verLiteralPattern matches a `Ver:` struct-field assignment whose value is a
// bare double-quoted string literal, e.g. `Ver: "1.0"`. Interior whitespace
// between the colon and the literal is collapsed by the caller (via
// strings.Fields), so a tab- or multi-space-aligned form (gofumpt aligns struct
// keys) is matched identically to a single-space form. `Ver: rampproto.Ver`,
// `Ver: req.GetVer()`, etc. do not match because the value is not a quoted
// string.
var verLiteralPattern = regexp.MustCompile(`\bVer:\s*"[^"]*"`)

// countVerLiteral reports how many `Ver: "<literal>"` field assignments occur in
// src after collapsing interior whitespace, so an alignment variant (extra
// spaces, a tab, or a value pushed onto the next line) is counted the same as
// the canonical spelling and cannot slip past.
func countVerLiteral(src string) int {
	normalized := strings.Join(strings.Fields(src), " ")
	return len(verLiteralPattern.FindAllString(normalized, -1))
}

// repoRoot walks parent directories from the test's working directory until it
// finds the one containing go.mod, returning that path. The guard must read
// production source in BOTH the broker transport package and the exchange
// service package, so it anchors at the repo root rather than the package dir.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("walked to filesystem root without finding go.mod (started from %s)", dir)
		}
		dir = parent
	}
}

// TestVerIsSingleSourced walks every production (non-test) .go file under src/
// and fails if any of them stamps a bare string literal on a `Ver:` struct
// field. Every system-authored RAMP message builder must route through
// rampproto.Ver instead, so a proto major bump flips one constant rather than
// skewing a subset of authored messages.
func TestVerIsSingleSourced(t *testing.T) {
	t.Parallel() // pure source scan — no shared DB, safe to parallelize.

	root := repoRoot(t)
	srcDir := filepath.Join(root, "src")

	var offenders []string
	walkErr := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return rerr
		}
		if n := countVerLiteral(string(b)); n > 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			offenders = append(offenders, rel)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", srcDir, walkErr)
	}

	if len(offenders) > 0 {
		t.Fatalf("system-authored builder(s) stamp a bare Ver string literal in %v — "+
			"route the RAMP message version through rampproto.Ver (internal/proto.Ver) "+
			"so a proto major bump flips ONE constant and can never silently skew a "+
			"subset of authored messages", offenders)
	}
}

// TestVerLiteralMatcher_MetaTests pins the matcher itself: a bare literal (in
// any whitespace/alignment form) is detected as a violation, while the canonical
// constant and the echo-back GetVer() forms are not — so a formatting variant
// cannot slip past and an allowlisted form cannot false-positive.
func TestVerLiteralMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"positive_bare_literal", `Ver: "1.0",`, 1},
		{"negative_constant", `Ver: rampproto.Ver,`, 0},
		{"negative_echo_req", `Ver: req.GetVer(),`, 0},
		{"negative_echo_tx", `Ver: txReq.GetVer(),`, 0},
		{"negative_echo_manifest", `Ver: m.GetVer(),`, 0},
		// regex-slip: gofumpt aligns struct keys with extra spaces / tabs; the
		// literal padded apart from the colon must still be detected.
		{"slip_multi_space", `Ver:               "1.0",`, 1},
		{"slip_tab", "Ver:\t\"1.0\",", 1},
		{"slip_split_across_lines", "Ver:\n\t\t\"1.0\",", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := countVerLiteral(c.src); got != c.want {
				t.Fatalf("countVerLiteral(%q) = %d, want %d", c.src, got, c.want)
			}
		})
	}
}
