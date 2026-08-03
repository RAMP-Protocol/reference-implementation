package service

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This is a STRUCTURAL guard, not a behavioral test. It pins the
// single-stamp invariant: buildOffer stamps offer.Exchange EXACTLY ONCE. The
// canonical Exchange domain is a static config value (s.cfg.Exchange) set inside the
// signed Offer payload before SignOffer; stamping it twice is a no-behavior
// redundancy (both writes set the identical value and both precede signing, so
// the signed bytes are byte-identical either way).
//
// Because the redundancy is a runtime no-op, the existing behavioral lock
// (discover_offer_exchange_integration_test.go) pins "exchange is present AND
// signed AND tamper-rejected" but would stay green whether the field is stamped
// once or twice. Only a source-level guard can lock the single-stamp invariant.
//
// The guard goes RED on HEAD (commit 0c21a0f2): buildOffer stamps offer.Exchange
// twice —
//   - struct-literal form `Exchange: s.cfg.Exchange` (~line 107)
//   - redundant re-assignment `offer.Exchange = s.cfg.Exchange` (~line 154)
//
// After the fix deletes the re-stamp (discover.go:149-154), exactly one
// stamp remains and the guard goes GREEN.
//
// Modeled on src/broker/internal/transport/ver_ssot_guard_test.go: whitespace-
// normalized source scan + matcher meta-tests (positive / negative / regex-slip).

// exchangeStampPattern matches either form by which buildOffer stamps the
// canonical Exchange domain from static config:
//   - struct-literal:  `Exchange: s.cfg.Exchange`
//   - assignment:      `offer.Exchange = s.cfg.Exchange` (any receiver before .Exchange)
//
// Interior whitespace around the colon / equals is collapsed by the caller (via
// strings.Fields), so a tab- or multi-space-aligned form (gofumpt aligns struct
// keys) is matched identically to a single-space form.
var exchangeStampPattern = regexp.MustCompile(`(?:\bExchange:\s*s\.cfg\.Exchange|\.Exchange\s*=\s*s\.cfg\.Exchange)`)

// buildOfferStartPattern locates the start of the buildOffer method body. The
// guard counts stamps ONLY within that function (between this signature and the
// next top-level `func `), so a stamp in a sibling function cannot inflate or
// deflate the count.
var buildOfferStartPattern = regexp.MustCompile(`func \(s \*ExchangeService\) buildOffer\(`)

// nextTopLevelFuncPattern matches a top-level func declaration at column 0
// (after the normalized newline boundary). Used to bound the buildOffer body.
var nextTopLevelFuncPattern = regexp.MustCompile(`(?m)^func `)

// buildOfferBody returns the source slice of the buildOffer function body,
// starting at the buildOffer signature and ending just before the next
// top-level `func ` declaration (or end of file). It does NOT normalize
// whitespace — that is left to countExchangeStamps so the body isolation works
// on the raw, line-structured source.
func buildOfferBody(tb testing.TB, src string) string {
	tb.Helper()
	loc := buildOfferStartPattern.FindStringIndex(src)
	if loc == nil {
		tb.Fatalf("could not locate buildOffer signature in discover.go source")
	}
	body := src[loc[0]:]
	// Skip past the signature line itself, then find the next top-level func.
	rest := body[len(buildOfferStartPattern.FindString(body)):]
	if next := nextTopLevelFuncPattern.FindStringIndex(rest); next != nil {
		return body[:len(buildOfferStartPattern.FindString(body))+next[0]]
	}
	return body
}

// countExchangeStamps reports how many times buildOffer's body stamps
// offer.Exchange from static config, after collapsing interior whitespace so an
// alignment variant (extra spaces, a tab, or a value pushed onto the next line)
// is counted the same as the canonical spelling and cannot slip past.
func countExchangeStamps(src string) int {
	normalized := strings.Join(strings.Fields(src), " ")
	return len(exchangeStampPattern.FindAllString(normalized, -1))
}

// discoverRepoRoot walks parent directories from the test's working directory
// until it finds the one containing go.mod, returning that path. The guard reads
// production source by absolute path so it does not depend on the test's cwd.
func discoverRepoRoot(tb testing.TB) string {
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

// TestBuildOfferStampsExchangeOnce reads discover.go, isolates the buildOffer
// function body, and fails unless offer.Exchange is stamped from static config
// EXACTLY ONCE. On HEAD it is stamped twice (struct-literal :107 + re-stamp
// :154); after the fix removes the re-stamp, exactly one remains.
func TestBuildOfferStampsExchangeOnce(t *testing.T) {
	t.Parallel() // pure source scan — no shared DB, safe to parallelize.

	root := discoverRepoRoot(t)
	discoverPath := filepath.Join(root, "src", "exchange", "internal", "service", "discover.go")
	b, err := os.ReadFile(filepath.Clean(discoverPath))
	if err != nil {
		t.Fatalf("read %s: %v", discoverPath, err)
	}

	body := buildOfferBody(t, string(b))
	got := countExchangeStamps(body)
	if got != 1 {
		t.Fatalf("buildOffer stamps offer.Exchange %d time(s) from s.cfg.Exchange, want exactly 1 — "+
			"the canonical Exchange domain is a static config value set once in the signed Offer "+
			"payload before SignOffer; stamping it more than once is a redundant no-op. "+
			"Keep the struct-literal stamp and delete the post-construction re-stamp.", got)
	}
}

// TestExchangeStampMatcher_MetaTests pins the matcher itself: a 2-stamp snippet
// is counted 2 (flagged), a 1-stamp snippet is counted 1 (clean), and the
// assignment form is detected under whitespace/tab/line-split variants so a
// formatting change cannot slip a re-stamp past the guard.
func TestExchangeStampMatcher_MetaTests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want int
	}{
		// POSITIVE: both forms present (the HEAD shape) → 2, flagged.
		{
			"positive_two_stamps",
			"offer := &rampv1.Offer{\n\tExchange: s.cfg.Exchange,\n}\noffer.Exchange = s.cfg.Exchange\n",
			2,
		},
		// NEGATIVE: only the struct-literal stamp (the post-fix shape) → 1, clean.
		{
			"negative_one_stamp_literal",
			"offer := &rampv1.Offer{\n\tExchange: s.cfg.Exchange,\n}\n",
			1,
		},
		// NEGATIVE: only the assignment stamp → 1, clean.
		{
			"negative_one_stamp_assignment",
			"offer.Exchange = s.cfg.Exchange\n",
			1,
		},
		// NEGATIVE: no Exchange stamp at all → 0.
		{
			"negative_no_stamp",
			"offer.Signature = sig\n",
			0,
		},
		// regex-SLIP: gofumpt aligns struct keys; an alignment-padded literal
		// must still be detected.
		{"slip_literal_multi_space", `Exchange:               s.cfg.Exchange,`, 1},
		// regex-SLIP: tab between colon and value.
		{"slip_literal_tab", "Exchange:\ts.cfg.Exchange,", 1},
		// regex-SLIP: the assignment form padded around the equals.
		{"slip_assignment_multi_space", `offer.Exchange   =   s.cfg.Exchange`, 1},
		// regex-SLIP: the assignment form with a tab around the equals.
		{"slip_assignment_tab", "offer.Exchange\t=\ts.cfg.Exchange", 1},
		// regex-SLIP: the assignment form split across lines (value on next line).
		{"slip_assignment_split", "offer.Exchange =\n\ts.cfg.Exchange", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := countExchangeStamps(c.src); got != c.want {
				t.Fatalf("countExchangeStamps(%q) = %d, want %d", c.src, got, c.want)
			}
		})
	}
}
