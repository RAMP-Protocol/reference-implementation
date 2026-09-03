package ingest_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// checkFeed carries one finding of each kind the Exchange can reach: a wire
// violation on the entry envelope (a path with no leading slash, refused by
// the protovalidate pattern on ResourceEntry.path), an ingest-tier violation
// (a bare pricing unit that is not a registered metering token) and a warning
// (a bare restriction token that is not registered — accepted, flagged).
//
// Its last record is the one shape the others do not have: a single record that
// draws TWO violations, one from each tier, over the same two token lists. The
// mapper folds every term before validation, and "scrape" is a registered alias
// of "crawl", so by the time either tier reads the restriction both lists say
// "crawl". The wire rule sees a literal overlap and the ingest-tier rule sees the
// same collision in the tokens the fold produced. This is what a feed author
// actually meets: writing the two accepted spellings of one token, which look
// disjoint on the page, is refused twice over.
const checkFeed = `{"domain":"publisher.example","path":"article-without-slash",` +
	`"terms":[{"semantics":"enumerated","pricing":{"model":"free","rate":"0","currency":"EUR"}}]}
{"domain":"publisher.example","path":"/article/bogus-unit","terms":[{"semantics":"enumerated",` +
	`"functions":["ai-input"],"pricing":{"model":"per_unit","unit":"bogus-unit","rate":"0.01","currency":"EUR"}}]}
{"domain":"publisher.example","path":"/article/odd-function","terms":[{"semantics":"enumerated",` +
	`"functions":["ai-input","totally-made-up-function"],"pricing":{"model":"free","rate":"0","currency":"EUR"}}]}
{"domain":"publisher.example","path":"/article/alias-collision","terms":[{"semantics":"enumerated",` +
	`"functions":["scrape"],"prohibited_functions":["crawl"],"pricing":{"model":"free","rate":"0","currency":"EUR"}}]}
`

// TestCheck_ReportsEveryFindingWithRuleAndPath proves the local check reports
// what the Exchange would say, per record: both tiers' violations with the
// SDK's rule ids and entry-relative field paths, and warnings alongside them
// without failing the check. No key is loaded and nothing is dialled — the
// function takes a reader and nothing else.
func TestCheck_ReportsEveryFindingWithRuleAndPath(t *testing.T) {
	t.Parallel()
	report, err := ingest.Check(strings.NewReader(checkFeed))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Records != 4 {
		t.Fatalf("records = %d, want 4", report.Records)
	}
	// Four violations across four records: the last record draws two on its own,
	// which is the property the alias-collision case exists to pin.
	if report.OK() || report.Violations() != 4 || report.Warnings() != 1 {
		t.Fatalf("verdict = ok %v / %d violations / %d warnings, want not ok / 4 / 1",
			report.OK(), report.Violations(), report.Warnings())
	}

	want := []ingest.Finding{
		{Record: 0, URI: "publisher.examplearticle-without-slash", Rule: "string.pattern", Path: "path", Violation: true},
		{
			Record: 1, URI: "publisher.example/article/bogus-unit",
			Rule: helpers.RulePricingUnitRegistered, Path: "terms[0].pricing.unit", Token: "bogus-unit", Violation: true,
		},
		{
			Record: 2, URI: "publisher.example/article/odd-function",
			Rule: helpers.RuleRestrictionTokenRegistered, Path: "terms[0].restrictions[0].permitted[1]",
			Token: "totally-made-up-function",
		},
		// Both tiers on one record, in the order the composed face returns them.
		// The wire rule names the whole restriction and carries no token: it
		// compares the two lists and reports that they intersect, not which
		// element did it. The ingest-tier rule locates the permitted element and
		// names the canonical token both spellings folded to.
		{
			Record: 3, URI: "publisher.example/article/alias-collision",
			Rule: "restriction.permitted_prohibited_disjoint", Path: "terms[0].restrictions[0]", Violation: true,
		},
		{
			Record: 3, URI: "publisher.example/article/alias-collision",
			Rule: helpers.RuleRestrictionCanonicalDisjoint, Path: "terms[0].restrictions[0].permitted[0]",
			Token: "crawl", Violation: true,
		},
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("findings = %d, want %d: %+v", len(report.Findings), len(want), report.Findings)
	}
	for i, w := range want {
		got := report.Findings[i]
		// The message is the SDK's wording and is asserted only for presence:
		// the corpus the SDK ships pins its text, this test pins the report.
		if got.Message == "" {
			t.Errorf("finding %d carries no message: %+v", i, got)
		}
		got.Message = ""
		if got != w {
			t.Errorf("finding %d = %+v, want %+v", i, got, w)
		}
	}
}

// TestFinding_StringNamesRuleAndPath pins the report line shape the CLI
// prints, including that the token is shown only when the rule is about one.
func TestFinding_StringNamesRuleAndPath(t *testing.T) {
	t.Parallel()
	withToken := ingest.Finding{
		Record: 4, URI: "publisher.example/a", Rule: "pricing.unit.registered", Path: "terms[0].pricing.unit",
		Token: "bogus", Message: `pricing unit "bogus" is not a registered metering token`, Violation: true,
	}
	if got, want := withToken.String(),
		`record 4 (publisher.example/a): violation rule=pricing.unit.registered path=terms[0].pricing.unit `+
			`token="bogus": pricing unit "bogus" is not a registered metering token`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	warning := ingest.Finding{Record: 0, URI: "publisher.example/b", Rule: "r", Path: "p", Message: "m"}
	if got, want := warning.String(), "record 0 (publisher.example/b): warning rule=r path=p: m"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestCheck_SampleFeedIsClean proves the committed reference sample carries no
// violation — the check the CLI's --check runs before a push, over the feed
// the ingest e2e pushes. A warning would not fail it; a violation would.
func TestCheck_SampleFeedIsClean(t *testing.T) {
	t.Parallel()
	f, err := os.Open(filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "publisher", "sample.jsonl"))
	if err != nil {
		t.Fatalf("open sample feed: %v", err)
	}
	defer func() { _ = f.Close() }()
	report, err := ingest.Check(f)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !report.OK() {
		t.Fatalf("sample feed carries %d violation(s): %+v", report.Violations(), report.Findings)
	}
	if report.Records == 0 {
		t.Fatal("sample feed checked to zero records")
	}
}

// warningOnlyFeed is one record whose only finding is a warning: an
// unregistered bare restriction token, which the Exchange accepts and reports
// in PushResourcesResponse.warnings. Nothing about it is a violation.
const warningOnlyFeed = `{"domain":"publisher.example","path":"/article/odd-function","terms":[{"semantics":"enumerated",` +
	`"functions":["ai-input","totally-made-up-function"],"pricing":{"model":"free","rate":"0","currency":"EUR"}}]}
`

// TestCheck_WarningsDoNotFailTheCheck drives the one combination --check exists
// to allow: findings present, none of them a violation. Without it the suite
// covers only not-ok-with-warnings and ok-without-findings, and OK() could be
// tightened to "no findings at all" with every test still passing — which would
// block a publisher from pushing a feed the Exchange stores and merely warns
// about.
func TestCheck_WarningsDoNotFailTheCheck(t *testing.T) {
	t.Parallel()
	report, err := ingest.Check(strings.NewReader(warningOnlyFeed))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !report.OK() {
		t.Errorf("a feed whose only findings are warnings is not OK: %+v", report.Findings)
	}
	if report.Violations() != 0 || report.Warnings() != 1 {
		t.Fatalf("verdict = %d violations / %d warnings, want 0 / 1: %+v",
			report.Violations(), report.Warnings(), report.Findings)
	}
	if got := report.Findings[0]; got.Violation || got.Rule != helpers.RuleRestrictionTokenRegistered {
		t.Errorf("finding = %+v, want a warning carrying %s", got, helpers.RuleRestrictionTokenRegistered)
	}
}

// TestCheck_EmptyFeedIsAnError pins that a feed mapping to no entries gets the
// refusal the push gives it. It parses and it maps, so nothing earlier catches
// it, and a report of zero findings over zero records reads as a clean feed —
// which would send a publisher into a deterministic rejection with a green
// preflight behind them. Both refusals are the same error.
func TestCheck_EmptyFeedIsAnError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, feed string }{
		{"no bytes at all", ""},
		{"blank lines only", "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			report, err := ingest.Check(strings.NewReader(tc.feed))
			if !errors.Is(err, ingest.ErrEmptyFeed) {
				t.Fatalf("Check over an empty feed returned %v; want ErrEmptyFeed", err)
			}
			if report.Records != 0 || len(report.Findings) != 0 {
				t.Errorf("refused check returned a populated report: %+v", report)
			}
		})
	}
}

// TestCheck_FeedThatDoesNotMapIsAnError pins that a feed the mapper refuses is
// returned as the mapper's error — naming the record — not as a clean report:
// the check is as strict as the push about the feed's shape.
func TestCheck_FeedThatDoesNotMapIsAnError(t *testing.T) {
	t.Parallel()
	noPricing := `{"domain":"publisher.example","path":"/a","terms":[{"semantics":"enumerated"}]}` + "\n"
	_, err := ingest.Check(strings.NewReader(noPricing))
	if err == nil || !strings.Contains(err.Error(), "record 0 (publisher.example/a)") {
		t.Fatalf("Check over a feed the mapper refuses returned %v; want the mapper's error naming record 0", err)
	}
}
