package ingest

import (
	"fmt"
	"io"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Finding is one thing Check expects the Exchange to say about an entry: a
// reason it would refuse the submission (Violation), or a warning it would
// accept the entry with.
type Finding struct {
	// Record is the entry's 0-based index in the feed — the index MapRecords
	// and the push report name.
	Record int
	// URI is the entry's domain and path concatenated, the way the catalog
	// URI is formed; a path that does not start with "/" shows here as the
	// malformed URI it would produce.
	URI string
	// Rule, Path, Token and Message are the SDK's: the rule id (an
	// ingest-tier id, or the protovalidate id of a wire-tier rule), the field
	// path relative to the entry, the offending token when the rule is about
	// one token, and the human-readable reason.
	Rule, Path, Token, Message string
	// Violation is true for a finding the Exchange refuses the whole
	// submission for, false for one it accepts the entry with.
	Violation bool
}

// String renders the finding as one report line:
// `record N (uri): violation|warning rule=<id> path=<path> [token="<tok>"]: <message>`.
func (f Finding) String() string {
	severity := "warning"
	if f.Violation {
		severity = "violation"
	}
	token := ""
	if f.Token != "" {
		token = fmt.Sprintf(" token=%q", f.Token)
	}
	return fmt.Sprintf("record %d (%s): %s rule=%s path=%s%s: %s",
		f.Record, f.URI, severity, f.Rule, f.Path, token, f.Message)
}

// CheckReport is the verdict of a local feed check.
type CheckReport struct {
	// Records is how many entries the feed mapped to.
	Records int
	// Findings, in feed order; within an entry, violations before warnings,
	// each in the order the SDK reports them.
	Findings []Finding
}

// Violations counts the findings the Exchange would refuse a submission for.
func (r CheckReport) Violations() int {
	n := 0
	for _, f := range r.Findings {
		if f.Violation {
			n++
		}
	}
	return n
}

// Warnings counts the findings the Exchange would accept an entry with.
func (r CheckReport) Warnings() int { return len(r.Findings) - r.Violations() }

// OK reports whether the feed carries no violation. Warnings do not fail it.
func (r CheckReport) OK() bool { return r.Violations() == 0 }

// Check parses and maps feed exactly as Run does, then runs the SDK's entry
// validation over every entry — both tiers the Exchange applies, the wire
// rules over the entry as it would be sent and the ingest-tier checks over
// its canonicalised terms — and reports every finding, so a publisher fixes
// a feed in one round. It never loads a key and never dials: the verdict is
// advice about what the Exchange's own run will say, and that run is the
// deciding one. A feed that does not parse or map is returned as the error,
// exactly as Run would refuse it.
//
// So is a feed that maps to no entries. It parses and it maps, so nothing
// earlier catches it, but the push refuses it before it is sent and the wire
// refuses it after — and a check that answered "clean" for a feed the run
// deterministically rejects would send a publisher into that rejection with a
// green preflight behind them. Both refusals are ErrEmptyFeed, so they read the
// same. Zero findings over zero records is not the same verdict as zero
// findings over a feed.
func Check(feed io.Reader) (CheckReport, error) {
	records, err := ParseJSONL(feed)
	if err != nil {
		return CheckReport{}, err
	}
	entries, err := MapRecords(records)
	if err != nil {
		return CheckReport{}, err
	}
	if len(entries) == 0 {
		return CheckReport{}, ErrEmptyFeed
	}
	report := CheckReport{Records: len(entries)}
	for i, entry := range entries {
		uri := entry.GetDomain() + entry.GetPath()
		verdict := helpers.ValidateResourceEntry(entry)
		for _, v := range verdict.Violations {
			report.Findings = append(report.Findings, Finding{
				Record: i, URI: uri, Rule: v.Rule, Path: v.Path, Token: v.Token, Message: v.Message, Violation: true,
			})
		}
		for _, w := range verdict.Warnings {
			report.Findings = append(report.Findings, Finding{
				Record: i, URI: uri, Rule: w.Rule, Path: w.Path, Token: w.Token, Message: w.Message,
			})
		}
	}
	return report, nil
}

// WriteCheckReport prints one line per finding (Finding.String), then a
// summary line `check: records=N violations=V warnings=W`. Write errors on
// the report sink (stderr) are non-fatal and intentionally ignored: the
// authoritative outcome is the returned CheckReport / process exit code.
func WriteCheckReport(w io.Writer, r CheckReport) {
	for _, f := range r.Findings {
		_, _ = fmt.Fprintln(w, f.String())
	}
	_, _ = fmt.Fprintf(w, "check: records=%d violations=%d warnings=%d\n", r.Records, r.Violations(), r.Warnings())
}
