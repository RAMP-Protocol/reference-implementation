package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Render writes the chain and its assertions. Text, not JSON: the audience is a
// person reading a terminal, and the values a machine would want are the ones
// the admin RPC already serves.
func Render(w io.Writer, l Ledger) error {
	var b strings.Builder
	line(&b, "RAMP evidence chain\n  transaction %s\n  tenant      %s\n\n", l.TransactionID, l.TenantID)
	renderRows(&b, l.Rows)
	b.WriteString("\n")
	renderAssertions(&b, l.Assertions)
	_, err := io.WriteString(w, b.String())
	return err
}

// line writes one formatted line. Every destination here is a strings.Builder,
// directly or behind a tabwriter, and neither can fail — so the error is
// discarded in this one place rather than at every call site.
func line(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func renderRows(b *strings.Builder, rows []Row) {
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	line(tw, "PARTY\tSTEP\tEVENT\tCORRELATOR\tCRYPTO\n")
	for _, r := range rows {
		if r.Absence != "" {
			// A gap prints its reason across the row rather than leaving empty
			// cells, which would read as a step that happened and recorded
			// nothing.
			line(tw, "%s\t%s\t— %s\n", r.Party, r.Step, r.Absence)
			continue
		}
		line(tw, "%s\t%s\t%s\t%s\t%s\n", r.Party, r.Step, r.Event, r.Correlator, r.Crypto)
	}
	// tabwriter buffers until Flush; the error it reports is the underlying
	// writer's, and a strings.Builder never fails.
	_ = tw.Flush()
}

// renderAssertions prints each verdict with one of three marks and then a
// summary that keeps them apart. A check whose source was never read is NOT a
// failed check, and collapsing the two would make an operator with a closed
// tunnel see the same output as an operator holding a forged row.
func renderAssertions(b *strings.Builder, assertions []Assertion) {
	b.WriteString("ASSERTIONS\n")
	held, failed, skipped := 0, 0, 0
	for _, a := range assertions {
		var mark string
		switch {
		case a.Unchecked:
			mark, skipped = "?", skipped+1
		case a.OK:
			mark, held = "v", held+1
		default:
			mark, failed = "x", failed+1
		}
		line(b, "  [%s] %s\n        %s\n", mark, a.Name, a.Detail)
	}
	line(b, "\n%d of %d checked assertions hold", held, held+failed)
	if failed > 0 {
		line(b, "; %d FAILED", failed)
	}
	if skipped > 0 {
		line(b, "; %d could not be checked because a source was not read", skipped)
	}
	b.WriteString(".\n")
}
