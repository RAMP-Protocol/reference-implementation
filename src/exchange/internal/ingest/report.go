package ingest

import (
	"errors"
	"fmt"
	"io"
	"math"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// RepeatedMaxItems is the repeated.max_items rule the pinned protocol module
// authors on one repeated field, read off the descriptor so a bound a caller
// enforces is the wire's and cannot drift from it. A descriptor without the
// rule is a protocol revision the caller was not written against, and is
// refused rather than guessed at. So is a bound of zero, or one larger than an
// int holds on a 32-bit build: neither is a size a list can be split at, and
// treating one as a size would substitute a number nobody chose.
//
// It is exported because the wire bounds have two readers — this package,
// which chunks a feed at the entries bound, and the transport integration
// tests, which drive the caps the same descriptor carries on other fields. One
// reader is what keeps them agreeing on where the rule is found and on when its
// absence is a finding rather than a zero.
func RepeatedMaxItems(message, field protoreflect.Name) (int, error) {
	md := rampv1.File_ramp_v1_ramp_proto.Messages().ByName(message)
	if md == nil {
		return 0, fmt.Errorf("pinned protocol descriptor has no %s message", message)
	}
	fd := md.Fields().ByName(field)
	if fd == nil {
		return 0, fmt.Errorf("pinned protocol descriptor has no %s.%s field", message, field)
	}
	rules, _ := proto.GetExtension(fd.Options(), validate.E_Field).(*validate.FieldRules)
	repeated := rules.GetRepeated()
	if repeated == nil || repeated.MaxItems == nil {
		return 0, fmt.Errorf(
			"%s.%s carries no repeated.max_items rule in the pinned protocol descriptor", message, field)
	}
	maxItems := repeated.GetMaxItems()
	if maxItems == 0 || maxItems > math.MaxInt32 {
		return 0, fmt.Errorf("%s.%s repeated.max_items = %d is not a bound a list can be split at",
			message, field, maxItems)
	}
	return int(maxItems), nil
}

// EntriesPerSubmission is the most entries one PushResources submission may
// carry: RepeatedMaxItems read off PushResourcesRequest.entries. The
// alternatives to refusing a descriptor that carries no such rule are an
// unbounded submission the Exchange refuses whole, or a chunk size nobody
// chose.
func EntriesPerSubmission() (int, error) {
	return RepeatedMaxItems("PushResourcesRequest", "entries")
}

// submissionsNeeded is how many submissions n entries take at bound entries
// per submission.
func submissionsNeeded(n, bound int) int { return (n + bound - 1) / bound }

// SubmissionResult is the outcome of one PushResources call: the contiguous
// slice of the feed it carried, as inclusive 0-based entry indexes in feed
// order (the index MapRecords names), and either the Exchange's counts or the
// error the call ended on. That error is not always a refusal — Unconfirmed
// below is what tells the two apart.
type SubmissionResult struct {
	First, Last int
	Accepted    int32
	Warnings    []string
	Err         error
}

// Stored reports whether the Exchange stored the submission.
func (s SubmissionResult) Stored() bool { return s.Err == nil }

// Unconfirmed reports whether this submission failed WITHOUT a verdict from the
// Exchange, which is a different fact from being refused and the report must
// not print them alike.
//
// The question is whether the Exchange ANSWERED, and only the client knows: it
// is the layer that either got a reply or did not. The SDK carries that as
// CallError.Kind, and CallUnreachable is its name for a peer that never
// answered — a dial failure, a deadline, or a redirect the SDK declined to
// follow. Every CatalogClient verb classifies its transport failure that way,
// so the kind is present on every error the call returns.
//
// It cannot be re-derived here from the error's Go type. The transport codes
// every failure, so a deadline, a dropped connection and a refusal are all
// *connect.Error by the time they arrive, and asking whether a Connect code is
// present answers yes for all three.
//
// CallUnreachable is the ONLY kind that reads as unconfirmed, and the ones left
// out matter:
//
//   - CallRefused is a verdict. The Exchange answered and said no.
//   - CallTooLarge is also a verdict. A submission past the request cap comes
//     back resource_exhausted, which the SDK classifies here; the operator
//     documentation describes that refusal as REFUSED with nothing stored, and
//     the ingest e2e asserts that word. It is a refusal, not a silence.
//   - CallNotSent, CallMalformed and CallNotSignable mean nothing left this
//     process, so nothing can have been stored. REFUSED is imprecise about who
//     refused, but its claim — the range is absent — holds.
//
// An error the SDK did not classify reads as unconfirmed. One produces that
// today: shortAcceptance, a 2xx whose accepted count disagreed with what was
// sent, which is the Exchange reporting success over something. Whether the
// range is stored is unknown either way, and re-running is what settles it — a
// push upserts on the resource URI, so it is safe.
func (s SubmissionResult) Unconfirmed() bool {
	if s.Err == nil {
		return false
	}
	var ce *sdkconnect.CallError
	if errors.As(s.Err, &ce) {
		return ce.Kind == sdkconnect.CallUnreachable
	}
	return true
}

// PushReport is the structured verdict of a push run: the counts the Exchange
// returned for what was stored, plus any non-fatal warnings (unknown vocab
// tokens, OTHER obligations without detail), and one result per submission
// that was sent. The Exchange stores or refuses a submission whole, so a
// refusal is never a count here — it is the last submission's error, and the
// run's returned error.
type PushReport struct {
	// Entries is how many entries the feed mapped to.
	Entries int
	// Planned is how many submissions the feed takes at the wire bound.
	Planned int
	// Accepted is the entry count over the submissions that were stored.
	Accepted int32
	// Warnings, in submission order, then in the order the Exchange returned
	// them.
	Warnings []string
	// Submissions holds one result per submission that was SENT, in feed
	// order. A failed submission is the last one: nothing after it was sent.
	Submissions []SubmissionResult
}

// StoppedAt returns the submission the run stopped at, if it stopped at one.
// Not every one of those was refused — see SubmissionResult.Unconfirmed — which
// is why this is named for where the run stopped rather than for a verdict it
// may not have received.
func (r PushReport) StoppedAt() (SubmissionResult, bool) {
	if n := len(r.Submissions); n > 0 && !r.Submissions[n-1].Stored() {
		return r.Submissions[n-1], true
	}
	return SubmissionResult{}, false
}

// unsent returns the inclusive index range of the entries the stopped run left
// unsent, and false when the submission it stopped at was the last one.
func (r PushReport) unsent() (first, last int, ok bool) {
	failed, stopped := r.StoppedAt()
	if !stopped || failed.Last+1 >= r.Entries {
		return 0, 0, false
	}
	return failed.Last + 1, r.Entries - 1, true
}

// refusal renders the error for a run that stopped: which submission and why,
// what was stored before it, what was left unsent after it. The cause stays in
// the chain, so a caller can still read its Connect code.
//
// It says "refused" only for a submission the Exchange actually refused, and
// says the range is unknown for one that got no verdict — the same split
// writeSubmissions prints, from the same predicate, so the error and the report
// cannot describe one run two ways.
func (r PushReport) refusal() error {
	failed, ok := r.StoppedAt()
	if !ok {
		return nil
	}
	outcome, fate := "refused", ""
	if failed.Unconfirmed() {
		outcome, fate = "not confirmed", " (its entries may or may not be stored)"
	}
	// "before it" is load-bearing. This clause is about the submissions that
	// went first, not about the one the run stopped at — and for an unconfirmed
	// stop those are different claims. Without it the sentence reads "its
	// entries may or may not be stored ... no entries were stored", which
	// answers the question the outcome word just left open, and answers it
	// wrongly.
	stored := "nothing was stored before it"
	if failed.First > 0 {
		stored = fmt.Sprintf("entries 0-%d were stored before it", failed.First-1)
	}
	after := "no entries followed it"
	if first, last, ok := r.unsent(); ok {
		after = fmt.Sprintf("entries %d-%d were not sent", first, last)
	}
	return fmt.Errorf("submission %d of %d (entries %d-%d) %s%s: %w; %s; %s",
		len(r.Submissions), r.Planned, failed.First, failed.Last, outcome, fate, failed.Err, stored, after)
}

// WriteReport prints the structured verdict to w in the shape an operator and
// the e2e harness read: a summary line of what was stored, then — when the
// feed took more than one submission or one failed — a line per submission
// naming the entry range it carried and what became of it, and the range a
// stopped run left unsent, then the warnings. Write errors on the report sink
// (stderr) are non-fatal and intentionally ignored: the authoritative outcome
// is the returned PushReport / process exit code.
func WriteReport(w io.Writer, r PushReport) {
	_, _ = fmt.Fprintf(w, "push: accepted=%d warnings=%d\n", r.Accepted, len(r.Warnings))
	if _, stopped := r.StoppedAt(); stopped || r.Planned > 1 {
		writeSubmissions(w, r)
	}
	for _, warn := range r.Warnings {
		_, _ = fmt.Fprintf(w, "  warning: %s\n", warn)
	}
}

// writeSubmissions prints the per-submission lines of WriteReport.
//
// Three outcomes, not two. REFUSED means the Exchange answered with a verdict
// and stored nothing from that range, which is what the operator documentation
// promises. NOT CONFIRMED means no verdict came back, so the range may be
// stored — printing that one as REFUSED told an operator the entries were
// absent when they may be present, and the report exists to convey exactly that
// distinction.
func writeSubmissions(w io.Writer, r PushReport) {
	for i, s := range r.Submissions {
		if s.Stored() {
			_, _ = fmt.Fprintf(w, "  submission %d of %d (entries %d-%d): stored, accepted=%d warnings=%d\n",
				i+1, r.Planned, s.First, s.Last, s.Accepted, len(s.Warnings))
			continue
		}
		outcome := "REFUSED"
		if s.Unconfirmed() {
			outcome = "NOT CONFIRMED (the range may or may not be stored)"
		}
		_, _ = fmt.Fprintf(w, "  submission %d of %d (entries %d-%d): %s: %v\n",
			i+1, r.Planned, s.First, s.Last, outcome, s.Err)
	}
	if first, last, ok := r.unsent(); ok {
		_, _ = fmt.Fprintf(w, "  entries %d-%d: not sent\n", first, last)
	}
}
