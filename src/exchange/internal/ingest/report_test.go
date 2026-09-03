package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	connect "connectrpc.com/connect"

	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
)

// exchangeRefusal is the error a submission the Exchange REFUSED carries, in
// the shape the SDK's CatalogClient actually returns one: a *CallError the
// client classified CallRefused, wrapping the Connect error the peer sent. The
// peer answered and said no, so nothing from that range is stored.
//
// It is built the way sdkconnect.sendError builds it — kind, op, the peer's
// code as the reason, the Connect error kept in the chain — because a fixture
// that is not the client's own shape tests a case the client cannot produce.
func exchangeRefusal(msg string) error {
	return &sdkconnect.CallError{
		Kind:   sdkconnect.CallRefused,
		Op:     "push resources",
		Reason: connect.CodeInvalidArgument.String(),
		Err:    connect.NewError(connect.CodeInvalidArgument, errors.New(msg)),
	}
}

// unreachable is the error a submission carries when the call never got an
// answer: the client's own classification for a dial failure, a deadline, or a
// dropped connection. push_test.go proves the real client produces this kind
// for a timeout and for a reset connection; this builds the same shape for the
// table below.
func unreachable(cause error) error {
	return &sdkconnect.CallError{Kind: sdkconnect.CallUnreachable, Op: "push resources", Err: cause}
}

// TestEntriesPerSubmission_ReadsAWireBound pins that the bound comes off the
// pinned descriptor and is a size a feed can be split at. Its exact value is
// the wire's to set; the ingest e2e proves the value read here is the one the
// Exchange enforces, from both sides of the bound.
func TestEntriesPerSubmission_ReadsAWireBound(t *testing.T) {
	t.Parallel()
	bound, err := EntriesPerSubmission()
	if err != nil {
		t.Fatalf("EntriesPerSubmission: %v", err)
	}
	if bound < 2 {
		t.Fatalf("bound = %d; a submission bound a feed can be split at is at least 2", bound)
	}
}

// TestSubmissionsNeeded pins the ceiling division a run plans with.
func TestSubmissionsNeeded(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ n, bound, want int }{
		{1, 256, 1}, {256, 256, 1}, {257, 256, 2}, {512, 256, 2}, {513, 256, 3}, {1, 1, 1}, {3, 1, 3},
	} {
		if got := submissionsNeeded(tc.n, tc.bound); got != tc.want {
			t.Errorf("submissionsNeeded(%d, %d) = %d, want %d", tc.n, tc.bound, got, tc.want)
		}
	}
}

// refusedAt builds the report of a run over entries entries at bound per
// submission that stopped at the submission covering [first, last]: every
// submission before it is stored in full.
func refusedAt(entries, bound, first, last int, cause error) PushReport {
	r := PushReport{Entries: entries, Planned: submissionsNeeded(entries, bound)}
	for i := 0; i < first; i += bound {
		r.Submissions = append(r.Submissions, SubmissionResult{First: i, Last: i + bound - 1, Accepted: int32(bound)})
		r.Accepted += int32(bound)
	}
	r.Submissions = append(r.Submissions, SubmissionResult{First: first, Last: last, Err: cause})
	return r
}

// TestPushReport_RefusalNamesStoredRefusedAndUnsent pins the wording of the
// error a refused submission produces, for the three positions a refusal can
// take: first (nothing stored), middle (a stored range before it and an unsent
// range after it), last (nothing after it). The cause stays in the chain so a
// caller can still read the client's classification off it.
//
// The two halves this package writes are asserted exactly; the cause between
// them is asserted with errors.Is instead. The cause's text is the SDK's
// rendering of its own CallError, so pinning it here would make a reword
// upstream fail a test about this package's sentence.
func TestPushReport_RefusalNamesStoredRefusedAndUnsent(t *testing.T) {
	t.Parallel()
	cause := exchangeRefusal("refused by the exchange")
	cases := map[string]struct {
		report             PushReport
		wantHead, wantTail string
	}{
		"only submission": {
			refusedAt(10, 10, 0, 9, cause),
			"submission 1 of 1 (entries 0-9) refused: ",
			"; nothing was stored before it; no entries followed it",
		},
		"middle submission": {
			refusedAt(513, 256, 256, 511, cause),
			"submission 2 of 3 (entries 256-511) refused: ",
			"; entries 0-255 were stored before it; entries 512-512 were not sent",
		},
		"last submission": {
			refusedAt(257, 256, 256, 256, cause),
			"submission 2 of 2 (entries 256-256) refused: ",
			"; entries 0-255 were stored before it; no entries followed it",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.report.refusal()
			if err == nil {
				t.Fatal("refusal() returned nil for a report that stopped at a submission")
			}
			if got := err.Error(); !strings.HasPrefix(got, tc.wantHead) || !strings.HasSuffix(got, tc.wantTail) {
				t.Fatalf("refusal() = %q\nwant it to start %q and end %q", got, tc.wantHead, tc.wantTail)
			}
			if !errors.Is(err, cause) {
				t.Error("the refusing call's error is not in the chain")
			}
		})
	}
	if err := (PushReport{Submissions: []SubmissionResult{{First: 0, Last: 1}}}).refusal(); err != nil {
		t.Errorf("a report with every submission stored has no refusal, got %v", err)
	}
}

// TestSubmissionResult_UnconfirmedSeparatesNoVerdictFromRefusal pins the
// predicate the report's two failure labels turn on, over every kind the SDK
// client can classify a failure as.
//
// The question is whether the Exchange answered. Only CallUnreachable says it
// did not. A refusal and an over-cap rejection are both verdicts; the three
// nothing-left-the-process kinds mean the range cannot be stored either. What
// remains is an error the SDK did not classify, and the one producer of that is
// a 2xx whose accepted count disagreed with what was sent — the sharpest case
// of all, because the Exchange answered SUCCESS, so its entries are very likely
// stored and printing that range as refused told an operator the opposite.
//
// Every kind gets a row rather than the interesting ones, so a kind added to
// the SDK later shows up here as a case nobody classified instead of falling
// silently into the default.
func TestSubmissionResult_UnconfirmedSeparatesNoVerdictFromRefusal(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"stored":                     {nil, false},
		"exchange refused":           {exchangeRefusal("boom"), false},
		"answer past the read cap":   {&sdkconnect.CallError{Kind: sdkconnect.CallTooLarge}, false},
		"never sent":                 {&sdkconnect.CallError{Kind: sdkconnect.CallNotSent}, false},
		"could not be built":         {&sdkconnect.CallError{Kind: sdkconnect.CallMalformed}, false},
		"could not be signed":        {&sdkconnect.CallError{Kind: sdkconnect.CallNotSignable}, false},
		"connection dropped":         {unreachable(errors.New("read tcp: connection reset by peer")), true},
		"deadline before any answer": {unreachable(context.DeadlineExceeded), true},
		"short accepted count":       {shortAcceptance(3, 10), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := (SubmissionResult{Err: tc.err}).Unconfirmed(); got != tc.want {
				t.Errorf("Unconfirmed() = %v, want %v (err=%v)", got, tc.want, tc.err)
			}
		})
	}
	// The classification survives a wrap in both directions: errors.As walks the
	// chain, so a caller that adds context to either error does not flip the
	// label it carries.
	wrapped := fmt.Errorf("push submission 2: %w", exchangeRefusal("boom"))
	if (SubmissionResult{Err: wrapped}).Unconfirmed() {
		t.Error("a wrapped refusal reads as unconfirmed; the client's classification is still in the chain")
	}
	wrappedSilence := fmt.Errorf("push submission 2: %w", unreachable(context.DeadlineExceeded))
	if !(SubmissionResult{Err: wrappedSilence}).Unconfirmed() {
		t.Error("a wrapped unreachable call reads as refused; the client's classification is still in the chain")
	}
}

// TestPushReport_UnconfirmedSubmissionIsNotCalledRefused pins the error text
// for the case the labels exist for: the run stopped without a verdict, so it
// must not claim the range was refused, and it must say the entries may be
// stored.
func TestPushReport_UnconfirmedSubmissionIsNotCalledRefused(t *testing.T) {
	t.Parallel()
	err := refusedAt(513, 256, 256, 511, shortAcceptance(3, 256)).refusal()
	if err == nil {
		t.Fatal("a run that stopped at an unconfirmed submission returned no error")
	}
	got := err.Error()
	if !strings.Contains(got, "submission 2 of 3 (entries 256-511) not confirmed (its entries may or may not be stored)") {
		t.Errorf("error does not name the submission as unconfirmed:\n%s", got)
	}
	// The outcome word specifically, not the word anywhere: the short-count
	// message explains the all-or-nothing contract and says "refused whole"
	// inside its own sentence.
	if strings.Contains(got, "(entries 256-511) refused:") {
		t.Errorf("error calls an unconfirmed submission refused:\n%s", got)
	}
	if !strings.Contains(got, "entries 0-255 were stored before it") || !strings.Contains(got, "entries 512-512 were not sent") {
		t.Errorf("error drops the stored or unsent range:\n%s", got)
	}
}

// TestWriteReport pins the stderr shape the harness and an operator read: one
// summary line for a single stored submission, and the per-submission lines —
// stored, refused, not sent — once a feed took several or one was refused.
func TestWriteReport(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	WriteReport(&out, PushReport{
		Entries: 3, Planned: 1, Accepted: 3, Warnings: []string{"w1"},
		Submissions: []SubmissionResult{{First: 0, Last: 2, Accepted: 3, Warnings: []string{"w1"}}},
	})
	if got, want := out.String(), "push: accepted=3 warnings=1\n  warning: w1\n"; got != want {
		t.Errorf("single stored submission:\n%s\nwant:\n%s", got, want)
	}

	out.Reset()
	WriteReport(&out, refusedAt(513, 256, 256, 511, exchangeRefusal("boom")))
	for _, want := range []string{
		"push: accepted=256 warnings=0\n",
		"  submission 1 of 3 (entries 0-255): stored, accepted=256 warnings=0\n",
		"  submission 2 of 3 (entries 256-511): REFUSED: ",
		"  entries 512-512: not sent\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("refused mid-run report lacks %q:\n%s", want, out.String())
		}
	}

	// The same run, stopped without a verdict. REFUSED means the range is
	// absent; this range may be present, and the line has to say so or an
	// operator reads it as the stronger claim.
	out.Reset()
	WriteReport(&out, refusedAt(513, 256, 256, 511, shortAcceptance(3, 256)))
	if want := "  submission 2 of 3 (entries 256-511): NOT CONFIRMED (the range may or may not be stored): "; !strings.Contains(out.String(), want) {
		t.Errorf("unconfirmed mid-run report lacks %q:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "REFUSED") {
		t.Errorf("an unconfirmed submission is printed as REFUSED:\n%s", out.String())
	}

	out.Reset()
	WriteReport(&out, PushReport{
		Entries: 257, Planned: 2, Accepted: 257,
		Submissions: []SubmissionResult{{First: 0, Last: 255, Accepted: 256}, {First: 256, Last: 256, Accepted: 1}},
	})
	if !strings.Contains(out.String(), "  submission 2 of 2 (entries 256-256): stored, accepted=1 warnings=0\n") ||
		strings.Contains(out.String(), "not sent") {
		t.Errorf("two stored submissions report is wrong:\n%s", out.String())
	}
}
