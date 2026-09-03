package service

import "testing"

// TestOverdueRule_Blocks pins the reporting-compliance thresholds.
//
// The rule is unit-tested because the absolute cap cannot be reached affordably
// through the public RPC: 11 overdue obligations below the 20% rate needs 55
// obligations, which is 55 executes plus 44 reports. The rate boundary the
// acceptance criteria name is also driven end-to-end through ExecuteTransaction
// in the transport suite; this table is what covers the cap, which is the half
// of the policy the protocol does not give us.
//
// The boundary rows are what pin the two numbers, so a change to either fails
// here. AtTheCapBelowTheRate against CapFiresBelowTheRate fixes the cap at
// exactly 10: a cap of 9 blocks the first, a cap of 11 lets the second through.
// OneOfFive against OneOfFour fixes the divisor at exactly 5 the same way. The
// rate is the protocol's 20% MAY; the cap, the denominator and the absence of an
// evaluation period are this Exchange's own policy.
func TestOverdueRule_Blocks(t *testing.T) {
	t.Parallel() // pure arithmetic — no shared DB.

	cases := []struct {
		name    string
		overdue int64
		due     int64
		want    bool
		why     string
	}{
		{
			name: "NothingDue", overdue: 0, due: 0, want: false,
			why: "a new agent has nothing to be behind on",
		},
		{
			name: "AllReported", overdue: 0, due: 40, want: false,
			why: "every report filed, however late each one was",
		},
		{
			name: "FirstMissedReport", overdue: 1, due: 1, want: true,
			why: "100% — no minimum sample size, so the first miss blocks",
		},
		{
			name: "OneOfFour", overdue: 1, due: 4, want: true,
			why: "25% is above the rate ceiling",
		},
		{
			name: "OneOfFive", overdue: 1, due: 5, want: false,
			why: "exactly 20% — the ceiling is 'above', not 'at'",
		},
		{
			name: "TwoOfTen", overdue: 2, due: 10, want: false,
			why: "exactly 20%",
		},
		{
			name: "ThreeOfTen", overdue: 3, due: 10, want: true,
			why: "30%",
		},
		{
			name: "CapFiresBelowTheRate", overdue: 11, due: 55, want: true,
			why: "exactly 20% passes the rate, but 11 unreported obligations is too " +
				"many in absolute terms — this is the case the cap exists for, and " +
				"55 due is the cheapest way to reach it",
		},
		{
			name: "AtTheCapBelowTheRate", overdue: 10, due: 55, want: false,
			why: "18.1%, and 10 is at the cap rather than above it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultOverdueRule.blocks(tc.overdue, tc.due); got != tc.want {
				t.Errorf("blocks(%d overdue of %d due) = %v, want %v — %s",
					tc.overdue, tc.due, got, tc.want, tc.why)
			}
		})
	}
}
