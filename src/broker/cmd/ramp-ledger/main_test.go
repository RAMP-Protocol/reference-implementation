package main

import (
	"slices"
	"testing"
)

// The sweep is the only thing that finds a delivery record, and Lambda@Edge
// writes its logs in the region of the point of presence that served the
// request. A region dropped from this list is invisible: the chain still
// renders and the delivery row simply reads "not recorded", which looks like
// CloudWatch ingestion lag rather than a shortened search. This pins the list
// so shrinking it has to be a deliberate edit to a test.
func TestDefaultEdgeRegions_coversTheSweptPointsOfPresence(t *testing.T) {
	t.Parallel()
	want := []string{
		"us-east-1", "us-east-2", "us-west-2",
		"eu-west-1", "eu-central-1", "eu-north-1",
		"ap-southeast-1", "ap-northeast-1",
	}
	if !slices.Equal(defaultEdgeRegions, want) {
		t.Errorf("default sweep = %v, want %v", defaultEdgeRegions, want)
	}
}

// An operator who names regions gets exactly those; one who names none, or
// names only separators, falls back to the default sweep. Returning an empty
// list for the second case would search nowhere and report the delivery as
// missing, which is the same silent failure a shortened list produces.
func TestSplitRegions_fallsBackWhenTheOperatorNamesNone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: defaultEdgeRegions},
		{name: "whitespace only", raw: "   ", want: defaultEdgeRegions},
		{name: "separators only", raw: ",,, ,", want: defaultEdgeRegions},
		{name: "one region", raw: "eu-west-2", want: []string{"eu-west-2"}},
		{name: "spaces are trimmed", raw: " eu-west-2 , us-east-1 ", want: []string{"eu-west-2", "us-east-1"}},
		{name: "empty entries are dropped", raw: "eu-west-2,,us-east-1", want: []string{"eu-west-2", "us-east-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := splitRegions(tc.raw); !slices.Equal(got, tc.want) {
				t.Errorf("splitRegions(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// The tool refuses only what makes the run impossible. A missing Broker DSN or
// edge log group is a narrower chain, not an error, and the rendered gap says
// which leg is missing and why.
func TestValidate_requiresOnlyTheTransactionAndTheAdminURL(t *testing.T) {
	t.Parallel()
	full := Config{TransactionID: "tx-1", AdminURL: "http://127.0.0.1:8091"}

	if err := validate(full); err != nil {
		t.Errorf("a transaction id and an admin URL should be enough: %v", err)
	}

	noTx := full
	noTx.TransactionID = ""
	if err := validate(noTx); err == nil {
		t.Error("a run with no transaction id was accepted")
	}

	noURL := full
	noURL.AdminURL = ""
	if err := validate(noURL); err == nil {
		t.Error("a run with no admin URL was accepted")
	}
}
