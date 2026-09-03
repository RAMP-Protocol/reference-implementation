// Finding the delivery line: sweeping the regions CloudFront may have served
// from, and refusing argument values the AWS CLI would read as options.
//
// Split from the delivery-line parser's own tests, which read a line once it
// has been found. The two answer different questions — "which region holds it"
// against "what does it say" — and the parser file had grown past the
// file-length gate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeAWS struct {
	byRegion map[string]string
	errors   map[string]error
	asked    []string
}

func (f *fakeAWS) FilterLogEvents(_ context.Context, region, _, pattern string, _ time.Time) ([]byte, error) {
	f.asked = append(f.asked, region)
	if err, ok := f.errors[region]; ok {
		return nil, err
	}
	line, ok := f.byRegion[region]
	if !ok || !strings.Contains(line, pattern) {
		return []byte(`{"events":[]}`), nil
	}
	body, err := json.Marshal(map[string]any{
		"events": []map[string]any{{"message": line, "timestamp": 1786000000000}},
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func TestFindDelivery_sweepsRegionsAndReportsWhichOneServed(t *testing.T) {
	aws := &fakeAWS{
		byRegion: map[string]string{"us-east-1": lambdaLine},
		errors:   map[string]error{"eu-central-1": errNoSuchLogGroup},
	}
	regions := []string{"eu-central-1", "eu-west-1", "us-east-1", "us-west-2"}

	record, err := FindDelivery(context.Background(), aws, "/aws/lambda/us-east-1.edge", regions, digestA, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if record == nil {
		t.Fatal("the record was in us-east-1 but the sweep found nothing")
	}
	if record.Region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", record.Region)
	}
	// The sweep stops at the first hit; us-west-2 is never queried.
	if want := []string{"eu-central-1", "eu-west-1", "us-east-1"}; !equalStrings(aws.asked, want) {
		t.Errorf("queried %v, want %v", aws.asked, want)
	}
}

// A region where the function has never run has no log group. That is the
// normal case for most of the swept list, so it must not end the sweep.
func TestFindDelivery_missingLogGroupDoesNotStopTheSweep(t *testing.T) {
	aws := &fakeAWS{
		byRegion: map[string]string{"us-west-2": lambdaLine},
		errors: map[string]error{
			"eu-central-1": errNoSuchLogGroup,
			"eu-west-1":    errNoSuchLogGroup,
			"us-east-1":    errNoSuchLogGroup,
		},
	}
	record, err := FindDelivery(context.Background(), aws, "group",
		[]string{"eu-central-1", "eu-west-1", "us-east-1", "us-west-2"}, digestA, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if record == nil || record.Region != "us-west-2" {
		t.Fatalf("record = %v, want one found in us-west-2", record)
	}
}

// Every region missing the group means the group name is wrong, not that the
// delivery is missing. Saying so is the difference between an operator fixing a
// flag and an operator doubting the chain.
func TestFindDelivery_groupMissingEverywhereIsReportedAsSuch(t *testing.T) {
	aws := &fakeAWS{errors: map[string]error{"eu-west-1": errNoSuchLogGroup, "us-east-1": errNoSuchLogGroup}}

	_, err := FindDelivery(context.Background(), aws, "typo-group", []string{"eu-west-1", "us-east-1"}, digestA, time.Unix(0, 0))
	if err == nil {
		t.Fatal("a log group that exists nowhere was reported as a normal empty result")
	}
	if !strings.Contains(err.Error(), "typo-group") {
		t.Errorf("error should name the group, got %q", err)
	}
}

// Nothing found, but the group exists: an ordinary empty result. The caller
// renders it as a gap with a reason, so it must not be an error.
func TestFindDelivery_noMatchIsNotAnError(t *testing.T) {
	aws := &fakeAWS{byRegion: map[string]string{"us-east-1": lambdaLine}}

	record, err := FindDelivery(context.Background(), aws, "group", []string{"us-east-1"}, digestB, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record != nil {
		t.Errorf("found a record for a digest that was not logged: %+v", record)
	}
}

func TestFindDelivery_realAWSFailureStopsTheSweep(t *testing.T) {
	aws := &fakeAWS{errors: map[string]error{"eu-west-1": errors.New("ExpiredToken: credentials expired")}}

	_, err := FindDelivery(context.Background(), aws, "group", []string{"eu-west-1", "us-east-1"}, digestA, time.Unix(0, 0))
	if err == nil {
		t.Fatal("an authentication failure was swallowed as a missing log group")
	}
	if !strings.Contains(err.Error(), "ExpiredToken") {
		t.Errorf("error should carry the AWS message, got %q", err)
	}
	if len(aws.asked) != 1 {
		t.Errorf("swept %d regions after a real failure, want 1", len(aws.asked))
	}
}

// The aws CLI reads any argument starting with a dash as an option, so a value
// that reaches it unchecked can redirect the read to another account or
// endpoint. No shell is involved, so this is not shell injection — it is the
// CLI's own flag parser, and it is why these three values are validated.
func TestCheckAWSArgs_refusesValuesTheCLIWouldReadAsOptions(t *testing.T) {
	const goodGroup = "/aws/lambda/us-east-1.ramp-edge"

	refused := []struct {
		name                   string
		region, group, pattern string
	}{
		{"region smuggling a profile", "--profile=attacker", goodGroup, digestA},
		{"region redirecting the endpoint", "--endpoint-url=http://evil.example", goodGroup, digestA},
		{"log group as an option", "eu-west-1", "--profile=attacker", digestA},
		{"pattern as an option", "eu-west-1", goodGroup, "--query=*"},
		{"pattern that is not a digest", "eu-west-1", goodGroup, "'; rm -rf /"},
		{"empty region", "", goodGroup, digestA},
		{"empty log group", "eu-west-1", "", digestA},
		{"region with a space", "eu-west-1 extra", goodGroup, digestA},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkAWSArgs(tc.region, tc.group, tc.pattern); err == nil {
				t.Errorf("checkAWSArgs(%q, %q, %q) accepted a value the CLI would misread",
					tc.region, tc.group, tc.pattern)
			}
		})
	}

	// The guard must not refuse what the tool legitimately passes.
	for _, region := range []string{"eu-central-1", "us-east-1", "ap-southeast-2", "us-gov-west-1"} {
		if err := checkAWSArgs(region, goodGroup, digestA); err != nil {
			t.Errorf("checkAWSArgs refused a real region %q: %v", region, err)
		}
	}
}

func equalStrings(got, want []string) bool {
	return fmt.Sprint(got) == fmt.Sprint(want)
}
