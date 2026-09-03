package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// deliveryEvent names the record the edge worker emits for a verified
// delivery. It must stay byte-equal to the worker's own DELIVERY_EVENT constant
// in src/edge/src/log.ts — this tool finds a delivery by that name, so the two
// sides disagreeing means every chain renders its delivery leg as missing.
const deliveryEvent = "edge.deliver.authorized"

// DeliveryRecord is the edge worker's structured record of one authorized
// delivery, as recovered from the log stream.
type DeliveryRecord struct {
	URLHash   string `json:"url_hash"`
	Outcome   string `json:"outcome"`
	Kid       string `json:"kid"`
	AgentID   string `json:"agent_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	RequestID string `json:"request_id"`
	// OriginStatus is the origin's HTTP status, present only when the worker
	// waited for the response. It is a STRING because the worker serializes
	// every field of the record as one, so a number here would fail to decode
	// the whole record and cost the delivery leg entirely. Empty means the
	// worker never observed a response — which is the CloudFront case, not an
	// error — and the renderer must read empty as "unknown", never as zero.
	OriginStatus string `json:"origin_status"`
	// Region is where the record was found, filled in by the sweep rather than
	// read from the record. Lambda@Edge logs land in whichever point of
	// presence served the request, so which region held it is a fact about the
	// delivery worth rendering.
	Region string `json:"-"`
}

// FindDelivery sweeps a list of regions for the delivery record carrying
// urlHash and returns the first match.
//
// The sweep exists because Lambda@Edge writes its logs into the region of the
// point of presence that served the request, not into the function's home
// region, and nothing tells us in advance which that was. A region with no log
// group for this function simply has not served a request here yet — that is
// the normal case for most of the list, so it is skipped rather than reported.
//
// The filter pattern is the digest itself. CloudWatch matches it as a plain
// substring of the message, which finds the record without this tool having to
// state anything about how the message is laid out.
func FindDelivery(
	ctx context.Context, aws AWSRunner, logGroup string, regions []string, urlHash string, since time.Time,
) (*DeliveryRecord, error) {
	var skipped []string
	for _, region := range regions {
		out, err := aws.FilterLogEvents(ctx, region, logGroup, urlHash, since)
		switch {
		case errors.Is(err, errNoSuchLogGroup):
			skipped = append(skipped, region)
			continue
		case err != nil:
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		record, err := firstDeliveryRecord(out)
		if err != nil {
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		if record != nil {
			record.Region = region
			return record, nil
		}
	}
	if len(skipped) == len(regions) {
		return nil, fmt.Errorf("log group %q exists in none of the %d swept regions", logGroup, len(regions))
	}
	return nil, nil
}

// filterLogEventsOutput is the slice of the CloudWatch response this tool
// reads. Everything else the API returns is ignored on purpose: a field this
// tool does not use is a field that cannot break it.
type filterLogEventsOutput struct {
	Events []struct {
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	} `json:"events"`
}

func firstDeliveryRecord(raw []byte) (*DeliveryRecord, error) {
	var out filterLogEventsOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode filter-log-events response: %w", err)
	}
	for _, event := range out.Events {
		record, err := parseDeliveryLine(event.Message)
		if err != nil {
			return nil, err
		}
		if record != nil {
			return record, nil
		}
	}
	return nil, nil
}

// missingRequired names the first field the worker always writes that this
// record does not carry, or "" when every one of them is present. The names are
// the wire names, so the message says what a reader would grep the logs for.
func missingRequired(r *DeliveryRecord) string {
	for _, f := range []struct {
		name  string
		value string
	}{
		{"url_hash", r.URLHash},
		{"outcome", r.Outcome},
		{"method", r.Method},
		{"path", r.Path},
		{"request_id", r.RequestID},
	} {
		if f.value == "" {
			return f.name
		}
	}
	return ""
}

// parseDeliveryLine recovers the record from one collected log line, or answers
// nil for a line that is not a delivery record.
//
// The Lambda runtime prefixes every console write with its own envelope —
// timestamp, invocation id and level, tab-separated — so the line looks like:
//
//	2026-08-16T14:21:55.123Z\t8e1c…\tINFO\tedge.deliver.authorized {"url_hash":…}
//
// The envelope is stripped by finding the event name, which also rejects any
// other record the filter's substring match happened to catch. What follows the
// event name is the JSON payload the worker serialized; the worker serializes
// it precisely so this step is a JSON parse rather than a guess at whichever
// runtime's object-inspection format wrote the line.
func parseDeliveryLine(message string) (*DeliveryRecord, error) {
	start := strings.Index(message, deliveryEvent)
	if start < 0 {
		return nil, nil
	}
	payload := strings.TrimSpace(message[start+len(deliveryEvent):])
	if !strings.HasPrefix(payload, "{") {
		return nil, fmt.Errorf("delivery record has no JSON payload: %q", truncate(message, 200))
	}
	var record DeliveryRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return nil, fmt.Errorf("decode delivery record: %w (line %q)", err, truncate(message, 200))
	}
	// A payload whose keys this struct does not name decodes CLEANLY — encoding/json
	// ignores what it cannot place — and yields a record whose every field is empty.
	// That is the shape a cross-language rename takes: the worker renames a key, its
	// own test is updated alongside, and nothing here objects. The line is still
	// found, because the CloudWatch filter matches the digest as a substring of the
	// raw line and the digest is still in it under the new key.
	//
	// Left unchecked, rows 5 and 6 then render with blanks and the delivered-URL
	// assertion reports FAILED — which an operator reads as tampering rather than as
	// two components disagreeing about a field name. Refusing the record here turns
	// that into "not read: ...", which is what actually happened.
	//
	// All five are required because the worker always writes all five: method,
	// path and request_id come from the base every record carries, and the
	// request id is minted when the caller sends none. Missing any of them means
	// the payload is not the record this parser was written for. Accepting a
	// partial one renders row 5 with a blank method, a blank path, or a blank
	// correlator — each a fact stated as empty rather than as unknown.
	if missing := missingRequired(&record); missing != "" {
		return nil, fmt.Errorf(
			"delivery record carries no %s, so the worker and this parser disagree "+
				"about the payload's field names (line %q)",
			missing, truncate(message, 200))
	}
	return &record, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// errNoSuchLogGroup marks the one AWS failure the sweep treats as ordinary: the
// function has no log group in that region because it has not run there.
var errNoSuchLogGroup = errors.New("log group does not exist in this region")

// awsRegion and awsLogGroup are the shapes AWS itself accepts for these two
// names. Anything outside them cannot address a real resource.
var (
	awsRegion   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	awsLogGroup = regexp.MustCompile(`^[A-Za-z0-9_./#-]{1,512}$`)
)

// checkAWSArgs refuses any value that could reach the aws CLI as something
// other than the argument it is meant to be.
//
// No shell is involved — the arguments are passed as an argv array — so there
// is no command string to inject into. What IS reachable is the CLI's own flag
// parser: a value beginning with a dash is read as an option, so an unchecked
// region could smuggle in "--profile" or "--endpoint-url" and quietly redirect
// the read to another account. These three values arrive from operator flags
// and from the evidence row, which is remote data, so they are validated here
// rather than trusted.
func checkAWSArgs(region, logGroup, pattern string) error {
	if !awsRegion.MatchString(region) {
		return fmt.Errorf("%q is not an AWS region name", region)
	}
	if !awsLogGroup.MatchString(logGroup) {
		return fmt.Errorf("%q is not a usable CloudWatch log group name", logGroup)
	}
	// The pattern is a digest computed here from the evidence row, so hex is
	// the only shape it can legitimately take.
	if !isHex(pattern) {
		return fmt.Errorf("filter pattern %q is not a hex digest", pattern)
	}
	return nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// AWSRunner is the narrow slice of AWS this tool needs. It is an interface so
// the sweep's region loop and the record parsing are testable without AWS.
type AWSRunner interface {
	FilterLogEvents(ctx context.Context, region, logGroup, pattern string, since time.Time) ([]byte, error)
}

// CLIRunner reads CloudWatch through the aws command-line tool.
//
// The CLI rather than the AWS SDK, deliberately. This binary is an operator
// tool run by hand against a live deployment, and the aws CLI is already a
// prerequisite of this repo's deploy tooling, so it is configured on the
// machine that runs the ledger. Linking the SDK instead would add its
// credential, IMDS and SSO chain to the module that the Exchange and Broker
// servers also build from, to save shelling out to a tool the operator already
// has authenticated. Credentials come from the CLI's own resolution chain —
// this tool passes none and hardcodes no profile.
type CLIRunner struct{}

func (CLIRunner) FilterLogEvents(
	ctx context.Context, region, logGroup, pattern string, since time.Time,
) ([]byte, error) {
	if err := checkAWSArgs(region, logGroup, pattern); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "aws", "logs", "filter-log-events",
		"--region", region,
		"--log-group-name", logGroup,
		"--filter-pattern", pattern,
		"--start-time", fmt.Sprint(since.UnixMilli()),
		"--output", "json")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		if strings.Contains(stderr.String(), "ResourceNotFoundException") {
			return nil, errNoSuchLogGroup
		}
		return nil, fmt.Errorf("aws logs filter-log-events: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout, nil
}
