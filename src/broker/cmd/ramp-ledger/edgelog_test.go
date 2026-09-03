package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The Lambda@Edge envelope — timestamp, invocation id, level, tab-separated —
// in front of what the worker wrote.
//
// HAND-WRITTEN, not captured. It reproduces the envelope shape from the
// documented format, so it can only confirm this parser reads what its author
// expected. capturedLine below is one real line, and confirms that what the
// deployed pipeline emits is something this parser accepts. The payload's field
// names are not on trust here — the shared vector below carries those, and both
// languages read it.
const lambdaLine = "2026-08-16T12:00:03.918Z\t8e1c47a1-3f2b-4f0a-9c1d-77b0e2a41d55\tINFO\t" +
	`edge.deliver.authorized {"url_hash":"` + digestA + `","outcome":"cdn-origin-fetch",` +
	`"kid":"nJ2v","agent_id":"agents.example","method":"GET","path":"/a/4711","request_id":"edge-req-01"}`

// The forwarding branches wait for the origin and record what it answered. The
// worker serializes every field as a string, so the status arrives quoted; a Go
// field typed as a number here would fail to decode the WHOLE record and cost
// the delivery leg entirely, not just this one value.
const forwardedLine = "2026-08-16T12:00:03.918Z\t8e1c47a1-3f2b-4f0a-9c1d-77b0e2a41d55\tINFO\t" +
	`edge.deliver.authorized {"url_hash":"` + digestA + `","outcome":"origin-forwarded",` +
	`"kid":"nJ2v","agent_id":"agents.example","method":"GET","path":"/a/4711",` +
	`"request_id":"edge-req-01","origin_status":"200"}`

const (
	digestA = "3b1f5a9c2e7d40b8916c5f0a2d3e4b7c8a9f0e1d2c3b4a5968778695a4b3c2d1"
	digestB = "aaaa5a9c2e7d40b8916c5f0a2d3e4b7c8a9f0e1d2c3b4a5968778695a4b3c2d1"
)

// CAPTURED, not written. This is one real CloudWatch line, byte for byte.
//
// Provenance: read from log group /aws/lambda/us-east-1.ramp-demo-edge in
// region eu-central-1 on 2026-08-17, produced by a licensed delivery through
// the deployed Lambda@Edge worker. Found by filtering that log group for the
// SHA-256 of the signed URL the delivery used. Nothing was edited: the
// timestamp, the invocation id, the level, the three tabs, the event name and
// every payload value are as CloudWatch returned them.
//
// Nothing here is secret. The signed URL is not in the record — only its
// digest — and kid and agent_id are public key thumbprints that the Exchange
// already puts in the query string of every signed URL it hands a client.
//
// What this line does NOT test, checked rather than assumed: the envelope.
// parseDeliveryLine finds the event name by substring and discards everything
// before it, so the timestamp, the invocation id, the level word and the tabs
// are all ignored. Replacing them with "17/08/2026 12:24:08  f10d0473  WARN"
// leaves the test passing. That tolerance is deliberate and must stay — the
// Cloudflare and Fastly workers write the same event with no Lambda envelope in
// front of it, so a parser that demanded one would read only a third of the
// deployments.
//
// What it does test is the half no hand-written fixture can reach: that a real
// delivery through the deployed worker produces a line this parser accepts,
// with the event name intact and the payload following it on the same line,
// unescaped and unwrapped, under the field names the parser reads. A logging
// pipeline that JSON-wrapped the message, escaped its quotes, or split it
// across lines would break the parser in production while every hand-written
// fixture kept passing.
const capturedLine = "2026-08-17T12:24:08.565Z\tf10d0473-a0e9-432e-8250-4ac2ad4d4489\tINFO\t" +
	`edge.deliver.authorized {"url_hash":"42f5933a4c3bea811a081a4ce2d7087aa886c875eec2deb6438a89b22d0969e3",` +
	`"outcome":"cdn-origin-fetch","kid":"4QSzECKtgJeix7wyRx8ADEI4o4x3darNVEef6BKkP4I",` +
	`"agent_id":"tEUmDRuyf9D8gygRlkUrrOw1ZEgx5sQO8a_17HufKvc","method":"GET",` +
	`"path":"/articles/philosophers/thales-of-miletus.txt",` +
	`"request_id":"cddd487a-1761-48bb-b4d4-f3bf2295c6f4"}`

func TestParseDeliveryLine_readsThroughTheLambdaEnvelope(t *testing.T) {
	record, err := parseDeliveryLine(lambdaLine)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if record == nil {
		t.Fatal("no record parsed from a well-formed delivery line")
	}
	for _, c := range []struct{ field, got, want string }{
		{"url_hash", record.URLHash, digestA},
		{"outcome", record.Outcome, "cdn-origin-fetch"},
		{"kid", record.Kid, "nJ2v"},
		{"agent_id", record.AgentID, "agents.example"},
		{"method", record.Method, "GET"},
		{"path", record.Path, "/a/4711"},
		{"request_id", record.RequestID, "edge-req-01"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

// The same parse, against a line CloudWatch really collected. What that line
// does and does not establish is written where the line is defined.
//
// The last assertion is the one worth reading. It confirms in production what
// the hand-written fixtures only assert: on the CloudFront viewer-request path
// the worker never sees the origin response, so it emits no origin_status at
// all. That absence is why the renderer's row 6 falls back to the weaker
// "origin fetch released" claim instead of reporting that content was served.
func TestParseDeliveryLine_readsALineCapturedFromARealDelivery(t *testing.T) {
	record, err := parseDeliveryLine(capturedLine)
	if err != nil {
		t.Fatalf("parse a real CloudWatch line: %v", err)
	}
	if record == nil {
		t.Fatal("no record parsed from a line a real delivery produced")
	}
	for _, c := range []struct{ field, got, want string }{
		{"url_hash", record.URLHash, "42f5933a4c3bea811a081a4ce2d7087aa886c875eec2deb6438a89b22d0969e3"},
		{"outcome", record.Outcome, "cdn-origin-fetch"},
		{"kid", record.Kid, "4QSzECKtgJeix7wyRx8ADEI4o4x3darNVEef6BKkP4I"},
		{"agent_id", record.AgentID, "tEUmDRuyf9D8gygRlkUrrOw1ZEgx5sQO8a_17HufKvc"},
		{"method", record.Method, "GET"},
		{"path", record.Path, "/articles/philosophers/thales-of-miletus.txt"},
		{"request_id", record.RequestID, "cddd487a-1761-48bb-b4d4-f3bf2295c6f4"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
	if record.OriginStatus != "" {
		t.Errorf("origin_status = %q, want it absent: the worker runs at the viewer-request "+
			"event on this path and hands the request back before any origin answers",
			record.OriginStatus)
	}
}

func TestParseDeliveryLine_ignoresLinesThatAreNotDeliveries(t *testing.T) {
	// The CloudWatch filter matches the digest as a plain substring, so a
	// denial record that happens to mention it arrives here too. Returning a
	// record for one would report a delivery that never happened.
	for _, line := range []string{
		"2026-08-16T12:00:03.918Z\tid\tWARN\tedge.deny.signature {\"reason\":\"bad\"}",
		"START RequestId: 8e1c47a1 Version: 3",
		"",
	} {
		record, err := parseDeliveryLine(line)
		if err != nil {
			t.Errorf("line %q: unexpected error %v", line, err)
		}
		if record != nil {
			t.Errorf("line %q parsed as a delivery record", line)
		}
	}
}

// A delivery line whose payload is not JSON is an error, never a silent skip.
// It means the worker and this tool disagree about the record's form, and
// treating it as "no delivery found" would render the gap as CloudWatch lag.
func TestParseDeliveryLine_unparseablePayloadIsAnError(t *testing.T) {
	for _, name := range []string{"object-inspection form", "no payload"} {
		t.Run(name, func(t *testing.T) {
			line := "2026-08-16T12:00:03.918Z\tid\tINFO\tedge.deliver.authorized"
			if name == "object-inspection form" {
				// What a console.info(event, object) call produces in Node:
				// unquoted keys and single quotes, which no JSON parser takes.
				line += " { url_hash: '" + digestA + "', outcome: 'cdn-origin-fetch' }"
			}
			if _, err := parseDeliveryLine(line); err == nil {
				t.Error("an unparseable payload was accepted")
			}
		})
	}
}

// fakeAWS answers per region from a script, so the sweep's region loop is
// testable without AWS.
// The origin status has to survive the parse, and its ABSENCE has to survive it
// too. The CloudFront branch writes no status because the worker never saw a
// response; reading that as an empty string rather than failing is what lets the
// renderer say "no origin status" instead of inventing one.
func TestParseDeliveryLine_readsTheOriginStatusAndItsAbsence(t *testing.T) {
	forwarded, err := parseDeliveryLine(forwardedLine)
	if err != nil {
		t.Fatalf("parse forwarded line: %v", err)
	}
	if forwarded.OriginStatus != "200" {
		t.Errorf("origin_status = %q, want \"200\"", forwarded.OriginStatus)
	}
	// Everything else on the record must still arrive; a new field must not
	// shift the decode of the ones already there.
	if forwarded.URLHash != digestA {
		t.Errorf("url_hash = %q, want %q", forwarded.URLHash, digestA)
	}
	if forwarded.Outcome != "origin-forwarded" {
		t.Errorf("outcome = %q, want \"origin-forwarded\"", forwarded.Outcome)
	}

	cdn, err := parseDeliveryLine(lambdaLine)
	if err != nil {
		t.Fatalf("parse cdn line: %v", err)
	}
	if cdn.OriginStatus != "" {
		t.Errorf("a record with no origin_status decoded to %q, want empty", cdn.OriginStatus)
	}
}

// A record whose keys this parser does not name must be REFUSED, not returned
// empty. encoding/json ignores keys it cannot place, so a renamed field decodes
// cleanly into a zero-valued record — and the line is still found, because the
// CloudWatch filter matches the digest as a substring of the raw line and the
// digest is still there under its new name.
//
// Returning that record would render rows 5 and 6 with blanks and fail the
// delivered-URL assertion, which reads as tampering. The error says what really
// happened: the two sides disagree about the payload's field names.
func TestParseDeliveryLine_refusesARecordWithoutItsLoadBearingFields(t *testing.T) {
	const envelope = "2026-08-16T12:00:03.918Z\tid\tINFO\tedge.deliver.authorized "
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{
			// The exact shape of a worker-side rename: the digest is present,
			// so the line is found, but not under a key this parser reads.
			name:    "url_hash renamed by the worker",
			payload: `{"urlHash":"` + digestA + `","outcome":"origin-forwarded"}`,
		},
		{
			name:    "outcome renamed by the worker",
			payload: `{"url_hash":"` + digestA + `","originMode":"origin-forwarded"}`,
		},
		{
			name:    "a payload that shares no field names at all",
			payload: `{"something":"else"}`,
		},
		{
			name:    "an empty object",
			payload: `{}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, err := parseDeliveryLine(envelope + tc.payload)
			if err == nil {
				t.Fatalf("a record missing its load-bearing fields was accepted: %+v", record)
			}
			if record != nil {
				t.Errorf("an error was returned alongside a record: %+v", record)
			}
		})
	}
}

// The complement, and it is what keeps the rule from being too strict: a record
// carrying the five required fields is accepted with every OPTIONAL one absent.
//
// kid, agent_id and origin_status are each omitted for a real reason — a signed
// URL that named no key id, no bound agent, or a runtime that never waited for
// an origin. Requiring any of them would refuse records that are entirely
// correct, and would break the CloudFront path outright, since that one never
// carries a status.
func TestParseDeliveryLine_acceptsARecordWithNoOptionalFields(t *testing.T) {
	const line = "2026-08-16T12:00:03.918Z\tid\tINFO\tedge.deliver.authorized " +
		`{"url_hash":"` + digestA + `","outcome":"cdn-origin-fetch",` +
		`"method":"GET","path":"/a/4711","request_id":"edge-req-01"}`
	record, err := parseDeliveryLine(line)
	if err != nil {
		t.Fatalf("a record with every required field was refused: %v", err)
	}
	if record.URLHash != digestA || record.Outcome != "cdn-origin-fetch" {
		t.Errorf("record decoded wrongly: %+v", record)
	}
	if record.Kid != "" || record.AgentID != "" || record.OriginStatus != "" {
		t.Errorf("optional fields were invented from an absent value: %+v", record)
	}
}

// Each required field, dropped one at a time. A rule written as a single
// condition over two fields silently stopped covering the other three when they
// were added; this table names them, so a sixth required field has to be added
// here to pass.
func TestParseDeliveryLine_refusesARecordMissingAnyRequiredField(t *testing.T) {
	full := map[string]string{
		"url_hash":   digestA,
		"outcome":    "origin-forwarded",
		"method":     "GET",
		"path":       "/a/4711",
		"request_id": "edge-req-01",
	}
	for _, drop := range []string{"url_hash", "outcome", "method", "path", "request_id"} {
		t.Run("without "+drop, func(t *testing.T) {
			payload := map[string]string{}
			for k, v := range full {
				if k != drop {
					payload[k] = v
				}
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("encode payload: %v", err)
			}
			line := "2026-08-16T12:00:03.918Z\tid\tINFO\t" + deliveryEvent + " " + string(encoded)
			record, err := parseDeliveryLine(line)
			if err == nil {
				t.Fatalf("a record without %s was accepted: %+v", drop, record)
			}
			if !strings.Contains(err.Error(), drop) {
				t.Errorf("the error does not name the missing field %q: %v", drop, err)
			}
		})
	}
}

// sharedDeliveryVectors is the one payload both languages check against. The
// TypeScript suite asserts an emitted record carries every key it lists; this
// side parses the payload and asserts every value. See the file's own comment
// for why neither language's tests can close this gap alone.
const sharedDeliveryVectors = "../../../../testdata/delivery-record-vectors.json"

// The cross-language contract. A rename in the worker that is mirrored in the
// worker's own test leaves both suites green today; this fails, because the
// expected names come from a file neither suite controls.
func TestParseDeliveryLine_matchesTheSharedVector(t *testing.T) {
	raw, err := os.ReadFile(sharedDeliveryVectors)
	if err != nil {
		t.Fatalf("read the shared delivery vector: %v", err)
	}
	var vectors struct {
		RequiredKeys []string          `json:"required_keys"`
		Payload      map[string]string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode the shared delivery vector: %v", err)
	}

	// The vector's payload, put through the same envelope a collected line has.
	payload, err := json.Marshal(vectors.Payload)
	if err != nil {
		t.Fatalf("re-encode the vector payload: %v", err)
	}
	line := "2026-08-16T12:00:03.918Z\tid\tINFO\t" + deliveryEvent + " " + string(payload)

	record, err := parseDeliveryLine(line)
	if err != nil {
		t.Fatalf("the shared vector did not parse: %v", err)
	}

	// What this parser reads, by the name it reads it under.
	canonical := map[string]string{
		"url_hash":      record.URLHash,
		"outcome":       record.Outcome,
		"kid":           record.Kid,
		"agent_id":      record.AgentID,
		"method":        record.Method,
		"path":          record.Path,
		"request_id":    record.RequestID,
		"origin_status": record.OriginStatus,
	}

	// The KEY SETS must match in both directions, and that is the load-bearing
	// half of this test. Comparing values alone proves nothing about a renamed
	// field: the vector's lookup misses, this struct's field is unset, and two
	// empty strings compare equal. Both loops below are what turn that silent
	// pass into a failure.
	for key := range vectors.Payload {
		if _, ok := canonical[key]; !ok {
			t.Errorf("the vector carries %q, which this parser does not read — "+
				"a field was added or renamed on the worker side only", key)
		}
	}
	for key := range canonical {
		if _, ok := vectors.Payload[key]; !ok {
			t.Errorf("this parser reads %q, which the vector does not carry — "+
				"the worker no longer emits it, or it was renamed there", key)
		}
	}

	// Then the values, for the keys both sides agree exist.
	for field, got := range canonical {
		if want, ok := vectors.Payload[field]; ok && got != want {
			t.Errorf("%s = %q, want %q — this parser and the worker disagree about the payload",
				field, got, want)
		}
	}

	// Every key the vector calls required must actually be in its payload, or
	// the vector documents a contract its own example does not meet.
	for _, key := range vectors.RequiredKeys {
		if _, ok := vectors.Payload[key]; !ok {
			t.Errorf("the vector requires %q but its payload does not carry it", key)
		}
	}
}
