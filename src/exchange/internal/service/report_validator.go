package service

import (
	"crypto/subtle"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// defaultQuantityTolerance is the protocol-suggested fractional tolerance for
// the ±20% consumed-vs-estimated comparison. The same value is the column
// DEFAULT in migration 000008 and the fallback the service uses when the
// tenant's reporting policy does not pin a tighter / looser tolerance
// (one named const, not three magic literals).
const defaultQuantityTolerance = 0.20

// timestampSkewFuture caps how far in the future a UsageReport.timestamp may
// drift before we treat it as broken-clock / clock-shift abuse. Matches
// httpsig.ReplayTTL — the same window the inbound signature gate already
// enforces, so honest clock skew that passed signature verification will not
// be rejected by the report-timestamp check.
const timestampSkewFuture = 5 * time.Minute

// timestampSkewPast caps how far before the originating transaction the
// report's timestamp may sit. A few seconds of negative skew is tolerated;
// older claims mean the report's wall-clock either lies about consumption
// time or comes from an unrelated transaction reused by the caller.
const timestampSkewPast = 5 * time.Second

// toleranceScale is the integer multiplier for fixed-point tolerance
// arithmetic. Six decimal places of precision; no float comparison.
const toleranceScale = 1_000_000

// ReportInput carries every input ValidateUsageReport consumes. Pure data; no DB access.
// Exchange is the configured exchange domain (cfg.Exchange) so the
// validator can refuse reports addressed at a different exchange.
type ReportInput struct {
	Obligation    repo.Obligation
	TransactionID string
	BillingID     string
	CreatedAt     time.Time
	Report        *rampv1.UsageReport
	Now           time.Time
	Exchange      string
}

// ValidateUsageReport runs the seven RAMP §3.2 #4 + L6-remainder checks in
// protocol order. Returns (repo.ValidationOutcomeValidated, nil) on success and
// (outcome, *exchange.Error) on the first failing check.
//
// The validator is a pure function (no struct receiver, no state, no allocations
// on the happy path) so the service can call it without wiring a dep and tests
// drive it without constructing a fixture.
func ValidateUsageReport(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	if out, err := validateRequiredFields(in); err != nil {
		return out, err
	}
	if out, err := validateWindow(in); err != nil {
		return out, err
	}
	if out, err := validateTolerance(in); err != nil {
		return out, err
	}
	if out, err := validateBillingID(in); err != nil {
		return out, err
	}
	if out, err := validateTimestamp(in); err != nil {
		return out, err
	}
	if out, err := validateExchange(in); err != nil {
		return out, err
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateRequiredFields(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	for _, field := range in.Obligation.RequiredFields {
		if !reportHasField(in.Report, field) {
			return repo.ValidationOutcomeRejectedFields, exchange.Newf(
				exchange.KindInvalidRequest,
				"required field %q missing or empty", field,
			).WithField(field)
		}
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateWindow(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	if in.Obligation.Deadline.IsZero() {
		// No deadline persisted (legacy row) — skip rather than reject so we do
		// not break replay against archived obligations.
		return repo.ValidationOutcomeValidated, nil
	}
	if in.Now.After(in.Obligation.Deadline) {
		return repo.ValidationOutcomeRejectedWindow, exchange.Newf(
			exchange.KindFailedPrecondition,
			"reporting window expired",
		).WithField("window")
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateTolerance(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	consumed := int64(in.Report.GetUsage().GetConsumedQuantity())
	if consumed < 0 {
		return repo.ValidationOutcomeRejectedTolerance, exchange.Newf(
			exchange.KindInvalidRequest,
			"consumed_quantity %d is negative", consumed,
		).WithField("consumed_quantity")
	}
	estimated := in.Obligation.EstimatedQuantity
	if estimated == 0 {
		// Zero-estimate obligation. Per the implementation-plan Q2 decision,
		// this is the strict-reject branch: with no estimate to compare
		// against, any non-zero consumption is rejected. Reporting zero
		// consumption against a zero-estimate obligation passes.
		if consumed != 0 {
			return repo.ValidationOutcomeRejectedTolerance, exchange.Newf(
				exchange.KindInvalidRequest,
				"consumed quantity %d reported against zero-estimate obligation",
				consumed,
			).WithField("consumed_quantity")
		}
		return repo.ValidationOutcomeValidated, nil
	}
	diff := consumed - estimated
	if diff < 0 {
		diff = -diff
	}
	tol := in.Obligation.QuantityTolerance
	// A stamped 0 is an explicit exact-match policy, not "unset": buildPersistIntent
	// resolves a nil policy to defaultQuantityTolerance before persisting, so a 0
	// reaching the validator can only be a deliberate zero-tolerance. Only the
	// impossible negative falls back to the default.
	if tol < 0 {
		tol = defaultQuantityTolerance
	}
	// Integer arithmetic: diff*toleranceScale > tol*toleranceScale*estimated
	// avoids any float comparison.
	tolPPM := int64(tol * float64(toleranceScale))
	if diff*toleranceScale > tolPPM*estimated {
		return repo.ValidationOutcomeRejectedTolerance, exchange.Newf(
			exchange.KindInvalidRequest,
			"consumed quantity outside ±%.0f%% of estimate", tol*100,
		).WithField("consumed_quantity")
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateBillingID(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	// The report's billing_id must equal the transaction's (RAMP §3.2 #4). A
	// free-tier transaction reserved no funds and stored an empty billing_id
	// (ADR-009 D5), so a conformant report carries an empty billing_id too; a
	// non-empty value names a reservation handle absent from this Exchange's
	// transaction log and is rejected as a forged handle (threat model T25 — the
	// Exchange validates the reported billing_id exists before accepting).
	got := []byte(in.Report.GetBillingId())
	want := []byte(in.BillingID)
	// Constant-time compare (defence-in-depth). A length mismatch returns 0 from
	// subtle.ConstantTimeCompare without leaking the length via timing — a length
	// difference is itself a mismatch. Two empty values compare equal, so a
	// free-tier report that carries no billing_id validates.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return repo.ValidationOutcomeRejectedBillingID, exchange.Newf(
			exchange.KindInvalidRequest,
			"billing_id mismatch",
		).WithField("billing_id")
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateTimestamp(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	ts := in.Report.GetTimestamp()
	if ts == nil {
		// Timestamp is optional in the proto — caller didn't claim one, so we
		// have nothing to check.
		return repo.ValidationOutcomeValidated, nil
	}
	reported := ts.AsTime()
	if !in.CreatedAt.IsZero() && reported.Before(in.CreatedAt.Add(-timestampSkewPast)) {
		return repo.ValidationOutcomeRejectedTimestamp, exchange.Newf(
			exchange.KindInvalidRequest,
			"report timestamp %s precedes transaction created_at %s",
			reported.UTC().Format(time.RFC3339Nano),
			in.CreatedAt.UTC().Format(time.RFC3339Nano),
		).WithField("timestamp")
	}
	if reported.After(in.Now.Add(timestampSkewFuture)) {
		return repo.ValidationOutcomeRejectedTimestamp, exchange.Newf(
			exchange.KindInvalidRequest,
			"report timestamp %s is more than %s in the future",
			reported.UTC().Format(time.RFC3339Nano), timestampSkewFuture,
		).WithField("timestamp")
	}
	return repo.ValidationOutcomeValidated, nil
}

func validateExchange(in ReportInput) (repo.ValidationOutcome, *exchange.Error) {
	got := in.Report.GetExchange()
	if got == "" {
		// Exchange is optional — caller didn't claim one.
		return repo.ValidationOutcomeValidated, nil
	}
	if in.Exchange != "" && got != in.Exchange {
		return repo.ValidationOutcomeRejectedExchange, exchange.Newf(
			exchange.KindInvalidRequest,
			"report exchange %q does not match exchange %q",
			got, in.Exchange,
		).WithField("exchange")
	}
	return repo.ValidationOutcomeValidated, nil
}

// knownReportFields is the canonical set of usage-report field names the
// Exchange understands. It is the single source of truth shared by reportHasField
// (which rejects an unknown name fail-closed) and the admin SetReportingPolicy
// write-side check ValidateRequiredFieldNames (which rejects a policy naming an
// unknown field up front). Keep it in lockstep with reportHasField's switch —
// TestReportHasFieldCoversKnownFields fails if they drift.
var knownReportFields = map[string]struct{}{
	"billing_id":        {},
	"transaction_id":    {},
	"consumed_quantity": {},
	"function":          {},
	"exchange":          {},
	"timestamp":         {},
	"id":                {},
}

// ValidateRequiredFieldNames rejects a reporting policy that names a field the
// validator cannot enforce. Every required_fields token must be a member of the
// canonical known set; an unknown token would make reportHasField return false
// for every report, permanently failing validation for that tenant — an
// availability lever on a plane with no per-operator identity. Names are matched
// literally: the '*' the wire pattern permits is a character, not a glob.
func ValidateRequiredFieldNames(names []string) *exchange.Error {
	for _, name := range names {
		if _, ok := knownReportFields[name]; !ok {
			return exchange.Newf(
				exchange.KindInvalidRequest,
				"unknown required_fields token %q", name,
			)
		}
	}
	return nil
}

// reportHasField returns true when the named protocol field is present and
// non-empty in the report. A name outside knownReportFields returns FALSE
// (fail-closed) so a typo in tenants.reporting_policy.required_fields surfaces
// as a rejected report rather than a silently disabled check.
func reportHasField(report *rampv1.UsageReport, field string) bool {
	if _, ok := knownReportFields[field]; !ok {
		return false
	}
	switch field {
	case "billing_id":
		return report.GetBillingId() != ""
	case "transaction_id":
		return report.GetTransactionId() != ""
	case "consumed_quantity":
		return report.GetUsage() != nil
	case "function":
		return len(report.GetUsage().GetFunction()) > 0
	case "exchange":
		return report.GetExchange() != ""
	case "timestamp":
		return report.GetTimestamp() != nil
	case "id":
		return report.GetIdempotencyKey() != ""
	default:
		return false
	}
}
