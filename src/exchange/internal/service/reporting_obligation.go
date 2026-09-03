package service

import (
	"slices"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// reportUsageEndpoint is where an agent files the report this Exchange expects.
const reportUsageEndpoint = "/ramp.v1.ExchangeService/ReportUsage"

// obligationPlan is what one executed item's reporting obligation will be:
// whether it is minted at all, the window the agent is asked to report within,
// and the required fields and tolerance the validator holds a report to.
//
// The window is advisory at report time: a report filed after it is still
// accepted, because rejecting a late report is what deadlocked an agent that
// missed one window. It is not decorative either — the same value writes the
// obligation's deadline, and an obligation still PENDING past that deadline
// counts as overdue in the execute gate.
//
// It exists so the row we persist and the ReportingObligation we hand the agent
// are the same decision made once. They used to be two: buildPersistIntent
// derived the window and the required fields for the database, while the result
// item independently reported required=true with no window and no fields, so the
// agent was told neither the window it was measured against nor the fields its
// report had to carry.
type obligationPlan struct {
	// Required is false only for a price whose metering is NONE. No obligation
	// row is written, and the agent is told none is owed.
	Required          bool
	WindowSeconds     int32
	RequiredFields    []string
	QuantityTolerance float64
}

// planObligation derives the obligation shape for one item from the tenant's
// reporting policy and the selected price. Called once per item, before the
// result item is built, because the result is serialized into
// transaction_log.result_payload on the same INSERT that writes the obligation —
// so both have to be decided before either is written.
func (s *ExchangeService) planObligation(tenant repo.Tenant, pricing PricingDoc) obligationPlan {
	policy := decodeReportingPolicy(tenant.ReportingPolicy)
	tolerance := defaultQuantityTolerance
	if policy.QuantityTolerance != nil {
		tolerance = *policy.QuantityTolerance
	}
	return obligationPlan{
		Required:          pricing.MetersUsage(),
		WindowSeconds:     windowSecondsForObligation(policy, s.cfg.ReportWindow),
		RequiredFields:    requiredFieldsFor(policy, pricing),
		QuantityTolerance: tolerance,
	}
}

// requiredFieldsFor resolves the tenant policy's required_fields for one price.
// Always returns a non-nil slice: the required_fields column is NOT NULL TEXT[]
// and sqlc passes the Go slice straight through, so a nil would violate the
// constraint.
func requiredFieldsFor(policy reportingPolicy, pricing PricingDoc) []string {
	fields := policy.RequiredFields
	if pricing.IsFree() {
		// A price-zero transaction stores no billing_id (ADR-009 D5), so a
		// conformant report carries an empty billing_id — which validateRequiredFields
		// would reject as "missing" (reportHasField keys billing_id on non-empty).
		// billing_id conformance on the free path is enforced separately by
		// validateBillingID (empty==empty passes; a forged non-empty is rejected,
		// threat model T25), so requiring it here is unsatisfiable, not redundant.
		// Drop it for this obligation; the paid / FreeAdapter path (non-zero
		// unit_cost, non-empty stored billing_id) keeps the requirement. The
		// "billing_id" token matches reportHasField.
		fields = slices.DeleteFunc(fields, func(f string) bool {
			return f == "billing_id"
		})
	}
	if fields == nil {
		return []string{}
	}
	return fields
}

// buildReportingObligation projects the plan onto the ReportingObligation the
// agent receives beside its signed URL, so the agent is told the window its
// deadline is derived from and the field list the validator holds its report to.
// Named for what it builds, like buildBatchResultItem which carries the result
// it lands in.
//
// A plan that mints nothing reports required=false and nothing else: there is no
// window to meet, no fields to carry, and no endpoint to file at.
func (p obligationPlan) buildReportingObligation() *rampv1.ReportingObligation {
	if !p.Required {
		return &rampv1.ReportingObligation{Required: false}
	}
	return &rampv1.ReportingObligation{
		Required:       true,
		Endpoint:       strPtr(reportUsageEndpoint),
		Window:         durationpb.New(time.Duration(p.WindowSeconds) * time.Second),
		RequiredFields: p.RequiredFields,
	}
}
