// Domain enums for obligation rows. The repo layer is the single owner of the
// sqlc-generated PG enum types (RampValidationOutcome, RampObligationState);
// services consume these typed string aliases and translate at the repo
// boundary. Enforces transport→service→repository layering: a service-public
// function MUST NOT surface sqlc types.

package repo

import "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"

// ValidationOutcome is the domain view of the ramp_validation_outcome PG enum.
type ValidationOutcome string

// ValidationOutcome values. Literals match the PG enum strings 1:1 so the
// domain → sqlc translation is a plain conversion.
const (
	ValidationOutcomeValidated         ValidationOutcome = "VALIDATED"
	ValidationOutcomeRejectedFields    ValidationOutcome = "REJECTED_FIELDS"
	ValidationOutcomeRejectedTolerance ValidationOutcome = "REJECTED_TOLERANCE"
	ValidationOutcomeRejectedBillingID ValidationOutcome = "REJECTED_BILLING_ID"
	ValidationOutcomeRejectedTimestamp ValidationOutcome = "REJECTED_TIMESTAMP"
	// ValidationOutcomeRejectedWindow is no longer produced. A report is now
	// accepted whatever the time: rejecting a late report left the obligation
	// PENDING, and a PENDING obligation past its deadline is what the execute
	// gate refuses on, so an agent that missed one window could neither report
	// nor transact. Lateness is no longer marked explicitly — it stays derivable
	// from received_at against deadline on the same row, both written from the
	// service clock. The constant stays because the PG enum still carries the
	// value and historical rows still hold it.
	ValidationOutcomeRejectedWindow ValidationOutcome = "REJECTED_WINDOW"
	// ValidationOutcomeRejectedExchange is no longer produced. A report naming a
	// different Exchange is now refused by the recipient interceptor on the
	// Connect surface, before the handler runs and therefore before any
	// obligation is loaded — that ordering is required, because the obligation is
	// looked up by an identifier only this Exchange can interpret. The constant
	// stays because the PG enum still carries the value and historical rows still
	// hold it; a report rejected this way leaves no obligation-level row.
	ValidationOutcomeRejectedExchange ValidationOutcome = "REJECTED_EXCHANGE"
)

// ObligationState is the domain view of the ramp_obligation_state PG enum.
type ObligationState string

// ObligationState values. Literals match the PG enum strings 1:1.
const (
	ObligationStatePending  ObligationState = "PENDING"
	ObligationStateReceived ObligationState = "RECEIVED"
)

// sqlcValidationOutcome translates a domain enum value to the sqlc-generated
// PG enum. The repo passes the result straight to sqlc query params.
func sqlcValidationOutcome(o ValidationOutcome) sqlc.RampValidationOutcome {
	return sqlc.RampValidationOutcome(o)
}

// domainValidationOutcome translates a sqlc-generated enum value back to the
// domain enum. Used when reading sqlc row values into Obligation.
func domainValidationOutcome(o sqlc.RampValidationOutcome) ValidationOutcome {
	return ValidationOutcome(o)
}

// sqlcObligationState translates a domain state value to the sqlc enum.
func sqlcObligationState(s ObligationState) sqlc.RampObligationState {
	return sqlc.RampObligationState(s)
}

// domainObligationState translates a sqlc state value to the domain enum.
func domainObligationState(s sqlc.RampObligationState) ObligationState {
	return ObligationState(s)
}
