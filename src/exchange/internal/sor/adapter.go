// Package sor is the Exchange's System of Record for agent accounts: the
// single source of truth for whether a registered agent's account is active.
// It mirrors the billing adapter pattern one-for-one — a narrow port with a
// reference in-memory implementation today and a Postgres backend to come —
// so the backend can change (a plain database now, a CRM such as HubSpot
// later) without touching the rest of the Exchange.
//
// Identity. An account is keyed on the agent's durable Web Bot Auth directory
// identity: its subdomain. Deriving the subdomain from the verified RFC 9421
// signature is the caller's job (per ADR-017 D6); the SoR just receives it.
// The subdomain is the idempotency anchor and an operator-facing finder — it
// is never the per-request account lookup key (that link lives on ramp.agents
// in the Exchange's own database, per ADR-021 D3).
//
// Account id. billing_ref is a random UUID minted by the Exchange and passed
// in to OnRegister (ADR-021 D1/D2). The SoR never mints ids; it persists the
// candidate on a new account and returns it, or — when an account for that
// subdomain already exists — returns the already-stored id unchanged
// (ADR-021 D4, "the stored id wins"). This makes a candidate collision with an
// existing subdomain harmless.
//
// Status. The SoR owns the active flag; the Exchange is a read-through cache
// (a short-TTL decorator, added by a later slice). The only status path is the
// pull: IsActive(billing_ref) at transaction time.
package sor

import (
	"context"
	"errors"
)

// LicensingProfile holds the typed licensing-deal fields the SoR maps out of a
// registration's raw key→value data. Every field is optional: completeness is
// an operational concern (an operator does not activate an incomplete account),
// not a storage constraint. Unmapped keys go to Account.Extra instead.
type LicensingProfile struct {
	LegalEntity             string
	JurisdictionCountry     string
	JurisdictionSubdivision string
	AddressLine1            string
	AddressLine2            string
	AddressCity             string
	AddressRegion           string
	AddressPostalCode       string
	AddressCountry          string
}

// Account is a persisted agent account as returned by the adapter surface.
// Extra carries the registration keys that are not (yet) promoted to a typed
// LicensingProfile field — the seam that lets storage be built ahead of the
// concrete registration_data field set being fixed.
type Account struct {
	BillingRef string
	Subdomain  string
	Active     bool
	Email      string
	Profile    LicensingProfile
	Extra      map[string]string
}

// OnRegisterRequest is what the Exchange passes to register (or idempotently
// re-register) an account. BillingRef is the Exchange-minted UUID candidate
// (ADR-021 D2); Subdomain is the durable identity / idempotency key; Active is
// the starting status the Exchange computed from tenant config (the SoR neither
// reads tenant config nor hardcodes a default — this parameter is the seam);
// RegistrationData is the raw key→value payload the SoR maps.
type OnRegisterRequest struct {
	BillingRef       string
	Subdomain        string
	Active           bool
	RegistrationData map[string]string
}

// Adapter is the narrow port the Exchange depends on. Backends are swappable
// behind it (in-memory reference, Postgres, a future CRM).
type Adapter interface {
	// OnRegister creates the account for req.Subdomain if none exists, mapping
	// req.RegistrationData into typed profile columns and the rest into Extra,
	// and returns the account with the passed-in candidate BillingRef. It is
	// idempotent on Subdomain: a repeat — even one carrying a different
	// candidate BillingRef or different data — returns the ORIGINALLY stored
	// account unchanged, with no side effects (ADR-021 D4). An empty Subdomain
	// returns ErrSubdomainRequired; an empty BillingRef returns
	// ErrBillingRefRequired.
	OnRegister(ctx context.Context, req OnRegisterRequest) (Account, error)
	// IsActive reports the SoR-owned active flag for an account by its
	// billing_ref. A known-but-inactive account returns (false, nil); only an
	// unknown billing_ref returns ErrAccountNotFound — a "not found" is never
	// reported as false. An empty billingRef returns ErrBillingRefRequired.
	IsActive(ctx context.Context, billingRef string) (bool, error)
}

// Sentinel errors returned by adapter implementations. Callers MUST use
// errors.Is to check; implementations MUST return (or wrap) these exact values.
var (
	// ErrAccountNotFound is returned by IsActive when no account exists for the
	// given billing_ref. It is distinct from a known-inactive account, which
	// returns (false, nil).
	ErrAccountNotFound = errors.New("sor: account not found")

	// ErrSubdomainRequired is returned by OnRegister when the request carries an
	// empty subdomain. The subdomain is the durable identity and the NOT NULL
	// backstop against a payload-derived identity ever reaching storage.
	ErrSubdomainRequired = errors.New("sor: subdomain required")

	// ErrBillingRefRequired is returned when a billing_ref argument is empty —
	// by OnRegister (the Exchange must mint and pass a candidate) and by
	// IsActive (an empty ref cannot identify an account).
	ErrBillingRefRequired = errors.New("sor: billing_ref required")
)

// validateOnRegister checks the required OnRegister arguments. It is the one
// place these checks live: every backend calls it, so a bad request gets the
// same error no matter which backend handles it.
func validateOnRegister(req OnRegisterRequest) error {
	if req.Subdomain == "" {
		return ErrSubdomainRequired
	}
	return validateBillingRef(req.BillingRef)
}

// validateBillingRef checks that a billing_ref argument is not empty. Used by
// both OnRegister and IsActive.
func validateBillingRef(billingRef string) error {
	if billingRef == "" {
		return ErrBillingRefRequired
	}
	return nil
}
