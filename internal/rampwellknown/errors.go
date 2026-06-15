package rampwellknown

import "errors"

// Sentinel errors. Callers branch with errors.Is; transport layers map these
// to the appropriate Connect/HTTP codes.
var (
	// ErrInvalidHost is returned when a host cannot be turned into a manifest URL.
	ErrInvalidHost = errors.New("rampwellknown: invalid host")

	// ErrNoManifest is returned when the origin serves no manifest (HTTP 404).
	// Consumers branch to their absence path (e.g. bare-URL fallback).
	ErrNoManifest = errors.New("rampwellknown: origin serves no ramp.json")

	// ErrFetch wraps a transient fetch / decode / non-2xx failure. The origin
	// is not authoritative when unreachable.
	ErrFetch = errors.New("rampwellknown: manifest fetch failed")

	// ErrSchemaInvalid is returned when a document fails JSON Schema validation
	// (malformed shape, wrong ver, missing required field, bad key encoding).
	ErrSchemaInvalid = errors.New("rampwellknown: schema validation failed")

	// ErrRoleMismatch is returned by Fetch when the manifest's role differs
	// from the role the caller required.
	ErrRoleMismatch = errors.New("rampwellknown: manifest role mismatch")

	// ErrKeyRevoked is returned by LookupKey when the kid appears in the
	// current revocation snapshot.
	ErrKeyRevoked = errors.New("rampwellknown: key revoked")

	// ErrKeyExpired is returned by LookupKey when the kid resolves to a key
	// whose [not_before, not_after) window does not cover now.
	ErrKeyExpired = errors.New("rampwellknown: key outside validity window")

	// ErrKeyUnknown is returned by LookupKey when no key in the manifest carries
	// the requested kid.
	ErrKeyUnknown = errors.New("rampwellknown: unknown key id")
)
