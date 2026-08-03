package keystore

import "errors"

// Sentinel errors every backend returns for the same condition, so a caller can
// branch on the condition rather than on a backend's error text.
//
// The set is TOTAL: every error leaving this package wraps exactly one of these,
// with ErrInternal as the residual class. A transport mapping domain errors to a
// connect.Code needs a total mapping — one unclassified error is one 500 served for
// a condition that had a better answer, and the caller has no way to tell which.
var (
	// ErrNotFound is returned when no key exists at a Ref, or when an agent has
	// no key at all. It is also what a lookup with the right thumbprint but the
	// wrong subdomain returns: one agent must never learn of another's keys, not
	// even that they exist.
	ErrNotFound = errors.New("keystore: key not found")

	// ErrInvalidSubdomain is returned when a subdomain is not a syntactically
	// valid DNS name. The check runs before the subdomain reaches a storage path,
	// so a crafted value cannot escape its agent's namespace.
	ErrInvalidSubdomain = errors.New("keystore: invalid subdomain")

	// ErrInvalidThumbprint is returned when a thumbprint is not a base64url
	// SHA-256 digest. Same reasoning as ErrInvalidSubdomain.
	ErrInvalidThumbprint = errors.New("keystore: invalid thumbprint")

	// ErrInvalidWindow is returned when a validity window cannot contain an
	// instant — NotBefore at or after NotAfter. A window is caller-supplied input
	// exactly as a subdomain is, and it gets a sentinel for the same reason: without
	// one, a transport has no way to tell a malformed request from a broken service,
	// and answers a caller's own bad input with a 500.
	ErrInvalidWindow = errors.New("keystore: invalid validity window")

	// ErrUnavailable is returned when the backend cannot answer at all: unreachable,
	// sealed, rate-limited, or mounted nowhere. It is the retryable class, and it is
	// deliberately distinct from ErrNotFound — a store that reported an outage as
	// "this agent holds no keys" would publish an empty directory for every agent in
	// the system and look perfectly healthy while doing it.
	ErrUnavailable = errors.New("keystore: key store is unavailable")

	// ErrPermissionDenied is returned when the backend refuses the service's
	// credential. It is never the caller's fault and never fixed by retrying: a
	// policy was narrowed too far, or a token expired. Telling it apart from
	// ErrUnavailable is what decides whether an operator goes looking for an outage
	// or for a policy — which is why the store classifies it here, where the answer
	// is still known, rather than leaving callers to interrogate a Vault error.
	ErrPermissionDenied = errors.New("keystore: key store refused the service's credential")

	// ErrNotExportable is returned by backends that cannot surrender private key
	// material — Vault Transit, a KMS, an HSM. It is part of the interface from
	// the start so that exportability is understood as a property of the backend
	// rather than a promise of the KeyStore.
	ErrNotExportable = errors.New("keystore: backend does not export private keys")

	// ErrInternal is the residual class: a fault of this store or of the request it
	// built, which neither a retry nor an operator's policy will fix — a key that
	// would not generate, a Vault status the store does not understand, a caller's own
	// cancelled context. It exists so that the taxonomy is total. Without it, the
	// errors that fit no other sentinel would reach a transport carrying nothing to
	// branch on, and every one of them would become an indistinguishable 500.
	ErrInternal = errors.New("keystore: key store failed internally")

	// ErrCorrupt is returned when a stored record contradicts itself — most
	// importantly when the private key recovered from storage does not derive the
	// public key stored beside it. Signing with a key whose public half is wrong
	// would produce signatures that no verifier accepts, so the store fails loudly
	// instead.
	ErrCorrupt = errors.New("keystore: stored key record is corrupt")
)
