// Package keystore custodies the Ed25519 private keys the Identity Service
// signs with on an agent's behalf.
//
// An agent that cannot hold a key itself (an MCP client, a script, anything
// without a secure store) delegates custody here: the service mints the key,
// publishes the public half in the agent's Web Bot Auth directory, and signs the
// agent's outgoing requests with the private half. Custody is therefore the most
// security-sensitive component in the service — whoever reads this store can
// impersonate every agent in it.
//
// # The backend is an implementation detail
//
// KeyStore is the only surface callers see. The shipped backend is HashiCorp
// Vault (KV v2), which owns encryption at rest, access control, and the audit
// log. A stronger backend — Vault Transit, a KMS, an HSM — is a drop-in behind
// the same interface, which is why Signer hands back a crypto.Signer rather than
// the private key: an HSM can sign, but it can never hand the key over. Export is
// consequently a property of the backend, not a guarantee of the interface (see
// ErrNotExportable).
//
// # Keys are addressed by {subdomain, thumbprint}
//
// The agent's durable identity is its WBA subdomain; the RFC 7638 thumbprint
// selects which of that agent's keys is meant. An account keyed on the thumbprint
// alone would be orphaned by the agent's first key rotation, so both halves are
// carried together in a Ref.
//
// # A Ref names a key; it does not entitle anyone to it
//
// Both halves of a Ref — the subdomain and the thumbprint — are PUBLIC: they are
// what the agent's directory publishes. Knowing them is therefore not evidence of
// anything, and this package does not pretend otherwise. It has no request, no
// principal, and no session, so it decides nothing about who may call it.
//
// Export is reached from the operator CLI, not from a public endpoint: whoever can
// invoke it already holds operator access to this service and its secret store, so
// there is no untrusted caller to authorize and no request-supplied subdomain to
// abuse. That is a deliberate choice about where the surface lives, and it is the
// reason the port carries no caller identity.
//
// Signer is the one that gets called per request, on an agent's behalf. The rule
// there is the ordinary one: the subdomain it signs for comes from the AUTHENTICATED
// identity of the request, never from a field the caller filled in. Take the
// subdomain from the wire and the service will happily sign as whoever was asked for.
//
// # What this package deliberately does not own
//
// Key rotation and revocation are a separate concern with their own semantics —
// an overlap window, a retirement order, and the crucial distinction between a key
// that is absent from a directory and one that has been revoked (a verifier treats
// those differently). Those operations belong to the rotation/revocation work, not
// to custody.
//
// What custody owes them is the substrate they are built on, and it is all here:
// an agent holds MANY keys, each with its own validity window, each addressable on
// its own thumbprint, all enumerable in a defined order. Minting the replacement
// key of a rotation is a plain Create; retiring the old one is Expire; erasing a
// revoked one — every version of it — is Destroy. The policy that decides WHEN to
// call those still lives in the rotation/revocation work, not here.
//
// # Why this is not a sqlc repository
//
// Architecture Rule 2 routes persistence through a repository over sqlc. Private
// keys are the deliberate exception: they live in a secret manager, not in the
// service's database, so that a database dump — the most common leak — carries no
// key material, and so that the custody backend can be swapped for an HSM without
// touching the schema. Key metadata rides along with the key for the same reason
// it is stored at all: to keep one record per key with one lifecycle.
package keystore

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"time"
)

// Ref identifies one key: the agent's durable identity (its WBA subdomain) plus
// the individual key (the RFC 7638 thumbprint of its public half, which is also
// the RFC 9421 keyid a verifier presents).
type Ref struct {
	Subdomain  string
	Thumbprint string
}

// Window is a key's validity period, half-open: valid when
// NotBefore <= t < NotAfter. It matches the JWK not_before/not_after the WBA
// directory publishes, so a key's window means the same thing here and on the wire.
type Window struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// Key is the public half of a stored key plus the metadata that describes it. The
// private half never appears here: it leaves the store only through Signer (as an
// opaque signer) or Export (as PEM, when the backend permits it).
type Key struct {
	Ref       Ref
	Public    ed25519.PublicKey
	Window    Window
	CreatedAt time.Time
}

// KeyStore is the custody port. Implementations hold Ed25519 private keys for
// agents and expose exactly the operations the service needs: mint, select, sign,
// publish, and export.
type KeyStore interface {
	// Create mints a fresh Ed25519 keypair for subdomain, valid over w. The
	// validity window is the caller's to choose: rotation policy (how long a key
	// lives, how long two keys overlap) is not custody's business. An agent may
	// hold several keys at once, which is what makes a rotation possible at all.
	Create(ctx context.Context, subdomain string, w Window) (Key, error)

	// Active returns the key an agent should sign with right now: the newest key
	// whose window covers the present instant. It exists so the "which key is
	// current?" rule lives in one place — during a rotation overlap two keys
	// verify, but only one signs, and a caller re-deriving that choice from List
	// would be free to pick the other one.
	Active(ctx context.Context, subdomain string) (Key, error)

	// Signer returns a signer for ref. It deliberately does NOT return the private
	// key: a Transit/KMS/HSM backend can sign without ever surrendering key bytes,
	// and this signature is what lets such a backend drop in without touching a
	// single caller.
	Signer(ctx context.Context, ref Ref) (crypto.Signer, error)

	// List returns every key held for subdomain, newest first by CreatedAt (ties
	// broken by thumbprint). It is what the agent's WBA directory publishes, and
	// what a rotation reads to know where it stands.
	//
	// The order is load-bearing, not cosmetic: a WBA consumer resolving an identity
	// without a known thumbprint takes the first active key in document order, so an
	// arbitrary order would silently keep peers on the old key through a rotation.
	List(ctx context.Context, subdomain string) ([]Key, error)

	// Export returns ref's private key as a PKCS#8 PEM document, so a developer can
	// move their agent's identity elsewhere — they own it, the service merely holds
	// it. Backends that cannot surrender key material return ErrNotExportable.
	Export(ctx context.Context, ref Ref) ([]byte, error)

	// Expire shortens ref's validity window to end at notAfter — the retirement half
	// of a rotation, where the previous key must stop being served once the overlap
	// has drained. It only ever SHORTENS: a notAfter at or before the key's NotBefore,
	// or one later than the window's current NotAfter, is ErrInvalidWindow. Moving a
	// window outward would let a retired — or worse, a revoked — key come back to life,
	// so that is the one direction custody refuses to move it.
	Expire(ctx context.Context, ref Ref, notAfter time.Time) error

	// Destroy erases ref's key material — EVERY version of it. On KV v2 a plain
	// overwrite leaves the old version, seed and all, readable to anyone who can name a
	// version number, so revocation cannot be a write of an empty record: it must
	// destroy the versions that still hold the key. After Destroy the key is gone from
	// List, Active and Signer at once. Destroying a key that is already gone is not an
	// error — a revocation interrupted midway must be safe to run again.
	Destroy(ctx context.Context, ref Ref) error

	// ListSubdomains returns every subdomain that holds at least one key — the agents
	// the rotation scheduler walks. Enumeration belongs to custody because only the
	// store knows which namespaces it holds; an empty store yields an empty slice, not
	// an error.
	ListSubdomains(ctx context.Context) ([]string, error)
}
