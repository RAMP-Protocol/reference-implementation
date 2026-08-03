// Package lifecycle owns the key rotation and revocation policy for the Identity
// Service — the "when" the keystore (custody) and publisher (serving) deliberately
// leave out. It sits above both: it drives keystore Create / Expire / Destroy to
// mint, retire, and erase keys, records revocations through the repo, and calls
// publisher.Invalidate so a key change shows up in the served documents at once.
//
// Two entry points live here. Revoker.Revoke is the operator's emergency lever: it
// publishes a compromised key to the subdomain's revocation list and destroys its
// material. The rotation Scheduler (a background loop) mints an overlapping
// replacement key on a cadence and prunes keys whose window has closed. Both depend
// downward only — on the keystore, the revocation repo, and the publisher's Invalidate
// hook — never on transport.
package lifecycle

// Invalidator drops a subdomain's cached documents so the next fetch rebuilds them —
// the directory reflecting the new key set, the revocation list reflecting the new
// revoked set. *publisher.Service satisfies it, and it is the same-process fast path
// that makes a key change visible without waiting out the cache TTL.
type Invalidator interface {
	Invalidate(subdomain string)
}
