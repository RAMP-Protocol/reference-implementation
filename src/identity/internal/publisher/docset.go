package publisher

import "time"

// docSet holds one agent's four built documents. Any of them may be nil: an agent can
// hold keys before its card is written, or hold an account row before either exists —
// each is absent from its own source, independent of the others. keyExpiry is the
// earliest NotAfter among the published keys, used to clamp the cache entry so an
// expired key cannot linger a full TTL past its window.
type docSet struct {
	wba        []byte
	card       []byte
	revocation []byte
	manifest   []byte
	keyExpiry  time.Time

	// Per-document backend availability. A document is nil either because it is ABSENT
	// (404) or because its backend was DOWN (503); these flags tell the two apart per
	// route, so one backend's outage 503s only the documents it owns. In particular a
	// Vault outage 503s the directory without sinking the revocation list, which is
	// pure-Postgres and must stay servable during exactly that outage.
	wbaUnavail      bool
	cardUnavail     bool
	revUnavail      bool
	manifestUnavail bool
}

// empty reports whether the agent is absent from every source — no directory, no
// card, nothing revoked, and no account row. Only a wholly-unknown subdomain is
// empty; an agent whose last key was destroyed but which still has revocations to
// report is present, so its revocation list keeps being served (a consumer holding a
// cached directory must still learn the key is dead) and it stays out of the negative
// cache.
//
// The manifest term is load-bearing rather than redundant: a developer whose account
// row was reserved before its key and card were written has an overlay and no siblings,
// so omitting it here would file a registered agent in the negative cache and 404 its
// overlay for the whole negative TTL.
func (d *docSet) empty() bool {
	return d.wba == nil && d.card == nil && d.revocation == nil && d.manifest == nil
}

// unavailable reports whether any document's backend was down during the build. Such a
// docSet is NOT cached: a 503 is a transient condition to retry on the next request,
// never a state to pin for the whole TTL (which would keep 503ing after the backend
// recovered).
func (d *docSet) unavailable() bool {
	return d.wbaUnavail || d.cardUnavail || d.revUnavail || d.manifestUnavail
}

// entry is a cached docSet with the instant it stops being served.
type entry struct {
	docs    *docSet
	expires time.Time
}
