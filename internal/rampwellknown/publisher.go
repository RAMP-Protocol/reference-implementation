package rampwellknown

// Identity maps a wire spelling of a host to the canonical identity it names, or
// reports that it names none. It is the rule by which two spellings are decided
// to be the same party.
//
// AuthorizesContributor takes it as a parameter rather than importing one:
// internal/agentid, which owns the rule, is built on this package, so depending
// on it here would close an import cycle. Making it an argument is not merely the
// way around that — a caller cannot invoke this predicate without stating which
// rule its comparison runs under, which is the property that was missing when
// both sides were compared as raw bytes.
type Identity func(string) (string, error)

// AuthorizesContributor reports whether callerID may push catalog entries on
// behalf of the publisher described by m. It is authorized when callerID names
// the same host as the manifest's own domain (a publisher pushing its own
// catalog) or as one of its catalog_contributors.
//
// BOTH sides go through identity, and that symmetry is the whole point. The
// caller's value arrives canonicalized from the transport edge while the manifest
// is publisher-authored and arrives however the publisher wrote it, so comparing
// them raw refused every publisher that spelled its own domain with a scheme, in
// mixed case, with a trailing dot, or with an explicit :443 — a party that had
// been authorized until the two sides stopped being folded the same way.
//
// Folding does not widen who counts as a contributor: distinct hosts have
// distinct identities, so this only removes differences of spelling. A manifest
// entry that names no host matches nothing, which is the same answer it would get
// from a caller whose own value named no host.
func AuthorizesContributor(m *Manifest, callerID string, identity Identity) bool {
	if m == nil || callerID == "" || identity == nil {
		return false
	}
	caller, err := identity(callerID)
	if err != nil {
		return false
	}
	sameParty := func(candidate string) bool {
		got, err := identity(candidate)
		return err == nil && got == caller
	}
	if sameParty(m.GetDomain()) {
		return true
	}
	for _, c := range m.GetCatalogContributors() {
		if sameParty(c.GetDomain()) {
			return true
		}
	}
	return false
}

// ResourceOwnerID returns the resource_owner_id the publisher described by m
// attests for the exchange identified by exchangeDomain — the payee account its
// catalog revenue settles to. The value is read from the ext map of the
// AuthorizedExchange entry whose domain matches exchangeDomain (the typed field is
// not yet on the wire), and the owner declares the same value across every domain
// it wants paid as one entity.
//
// The second result is false when m is nil, exchangeDomain is empty, no exchange
// entry matches, or the matching entry carries no non-empty resource_owner_id —
// i.e. the owner has not attested a payee for this exchange. Like
// AuthorizesContributor, it is pure over Manifest accessors with no Exchange
// dependency.
func ResourceOwnerID(m *Manifest, exchangeDomain string) (string, bool) {
	if m == nil || exchangeDomain == "" {
		return "", false
	}
	for _, ex := range m.GetExchanges() {
		if ex.GetDomain() != exchangeDomain {
			continue
		}
		id := ex.GetExt().GetFields()["resource_owner_id"].GetStringValue()
		return id, id != ""
	}
	return "", false
}
