package rampwellknown

// AuthorizesContributor reports whether callerID may push catalog entries on
// behalf of the publisher described by m. It is authorized when callerID equals
// the manifest's own domain (a publisher pushing its own catalog) or appears in
// catalog_contributors. Comparison is case-sensitive, matching the wire values.
//
// This is an Exchange catalog-push authorization predicate, but it lives in the
// shared discovery library by design: it is pure over Manifest accessors
// (GetDomain, GetCatalogContributors) with no Exchange dependency, and the
// library's own Cache tests exercise it. Moving it to the Exchange service would
// invert no import and split manifest-shape knowledge across two packages.
func AuthorizesContributor(m *Manifest, callerID string) bool {
	if m == nil || callerID == "" {
		return false
	}
	if callerID == m.GetDomain() {
		return true
	}
	for _, c := range m.GetCatalogContributors() {
		if c.GetDomain() == callerID {
			return true
		}
	}
	return false
}
