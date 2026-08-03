package service

// ResolveFeeRateBps returns the effective platform commission rate in basis
// points for a transaction: the per-(tenant, resource_owner) override when one is
// configured, otherwise the tenant-level default. It is pure and is called at
// Authorize, where the tenant (hence its default rate) is already loaded; the
// resolved rate is then frozen on the billing hold.
//
// An override of 0 is honoured as an explicit "no commission for this owner" and
// is distinct from the absence of an override (override == nil), which falls back
// to the tenant default.
func ResolveFeeRateBps(tenantDefault int, override *int) int {
	if override != nil {
		return *override
	}
	return tenantDefault
}
