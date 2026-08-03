package service

import (
	"fmt"
	"strings"
)

// RejectionReasonNotInContributors is the machine-readable reason emitted in
// CatalogPushRejection when the caller is authenticated but is not listed
// as a contributor in the publisher's ramp.json.
const RejectionReasonNotInContributors = "caller_not_in_catalog_contributors"

// RejectionReasonInvalidTerms is the machine-readable reason emitted when an
// entry carries a license term that fails a licenseterm coherence/membership
// rule. (Term SHAPE — pricing, REFERENCE_ONLY⇒uri, uri⇒uri_digest, formats,
// coherence — is rejected earlier by protovalidate at the RPC boundary.)
const RejectionReasonInvalidTerms = "invalid_license_terms"

// RejectionReasonUnknownPublisherDomain is emitted when an entry's domain has no
// tenant on this Exchange — it cannot own a catalog row here.
const RejectionReasonUnknownPublisherDomain = "unknown_publisher_domain"

// RejectionReasonMissingResourceOwner is emitted when an entry's owner manifest
// does not attest a resource_owner_id for this Exchange. The settlement payee is
// never inferred (no tenant_id fallback), so an un-attested entry cannot own a
// catalog row.
const RejectionReasonMissingResourceOwner = "missing_resource_owner_id"

// RejectionReasonTenantMismatch is emitted when the caller-supplied req.tenant_id
// disagrees with the tenant the entry's domain resolves to; the server-derived
// tenant is authoritative and the disagreeing client value is rejected.
const RejectionReasonTenantMismatch = "tenant_mismatch"

// CatalogPushRejection captures a single rejected entry along with its
// machine-readable reason. Under all-or-nothing PushResources the
// collected rejections are enumerated into the InvalidArgument error returned
// to the caller; nothing is persisted.
type CatalogPushRejection struct {
	URI    string
	Reason string
}

// reject builds a per-entry rejection. Centralizing the construction keeps the
// classifyEntry gate chain readable and the rejection shape consistent.
func reject(uri, reason string) *CatalogPushRejection {
	return &CatalogPushRejection{URI: uri, Reason: reason}
}

// formatRejections renders per-entry rejections as "uri (reason); uri (reason)"
// for the all-or-nothing InvalidArgument message, so a publisher sees exactly
// which URL failed and why.
func formatRejections(rejections []CatalogPushRejection) string {
	parts := make([]string, len(rejections))
	for i, r := range rejections {
		parts[i] = fmt.Sprintf("%s (%s)", r.URI, r.Reason)
	}
	return strings.Join(parts, "; ")
}
