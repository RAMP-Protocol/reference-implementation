package service

// Converting a wire ResourceEntry into the stored CatalogEntry shape. Split from
// catalog.go because these are pure functions over the two message shapes — no
// receiver, no service state, no IO — and the service file is about the push and
// rebuild flows that call them.

import (
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// entryFromProto converts a ResourceEntry message into the repo.CatalogEntry
// shape, materializing the stable resource_id and the pricing JSON payload.
func entryFromProto(tenantID string, e *rampv1.ResourceEntry) (repo.CatalogEntry, error) {
	if e.GetDomain() == "" || e.GetPath() == "" {
		return repo.CatalogEntry{}, fmt.Errorf("missing domain/path")
	}
	uri := currentCatalogURIScheme() + "://" + e.GetDomain() + e.GetPath()
	id := namespaceResourceID(tenantID, e.GetContentId(), uri)
	terms, err := marshalTerms(e.GetTerms())
	if err != nil {
		return repo.CatalogEntry{}, fmt.Errorf("marshal terms: %w", err)
	}
	metadata, err := marshalResourceMetadata(e)
	if err != nil {
		return repo.CatalogEntry{}, fmt.Errorf("marshal metadata: %w", err)
	}
	return repo.CatalogEntry{
		ResourceID: id,
		TenantID:   tenantID,
		URI:        uri,
		URIPrefix:  uri,
		// pricing is the legacy catalog.pricing JSONB column (NOT NULL). It no
		// longer carries offer/billing price — pricing is derived per-request
		// from the selected LicenseTerm. A neutral sentinel keeps the
		// NOT NULL column satisfied without re-introducing a hardcoded default;
		// no code path reads it for price.
		PricingJSON:    legacyPricingSentinel,
		TermsJSON:      terms,
		DeliveryMethod: "INSTRUCTIONS",
		MetadataJSON:   metadata,
	}, nil
}

// namespaceResourceID scopes a resource_id to its owning tenant so the public
// resource_id (== offer_id) can never collide across tenants: a
// contributor for one tenant cannot address — and so cannot overwrite — another
// tenant's row. tenant_id is a t_<uuid> (no ':') so the delimiter is unambiguous.
//
// The scoping KEY is the caller-supplied content_id when present. When absent,
// the key falls back to the entry's URI rather than a fresh server UUID: the URI
// is the stable identity of the resource, so an absent-content_id re-push of the
// same (domain, path) maps to the SAME resource_id and upserts in place
// (idempotency), instead of minting a new resource_id that would falsely collide
// with the incumbent under the URI-ownership gate. The URI already encodes
// the domain (which derives the tenant), so URI-keyed ids stay tenant-scoped.
func namespaceResourceID(tenantID, contentID, uri string) string {
	key := contentID
	if key == "" {
		key = uri
	}
	return tenantID + ":" + key
}

// legacyPricingSentinel is the value written into the NOT NULL catalog.pricing
// JSONB column now that offer/billing pricing is derived from the selected
// LicenseTerm rather than a stored pricing blob. It exists only to
// satisfy the column constraint until the column is dropped in a later schema
// change; nothing reads it for price.
var legacyPricingSentinel = []byte(`{}`)

// uriFromEntry reconstructs the URI from an entry even when the proto is
// missing fields — used only for the rejection message so invalid pushes show
// up as "uri": "" rather than being silently dropped.
func uriFromEntry(e *rampv1.ResourceEntry) string {
	if e.GetDomain() == "" && e.GetPath() == "" {
		return ""
	}
	return currentCatalogURIScheme() + "://" + e.GetDomain() + e.GetPath()
}
