package service

import (
	"context"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// RejectionReasonInvalidEntry is emitted when a ResourceEntry fails proto→repo
// conversion (entryFromProto) — e.g. a missing domain/path or a terms[] payload
// that will not marshal. Like the other per-entry verdicts it drops the single
// entry from the batch (never a batch abort) and is surfaced today only in the
// structured rejection log because the canonical PushResourcesResponse carries
// counts, not per-entry detail.
const RejectionReasonInvalidEntry = "invalid_entry"

// RejectionReasonURIOwnedByOther is emitted when an entry's materialized URI is
// already owned by a DIFFERENT catalog row (a different resource_id), or when two
// entries in the same batch claim the same URI under different resource_ids. A
// URI belongs to exactly one row (UNIQUE(uri)): a re-push of the same
// resource updates in place, but a colliding-URI/different-resource_id push would
// shadow the incumbent owner's terms + signing identity in the discovery trie, so
// it is rejected per-entry rather than allowed to overwrite.
const RejectionReasonURIOwnedByOther = "uri_owned_by_other_resource"

// rejectURIConflicts enforces the URI-ownership invariant before the
// batch upsert: a URI belongs to exactly one resource_id. It partitions the
// already-classified accepted entries into those that may proceed and those that
// collide on URI with a row owned by a DIFFERENT resource_id — either an existing
// catalog row or an earlier entry in the same batch.
//
// A re-push of the same resource (same resource_id, hence same URI) is NOT a
// conflict: the URI already maps to that resource_id, so the entry proceeds and
// the repo's ON CONFLICT (resource_id) upsert updates it in place. This keeps the
// failure a per-entry rejection rather than the batch-aborting UNIQUE(uri)
// violation it backstops, and keeps the surviving entries' upsert atomic.
//
// The ownership snapshot is read through the same repo.ListAll the trie rebuild
// uses (admin:cross_tenant — ownership is a global property; a URI's domain pins
// it to one tenant, so the cross-tenant read cannot leak isolation). The UNIQUE
// (uri) constraint added in migration 000012 is the concurrency backstop for the
// narrow window between this read and the commit.
func (s *CatalogService) rejectURIConflicts(
	ctx context.Context,
	accepted []repo.CatalogEntry,
) ([]repo.CatalogEntry, []CatalogPushRejection, error) {
	owners, err := s.uriOwners(ctx)
	if err != nil {
		return nil, nil, err
	}
	survivors := make([]repo.CatalogEntry, 0, len(accepted))
	var rejections []CatalogPushRejection
	for _, entry := range accepted {
		if owner, taken := owners[entry.URI]; taken && owner != entry.ResourceID {
			rejections = append(rejections, CatalogPushRejection{
				URI:    entry.URI,
				Reason: RejectionReasonURIOwnedByOther,
			})
			continue
		}
		// Claim the URI for this resource_id so a later same-batch entry that
		// reuses the URI under a different resource_id is caught too.
		owners[entry.URI] = entry.ResourceID
		survivors = append(survivors, entry)
	}
	return survivors, rejections, nil
}

// uriOwners builds the current uri -> resource_id ownership map from committed
// catalog state. admin:cross_tenant — the read spans all tenants; ownership is a
// global property (a URI's domain pins it to exactly one tenant),
// so the un-tenant-filtered read cannot surface a cross-tenant shadowing.
func (s *CatalogService) uriOwners(ctx context.Context) (map[string]string, error) {
	rows, err := s.repo.ListAll(ctx) // admin:cross_tenant — intentional global read
	if err != nil {
		return nil, err
	}
	owners := make(map[string]string, len(rows))
	for _, row := range rows {
		owners[row.URI] = row.ResourceID
	}
	return owners, nil
}
