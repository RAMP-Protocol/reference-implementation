package ingest

import (
	"fmt"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// resolveNamedEnum resolves a full proto enum NAME (via the generated
// <Enum>_value map) to its typed value, rejecting an unknown spelling or the
// zero/UNSPECIFIED sentinel — the ingest mirror of the proto {not_in:[0]} rule.
// kind names the noun used in the failure message.
func resolveNamedEnum[E ~int32](s string, values map[string]int32, kind string) (E, error) {
	v, ok := values[strings.TrimSpace(s)]
	if !ok || v == 0 {
		return 0, fmt.Errorf("unknown %s %q", kind, s)
	}
	return E(v), nil
}

// mapIngestionSource resolves the full proto IngestionSource enum NAME the feed
// carries (e.g. "INGESTION_SOURCE_CMS_API") to its enum value, failing loud on
// an unknown spelling or the UNSPECIFIED sentinel.
func mapIngestionSource(s string) (rampv1.IngestionSource, error) {
	return resolveNamedEnum[rampv1.IngestionSource](s, rampv1.IngestionSource_value, "ingestion source")
}

// mapResourceMutability resolves the full proto ResourceMutability enum NAME the
// feed carries (e.g. "RESOURCE_MUTABILITY_STATIC") to its enum value, failing
// loud on an unknown spelling or the UNSPECIFIED sentinel — the ingest mirror of
// the Offer-side {not_in:[0]} rule.
func mapResourceMutability(s string) (rampv1.ResourceMutability, error) {
	return resolveNamedEnum[rampv1.ResourceMutability](s, rampv1.ResourceMutability_value, "resource mutability")
}
