package directory

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// RevocationReader is the getter the serving layer depends on (interface
// segregation): it resolves one agent's current revocation state — the monotonic
// as_of and the complete set of revoked thumbprints — by subdomain. The concrete
// implementation lives in the repo package over Postgres. A subdomain with no
// revocation row yields (0, empty, nil): the epoch-dated "nothing revoked" baseline,
// never an error.
type RevocationReader interface {
	BySubdomain(ctx context.Context, subdomain string) (asOf int64, revoked []string, err error)
}

// BuildRevocation assembles an agent's KeyRevocationList — the snapshot served at
// its directory's revocation_url — from the registry's monotonic as_of and the
// complete set of revoked thumbprints. An empty set serializes to just {as_of}, the
// epoch-dated "nothing revoked" baseline.
//
// Unlike the WBA directory (a standards-owned JWK Set built with go-jose), the
// revocation list IS a RAMP protocol artifact, so it is built from the proto and
// marshalled with protojson (UseProtoNames) — byte-for-byte the wire shape the
// consumer's Loader schema-validates and protojson-decodes, so producer and consumer
// cannot drift.
//
// as_of carries whatever sub-second precision the caller's instant has (protojson
// emits up to nanoseconds): two revokes a nanosecond apart therefore serialize to
// distinct timestamps, which is what keeps the consumer's strict-monotonic guard from
// mistaking the second for a rollback of the first.
func BuildRevocation(asOf time.Time, revoked []string) ([]byte, error) {
	list := &rampwellknown.RevocationList{
		AsOf:    timestamppb.New(asOf.UTC()),
		Revoked: revoked,
	}
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("directory: BuildRevocation: %w", err)
	}
	if err := rampwellknown.ValidateRevocation(raw); err != nil {
		return nil, fmt.Errorf("directory: BuildRevocation: %w", err)
	}
	return raw, nil
}
