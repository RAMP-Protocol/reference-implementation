package directory_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
)

// An empty revoked set is the epoch-dated "nothing revoked" baseline: just {as_of},
// with revoked omitted (protojson with UseProtoNames drops an empty repeated field).
func TestBuildRevocation_EmptySetIsEpochBaseline(t *testing.T) {
	raw, err := directory.BuildRevocation(time.Unix(0, 0), nil)
	if err != nil {
		t.Fatalf("BuildRevocation: %v", err)
	}
	var doc struct {
		AsOf    string   `json:"as_of"`
		Revoked []string `json:"revoked"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.AsOf != "1970-01-01T00:00:00Z" {
		t.Errorf("as_of = %q, want the epoch baseline", doc.AsOf)
	}
	if len(doc.Revoked) != 0 {
		t.Errorf("revoked = %v, want empty/absent", doc.Revoked)
	}
}

// What Build produces, the consumer's protojson path reads back unchanged — proving
// producer and consumer agree on the wire shape.
func TestBuildRevocation_CarriesThumbprintsAndDecodesForTheConsumer(t *testing.T) {
	asOf := time.Unix(0, 1_700_000_000_000_000_000).UTC()
	tps := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}
	raw, err := directory.BuildRevocation(asOf, tps)
	if err != nil {
		t.Fatalf("BuildRevocation: %v", err)
	}

	var list rampwellknown.RevocationList
	if err := protojson.Unmarshal(raw, &list); err != nil {
		t.Fatalf("protojson decode: %v", err)
	}
	if !list.GetAsOf().AsTime().Equal(asOf) {
		t.Errorf("as_of round-trip = %s, want %s", list.GetAsOf().AsTime(), asOf)
	}
	if got := list.GetRevoked(); !reflect.DeepEqual(got, tps) {
		t.Errorf("revoked round-trip = %v, want %v", got, tps)
	}
}

// Two revokes a nanosecond apart MUST serialize to distinct as_of strings; otherwise
// the consumer's strict-monotonic guard would mistake the second for a rollback of
// the first and silently drop it.
func TestBuildRevocation_PreservesSubSecondPrecision(t *testing.T) {
	asOfOf := func(nanos int64) string {
		raw, err := directory.BuildRevocation(time.Unix(0, nanos), nil)
		if err != nil {
			t.Fatalf("BuildRevocation: %v", err)
		}
		var d struct {
			AsOf string `json:"as_of"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return d.AsOf
	}
	a := asOfOf(1_700_000_000_000_000_001)
	b := asOfOf(1_700_000_000_000_000_002)
	if a == b {
		t.Errorf("nanosecond-apart revokes collapsed to the same as_of %q", a)
	}
}
