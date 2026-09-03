package testutil

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
)

// txRequest is the message the cases below are read against. It is used for its
// descriptor alone, and it stamps ver anyway: every construction of a
// ver-bearing message in this repo does, and one that did not would be an
// exception a reader has to stop and account for.
func txRequest() *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{Ver: helpers.ProtocolVersion}
}

// walk runs the detector over one body and joins what it found, so each case
// below reads as "this body, these findings".
func walk(t *testing.T, msg proto.Message, body string) string {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	hits := aliasedNames(msg.ProtoReflect().Descriptor(), decoded, "")
	sort.Strings(hits)
	return strings.Join(hits, ",")
}

// TestCanonicalNames_FlagsATopLevelAlias is the positive case: the spelling the
// default protojson options produce.
func TestCanonicalNames_FlagsATopLevelAlias(t *testing.T) {
	t.Parallel()
	got := walk(t, txRequest(), `{"ver":"1.0","idempotencyKey":"k"}`)
	if got != "idempotencyKey" {
		t.Errorf("found %q, want the alias idempotencyKey", got)
	}
}

// TestCanonicalNames_FlagsAnAliasInsideARepeatedField pins the path a nested finding
// carries. Without the index a reader cannot tell which item is wrong.
func TestCanonicalNames_FlagsAnAliasInsideARepeatedField(t *testing.T) {
	t.Parallel()
	body := `{"items":[{"offer":{"exchange":"a.example"}},{"offer":{"offerId":"o-1"}}]}`
	got := walk(t, txRequest(), body)
	if got != "items[1].offer.offerId" {
		t.Errorf("found %q, want items[1].offer.offerId", got)
	}
}

// TestCanonicalNames_PassesACanonicalBody is the negative case. Every key here is a
// proto name, including two whose alias is identical to it.
func TestCanonicalNames_PassesACanonicalBody(t *testing.T) {
	t.Parallel()
	body := `{"ver":"1.0","idempotency_key":"k","items":[{"offer":{"offer_id":"o-1"}}]}`
	if got := walk(t, txRequest(), body); got != "" {
		t.Errorf("found %q in a canonical body, want nothing", got)
	}
}

// TestCanonicalNames_LeavesAKeyItCannotMatchAlone is a property of THE WALK, not of
// the assertion. An undeclared field is not a misspelled one, so the walk says
// nothing about it — but no such body reaches the walk through
// AssertCanonicalWireNames, because the decode refuses it first. That contract is
// pinned by TestCanonicalNames_RefusesAnUndeclaredKey below.
func TestCanonicalNames_LeavesAKeyItCannotMatchAlone(t *testing.T) {
	t.Parallel()
	if got := walk(t, txRequest(), `{"someFieldFromLater":1}`); got != "" {
		t.Errorf("found %q for an undeclared key, want nothing", got)
	}
}

// TestCanonicalNames_TreatsExtensionMembersAsData is the discriminating case for the
// well-known-type rule. Offer.ext is a google.protobuf.Struct, so "offerId"
// inside it is a member name a caller chose — it happens to spell the alias of
// Offer.offer_id, and reporting it would be wrong.
func TestCanonicalNames_TreatsExtensionMembersAsData(t *testing.T) {
	t.Parallel()
	if got := walk(t, &rampv1.Offer{}, `{"ext":{"offerId":"data"}}`); got != "" {
		t.Errorf("found %q inside an extension, want nothing", got)
	}
}

// TestCanonicalNames_TreatsMapKeysAsData is the same discrimination for the one map
// field the contract carries. "transactionDenial" spells the alias of
// ErrorDetail.transaction_denial, but here it is a metadata key.
func TestCanonicalNames_TreatsMapKeysAsData(t *testing.T) {
	t.Parallel()
	if got := walk(t, &rampv1.ErrorDetail{}, `{"metadata":{"transactionDenial":"x"}}`); got != "" {
		t.Errorf("found %q among map keys, want nothing", got)
	}
}

// TestCanonicalNames_ExportedEntryPointPassesACanonicalBody drives the exported entry
// point itself, so the JSON decode and the descriptor read are covered too.
func TestCanonicalNames_ExportedEntryPointPassesACanonicalBody(t *testing.T) {
	t.Parallel()
	AssertCanonicalWireNames(t, []byte(`{"ver":"1.0","idempotency_key":"k"}`), txRequest())
}

// --- the assertion itself, watched failing ---
//
// Everything above drives the walk. These drive the exported assertion's own
// reporting, because until they existed nothing did: every call site passed a
// canonical body, so the Errorf loop and the non-JSON Fatalf were never observed
// doing anything, and turning either into a Logf would have left the suite green.

// recorder stands in for testing.TB and keeps what the assertion reported.
type recorder struct {
	errs   []string
	fatals []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

// TestCanonicalNames_ReportsAnAliasedBody is the positive case for the reporting
// path: an alias must reach Errorf, carrying the dotted path that names it.
func TestCanonicalNames_ReportsAnAliasedBody(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	assertCanonicalWireNames(r, []byte(`{"ver":"1.0","idempotencyKey":"k"}`), txRequest())
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "idempotencyKey") {
		t.Errorf("reported %v, want one finding naming idempotencyKey", r.errs)
	}
	if len(r.fatals) != 0 {
		t.Errorf("an aliased body is a finding, not a fatal: %v", r.fatals)
	}
}

// TestCanonicalNames_IsSilentOnACanonicalBody is the negative case. Without it the
// test above is satisfied by an assertion that reports on everything.
func TestCanonicalNames_IsSilentOnACanonicalBody(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	assertCanonicalWireNames(r, []byte(`{"ver":"1.0","idempotency_key":"k"}`), txRequest())
	if len(r.errs) != 0 || len(r.fatals) != 0 {
		t.Errorf("reported %v / %v on a canonical body, want silence", r.errs, r.fatals)
	}
}

// TestCanonicalNames_RefusesABodyOfAnotherMessage is the mismatch check. The walk
// alone cannot see this: every key of a foreign body misses, each miss reads as a
// field a newer peer added, and the result is indistinguishable from a clean
// answer.
func TestCanonicalNames_RefusesABodyOfAnotherMessage(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	// A camelCase PushResourcesResponse, walked against a TransactionRequest.
	assertCanonicalWireNames(r, []byte(`{"ver":"1.0","accepted":1,"extCritical":"x"}`), txRequest())
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "does not decode as") {
		t.Errorf("reported %v, want one finding that the body is of another message", r.errs)
	}
}

// TestCanonicalNames_RefusesAnUndeclaredKey pins what the EXPORTED assertion does
// with a field this build does not declare. The walk leaves such a key alone,
// which reads like a tolerance for a peer on a newer protocol; the assertion has
// no such tolerance, because the strict decode stops the body first. Nothing
// drove that through the exported entry point before, so the difference between
// the two surfaces was only ever stated in a comment.
func TestCanonicalNames_RefusesAnUndeclaredKey(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	assertCanonicalWireNames(r, []byte(`{"ver":"1.0","someFieldFromLater":1}`), txRequest())
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "does not decode as") {
		t.Errorf("reported %v, want one finding that the body does not decode", r.errs)
	}
}

// TestCanonicalNames_FatalsOnABodyThatIsNotJSON pins the other reporting path.
func TestCanonicalNames_FatalsOnABodyThatIsNotJSON(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	assertCanonicalWireNames(r, []byte("<html>not json</html>"), txRequest())
	if len(r.fatals) != 1 || !strings.Contains(r.fatals[0], "not JSON") {
		t.Errorf("fatals %v, want one naming the body as not JSON", r.fatals)
	}
	if len(r.errs) != 0 {
		t.Errorf("a non-JSON body stops at the fatal; it also reported %v", r.errs)
	}
}

// --- AssertWireCarries, watched failing ---

// carries runs the presence assertion over a recorder and returns what it
// reported, so each case below reads as "this body, these names, this outcome".
func carries(t *testing.T, body string, msg proto.Message, names ...string) *recorder {
	t.Helper()
	r := &recorder{}
	assertWireCarries(r, []byte(body), msg, names...)
	return r
}

// TestWireCarries_PassesWhenEveryNameIsPresent is the negative case. Without it the
// cases below are satisfied by an assertion that reports on everything.
func TestWireCarries_PassesWhenEveryNameIsPresent(t *testing.T) {
	t.Parallel()
	body := `{"ver":"1.0","idempotency_key":"k","items":[{"agent_acceptance":{"signature":"s"}}]}`
	r := carries(t, body, txRequest(), "idempotency_key", "items[0].agent_acceptance")
	if len(r.errs) != 0 || len(r.fatals) != 0 {
		t.Errorf("reported %v / %v for a body carrying both, want silence", r.errs, r.fatals)
	}
}

// TestWireCarries_ReportsAnAbsentField is the positive case.
func TestWireCarries_ReportsAnAbsentField(t *testing.T) {
	t.Parallel()
	r := carries(t, `{"ver":"1.0"}`, txRequest(), "idempotency_key")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "idempotency_key") {
		t.Errorf("reported %v, want one finding naming idempotency_key", r.errs)
	}
}

// TestWireCarries_ReadsNestingRatherThanText is the case a substring search over the
// raw bytes cannot tell apart: the name IS in the body, at the wrong level. The
// items[]-nested per-item field sitting at the top level is exactly the shape
// the wire contract forbids, so an assertion that passed here would be blessing
// it.
func TestWireCarries_ReadsNestingRatherThanText(t *testing.T) {
	t.Parallel()
	body := `{"ver":"1.0","agent_acceptance":{"signature":"s"},"items":[{}]}`
	r := carries(t, body, txRequest(), "items[0].agent_acceptance")
	if len(r.errs) != 1 {
		t.Errorf("reported %v, want one finding: the field is present at the top level, "+
			"not inside items[0]", r.errs)
	}
}

// TestWireCarries_ReportsAnAbsentRepeatedElement pins the index half: the field is
// there and the element is not.
func TestWireCarries_ReportsAnAbsentRepeatedElement(t *testing.T) {
	t.Parallel()
	r := carries(t, `{"ver":"1.0","items":[]}`, txRequest(), "items[0].agent_acceptance")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "items[0]") {
		t.Errorf("reported %v, want one finding naming items[0]", r.errs)
	}
}

// TestWireCarries_FatalsOnANameTheContractDoesNotDeclare is the discriminating case
// for whose fault a failure is. A name the message has no field for cannot be
// satisfied by any body, so it is a fault in the test — reported as fatal, and
// naming the message, rather than as a field missing from the wire.
func TestWireCarries_FatalsOnANameTheContractDoesNotDeclare(t *testing.T) {
	t.Parallel()
	r := carries(t, `{"ver":"1.0"}`, txRequest(), "no_such_field")
	if len(r.fatals) != 1 || !strings.Contains(r.fatals[0], "declares no field") {
		t.Errorf("fatals %v, want one naming the undeclared field", r.fatals)
	}
	if len(r.errs) != 0 {
		t.Errorf("an undeclared name stops at the fatal; it also reported %v", r.errs)
	}
}

// TestWireCarries_FatalsOnABodyThatIsNotJSON pins this assertion's own decode
// boundary. It reads the same as the naming assertion's and is a SEPARATE code
// path: until this existed, only one of the two non-JSON fatals had ever been
// observed doing anything, and the untested one sat under a heading that made it
// look covered.
func TestWireCarries_FatalsOnABodyThatIsNotJSON(t *testing.T) {
	t.Parallel()
	r := carries(t, "<html>not json</html>", txRequest(), "idempotency_key")
	if len(r.fatals) != 1 || !strings.Contains(r.fatals[0], "not a JSON object") {
		t.Errorf("fatals %v, want one naming the body as not a JSON object", r.fatals)
	}
	if len(r.errs) != 0 {
		t.Errorf("a non-JSON body stops at the fatal; it also reported %v", r.errs)
	}
}
